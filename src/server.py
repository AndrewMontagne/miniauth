from aiohttp import web, ClientSession, ClientTimeout
import asyncio
import jwt
import time
import logging
import json
import os
from cachetools import TTLCache

CACHE_TTL = int(os.environ.get("CACHE_TTL", "600"))

routes = web.RouteTableDef()
ttl_cache = TTLCache(maxsize=2048, ttl=CACHE_TTL)
idp_request_lock = asyncio.Lock()  # Only one request to the IDP at a time

ISSUER_NAME = os.environ.get("POD_NAME", os.uname().nodename)
SHARED_SECRET = os.environ.get("SHARED_SECRET", "insecure")  # TODO: RSA Key?
COOKIE_KEY = os.environ.get("COOKIE_KEY", "miniauth")
EXPIRY_SECS = int(os.environ.get("EXPIRY_SECS", 10 * 60 * 60))  # default 10 hours
URI_ROOT = os.environ.get("URI_ROOT", "http://localhost:8080")
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN", "localhost")

OPENID_CONFIG_ENDPOINT = os.environ.get("OPENID_CONFIG_ENDPOINT", "")
OPENID_CLIENT_ID = os.environ.get("OPENID_CLIENT_ID", "miniauth")


@routes.get("/authz")
async def authz(request: web.Request):
    """Determines whether a user is authorized to access this resource"""
    cookies: dict = dict(request.cookies)

    # Bail out early if no cookie
    if COOKIE_KEY not in cookies.keys():
        return web.Response(body="No cookie! :(", status=401)

    cookie: str = cookies.get(COOKIE_KEY)

    # Bail out early if it doesn't look like a JSON web token
    if not cookie.startswith("ey"):
        return web.Response(body=f"Bad token! :(", status=401)

    # Validate the JSON Web Token
    try:
        payload = jwt.decode(cookie, SHARED_SECRET, algorithms="HS256")
    except:
        return web.Response(body=f"Bad token! :(", status=401)

    # Check to see if the JWT is in date and has not expired
    deltat = int(time.time()) - int(payload.get("iat", 0))
    if deltat < -1 or deltat > EXPIRY_SECS:
        return web.Response(body=f"Expired token! :(", status=401)

    # Check the user has the right groups for this resource
    if "admin" not in payload.get("groups", []):
        return web.Response(body="Not in the right group! :(", status=403)

    if deltat > CACHE_TTL:
        # Contact the IDP to make sure this user still has access
        if not await validate_refresh_token(payload.get("token")):
            return web.Response(body=f"Invalidated token! :(", status=401)

    # Successful response with caching headers for NGINX
    response = web.Response()
    response.headers.add("Cache-Control", f"max-age=600")
    response.headers.add("Vary", "Cookie")
    response.body = "AUTHZ OK! :)"

    return response


@routes.get("/authn")
async def authn(request: web.Request):
    """Redirects the user to the IDP to start the OIDC flow"""
    config = await get_openid_config()

    if config is None:  # TODO: Break-class basic auth?
        return web.Response(body="OpenID unavailable :(", status=503)

    payload = {"iat": int(time.time())}
    state = jwt.encode(payload, SHARED_SECRET, algorithm="HS256")

    redirect = f"{config['authorization_endpoint']}?response_type=code&state={state}&scope=openid%20email%20offline_access&client_id={OPENID_CLIENT_ID}&redirect_uri={URI_ROOT}/openid"
    response = web.Response(body="Redirecting...", status=302)

    # If we have a redirect, store it in a cookie so we can use it in /openid
    rd = request.query.get("rd", None)
    if rd is not None:
        response.set_cookie("rd", request.query.get("rd"), expires=300)

    response.headers.add("Location", redirect)
    return response


@routes.get("/openid")
async def openid(request: web.Request):
    """Processes the returned data from the IDP"""
    config = await get_openid_config()
    state = request.query["state"]

    # Bail out early if it doesn't look like a JSON web token
    if not state.startswith("ey"):
        return web.Response(body=f"Invalid state! :(", status=401)

    # Validate the JSON Web Token
    try:
        payload = jwt.decode(state, SHARED_SECRET, algorithms="HS256")
    except:
        return web.Response(body=f"Invalid state! :(", status=401)

    # Check to see if the JWT is in date and has not expired
    deltat = int(time.time()) - int(payload.get("iat", 0))
    if deltat < -1 or deltat > 300:
        return web.Response(body=f"Expired state! :(", status=401)
    
    # Check if we've seen this state recently
    if ttl_cache.get(f"state_{state}") is not None:
        return web.Response(body="State already used! :(", status=400)
    ttl_cache[f"state_{state}"] = "used!"

    async with ClientSession() as session:
        payload = {
            "grant_type": "authorization_code",
            "code": request.query["code"],
            "client_id": OPENID_CLIENT_ID,
            "redirect_uri": f"{URI_ROOT}/openid",
        }

        # Send the code off to the IDP to get our access token
        async with idp_request_lock:
            async with session.post(config["token_endpoint"], data=payload) as resp:
                body = await resp.json()
                token = body.get("access_token", None)
                if token is None:
                    return web.Response(body=f"Expired auth! :(", status=401)

                # Validate the JSON Web token against the IDP config
                jwks = jwt.PyJWKClient(config["jwks_uri"], cache_keys=True)
                signing_key = jwks.get_signing_key_from_jwt(token)
                try:
                    profile = jwt.decode(
                        token,
                        signing_key,
                        audience=OPENID_CLIENT_ID,
                        algorithms=config["authorization_signing_alg_values_supported"],
                    )
                except Exception as e:
                    return web.Response(
                        body=f"Bad Token!\n\n{json.dumps(profile,indent=2)}", status=401
                    )
                
    # Sanitise the groups before they go in the token
    groups = []
    for group in profile["groups"]:
        groups.append(group.strip('/\\ \n'))

    # Assemble the JWT that will go in our auth cookie
    payload = {
        "uid": profile["email"],
        "groups": groups,
        "token": body["refresh_token"],
    }
    payload["iat"] = int(time.time())
    payload["iss"] = ISSUER_NAME
    token = jwt.encode(payload, SHARED_SECRET, algorithm="HS256")

    # Send the cookie on the root domain we want to cover
    response = web.Response(status=302)
    response.set_cookie(COOKIE_KEY, token, max_age=EXPIRY_SECS, domain=COOKIE_DOMAIN)
    response.headers.add("Cache-Control", f"max-age={EXPIRY_SECS}")

    # If we have a stored redirect in a cookie, use it!
    redirect = request.cookies.get("rd", None)
    if redirect is not None:
        response.headers.add("Location", redirect)

    response.body = "AUTHN OK! :)"

    return response


@routes.get("/healthz")
async def healthz(request: web.Request):
    """Healthcheck, always returns a 200!"""
    return web.Response(body="OK! :)")


@routes.get("/debugz")
async def debugz(request: web.Request):
    return web.Response(body=json.dumps(dict(request.headers)))


async def get_openid_config():
    async with idp_request_lock:
        key = "openid_config"
        result = ttl_cache.get(key)
        if ttl_cache.get(key) is None:
            result = await _get_openid_config()
            ttl_cache[key] = result
    
    return result


async def _get_openid_config():
    """Fetches the OpenID config from the IDP, with a cache"""
    logging.debug("Fetching OpenID config...")
    async with ClientSession(timeout=ClientTimeout(5)) as session:
        try:
            async with session.get(OPENID_CONFIG_ENDPOINT) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    logging.warning("Failed to get OpenID config from IDP")
                    return None
        except:
            logging.warning("Failed to get OpenID config from IDP")
            return None


async def validate_refresh_token(refresh_token: str) -> bool:
    config = await get_openid_config()

    async with idp_request_lock:
        key = f"refreshtoken_{refresh_token}"
        result = ttl_cache.get(key)
        if ttl_cache.get(key) is None:
            result = await _validate_refresh_token(config, refresh_token)
            ttl_cache[key] = result
    
    return result


async def _validate_refresh_token(config: dict, refresh_token: str) -> bool:
    """Validates the refresh token with the IDP"""
    logging.debug("Validating refresh token...")
    async with ClientSession(timeout=ClientTimeout(5)) as session:
        try:
            payload = {
                "grant_type": "refresh_token",
                "client_id": OPENID_CLIENT_ID,
                "refresh_token": refresh_token,
            }
            async with session.post(config["token_endpoint"], data=payload) as resp:
                return resp.status == 200
        except:
            logging.warning("Failed to validate refresh token with IDP")


app = web.Application()
app.add_routes(routes)
logging.basicConfig(level=logging.DEBUG)
web.run_app(app)
