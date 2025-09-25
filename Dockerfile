FROM python:3.12-alpine
COPY ./src /app
RUN pip3 install -r /app/requirements.txt
EXPOSE 8080/tcp
ENTRYPOINT ["python3", "/app/server.py"]
