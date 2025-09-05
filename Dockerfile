# Simple Dockerfile for Python HTTPS forward proxy
FROM python:3.12-slim

WORKDIR /app

COPY . /app
EXPOSE 8081

CMD ["python", "main.py"]
