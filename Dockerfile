FROM python:3.13-alpine
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 80
CMD ["python", "/app/app.py"]
