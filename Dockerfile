FROM python:3.13-alpine
WORKDIR /app
COPY app.py unblock.py memory_guard.py unblock_ui.py /app/
EXPOSE 80
CMD ["python", "/app/app.py"]
