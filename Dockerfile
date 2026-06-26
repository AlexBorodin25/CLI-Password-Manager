FROM ubuntu:latest
LABEL authors="alexb"

ENTRYPOINT ["top", "-b"]

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY password_manager.py .

CMD ["python", "password_manager.py"]