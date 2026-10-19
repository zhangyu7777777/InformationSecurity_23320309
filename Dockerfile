FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN mkdir -p /app/data

ENV DATABASE=/app/data/app.db
ENV JWT_SECRET=change-me

EXPOSE 5000

CMD ["python", "app.py"]
