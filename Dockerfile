FROM python:3.11-slim

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/ ./app/

# Expose web dashboard port
EXPOSE 8080

# Run FastAPI web app and background Telegram bot
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
