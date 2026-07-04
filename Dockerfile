FROM python:3-slim

WORKDIR /app

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and UI assets
COPY flow_collector.py .
COPY dumpredistosqllite.py .
COPY web_ui.py .
COPY static/ ./static/

# Default command (can be overridden in docker-compose)
CMD ["python", "flow_collector.py"]
