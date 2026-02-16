FROM python:3.11-slim

LABEL maintainer="DoctorMen"
LABEL description="Guardian SIEM v2.2 — Security Information and Event Management"

WORKDIR /app

# Install system dependencies for Scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create required directories
RUN mkdir -p database service_logs logs reports

# Non-root user for security
RUN useradd -r -s /bin/false guardian && chown -R guardian:guardian /app
USER guardian

# Expose dashboard port
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/api/health')" || exit 1

# Default command: run the dashboard
CMD ["python", "guardian_dash.py"]
