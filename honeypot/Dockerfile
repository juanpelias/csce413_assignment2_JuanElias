FROM python:3.9-slim

# Install dependencies for Paramiko
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install paramiko cryptography

WORKDIR /app

# Copy ALL python files (this grabs honeypot.py AND logger.py)
COPY *.py /app/

# Create logs directory
RUN mkdir -p /app/logs

EXPOSE 2225

CMD ["python", "honeypot.py"]