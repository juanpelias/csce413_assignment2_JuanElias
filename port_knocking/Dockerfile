FROM ubuntu:22.04

# Install Python, iptables, and netcat (to simulate the hidden service)
RUN apt-get update && apt-get install -y \
    python3 \
    iptables \
    netcat \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY knock_server.py knock_client.py /app/

# Create a startup script
# 1. Start a fake service on port 2222 (background)
# 2. Start the knock server (foreground)
RUN echo '#!/bin/bash\n\
nc -lk -p 2222 -e /bin/cat &\n\
echo "Fake Hidden Service started on 2222"\n\
python3 knock_server.py --sequence "7000,8000,9000" --protected-port 2222\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# NET_ADMIN capability is required at runtime for iptables
CMD ["/app/entrypoint.sh"]