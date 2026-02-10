FROM ubuntu:22.04

# Install Python, iptables, and netcat-traditional (crucial fix!)
RUN apt-get update && apt-get install -y \
    python3 \
    iptables \
    netcat-traditional \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Fix: Make 'nc' use the traditional version (which supports -e)
RUN update-alternatives --set nc /bin/nc.traditional

WORKDIR /app
COPY knock_server.py knock_client.py /app/

# Create startup script
# We use -e /bin/cat so it behaves like an echo server
RUN echo '#!/bin/bash\n\
nc -lk -p 2222 -e /bin/cat &\n\
echo "Fake Hidden Service started on 2222"\n\
python3 knock_server.py --sequence "7000,8000,9000" --protected-port 2222\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]