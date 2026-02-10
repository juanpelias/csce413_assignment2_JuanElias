#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   PORT KNOCKING AUTOMATED DEMO        ${NC}"
echo -e "${BLUE}========================================${NC}"

# CLEANUP
echo -e "\n${BLUE}[1] Cleaning up old containers...${NC}"
docker rm -f knock_test 2>/dev/null || true
echo "Old container removed."

# BUILD
echo -e "\n${BLUE}[2] Building Docker Image...${NC}"
docker build -t port_knocker .

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed! Exiting.${NC}"
    exit 1
fi

# RUN
echo -e "\n${BLUE}[3] Starting Container...${NC}"
# --cap-add=NET_ADMIN is crucial for iptables!
docker run --rm -d --cap-add=NET_ADMIN --name knock_test port_knocker

# Give the server a moment to initialize the firewall rules
echo "Waiting 3 seconds for firewall to initialize..."
sleep 3

# GET IP
TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' knock_test)
echo -e "Target Container IP: ${GREEN}$TARGET_IP${NC}"

# TEST 1: EXPECT FAILURE (Port should be locked)
echo -e "\n${BLUE}[4] Testing access BEFORE knocking (Should FAIL)...${NC}"
echo "Trying to connect to $TARGET_IP:2222..."


nc -z -v -w 2 $TARGET_IP 2222
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${GREEN}SUCCESS: Connection timed out or refused. The port is LOCKED.${NC}"
else
    echo -e "${RED}FAILURE: The port is OPEN! Firewall rules are not working.${NC}"
    # We continue anyway to see if knocking breaks anything else, or you can exit here.
fi

# PERFORM THE KNOCK
echo -e "\n${BLUE}[5] Sending Knock Sequence (7000 -> 8000 -> 9000)...${NC}"
python3 knock_client.py --target $TARGET_IP --sequence "7000,8000,9000"

# TEST 2: EXPECT SUCCESS (Port should be open)
echo -e "\n${BLUE}[6] Testing access AFTER knocking (Should SUCCEED)...${NC}"
echo "Trying to connect to $TARGET_IP:2222..."

nc -z -v -w 2 $TARGET_IP 2222
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}SUCCESS: Connection succeeded! The port opened.${NC}"
else
    echo -e "${RED}FAILURE: Connection failed. The port is still locked.${NC}"
fi

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}   DEMO COMPLETE                       ${NC}"
echo -e "${BLUE}========================================${NC}"