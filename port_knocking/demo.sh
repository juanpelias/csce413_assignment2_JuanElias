#!/bin/bash

# Configuration
TARGET_IP="127.0.0.1"
SEQUENCE="7000,8000,9000"
PROTECTED_PORT=2222

echo "========================================"
echo "    PORT KNOCKING DEMONSTRATION"
echo "========================================"

# Step 1: Prove it is closed
echo "[1] Testing access BEFORE knocking..."
# nc -z -v -w 1 checks for open port with 1 sec timeout
nc -z -v -w 1 $TARGET_IP $PROTECTED_PORT 2>&1
if [ $? -ne 0 ]; then
    echo "    -> Port is CLOSED (As expected)"
else
    echo "    -> WARNING: Port is ALREADY OPEN. Reset your firewall!"
fi
echo ""

# Step 2: Perform the Knock
echo "[2] Sending Knock Sequence: $SEQUENCE"
python3 knock_client.py --target $TARGET_IP --sequence "$SEQUENCE" --protected-port $PROTECTED_PORT --delay 0.1
echo ""

# Step 3: Prove it is open
echo "[3] Testing access AFTER knocking..."
# We sleep briefly to let the server process the rules
sleep 1
nc -z -v -w 1 $TARGET_IP $PROTECTED_PORT 2>&1
if [ $? -eq 0 ]; then
    echo "    -> SUCCESS! Port is OPEN."
else
    echo "    -> FAILED. Port is still closed."
fi
echo "========================================"