#!/usr/bin/env python3
"""
Port Knocking Server - Final Implementation
"""
import argparse
import logging
import socket
import select
import time
import subprocess
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("KnockServer")

def run_cmd(cmd):
    """Helper to run shell commands safely."""
    try:
        subprocess.run(cmd, shell=True, check=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}\nError: {e.stderr.decode().strip()}")
def init_firewall(protected_port):
    """Initialize firewall: Secure Defaults."""
    logger.info("Initializing firewall...")
    
    # 1. Flush existing rules
    run_cmd("iptables -F")
    
    # 2. Allow established connections (Keep this first!)
    run_cmd("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # --- THE FIX IS HERE ---
    # We must DROP the protected port BEFORE we allow other traffic.
    # If we allow "lo" (loopback) first, local tests will bypass the block.
    
    # 3. DROP traffic to the protected port (The Lock)
    run_cmd(f"iptables -A INPUT -p tcp --dport {protected_port} -j DROP")
    
    # 4. Allow loopback (Now safe, because port 2222 was already dropped above)
    run_cmd("iptables -A INPUT -i lo -j ACCEPT")
    
    logger.info(f"Port {protected_port} is now CLOSED (DROP) for everyone.")

def open_port_for_ip(ip, protected_port):
    logger.info(f"Opening port {protected_port} for {ip}")
    run_cmd(f"iptables -I INPUT 1 -s {ip} -p tcp --dport {protected_port} -j ACCEPT")
    
    # Wait 10 seconds, then lock it!
    time.sleep(10)
    
    logger.info(f"Time is up! Locking port {protected_port} for {ip}")
    run_cmd(f"iptables -D INPUT -s {ip} -p tcp --dport {protected_port} -j ACCEPT")

def listen_for_knocks(sequence, window, protected_port):
    # Create UDP sockets for all knock ports
    sockets = []
    port_map = {} # Map socket_obj -> port_number
    
    for port in sequence:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            sockets.append(s)
            port_map[s] = port
            logger.info(f"Listening for knock on UDP port {port}")
        except PermissionError:
            logger.critical(f"Permission denied on port {port}. Run as root!")
            sys.exit(1)

    # State tracking: { '192.168.1.5': {'index': 0, 'last_seen': 12345.6} }
    client_state = {}

    while True:
        # Wait for data on any socket
        readable, _, _ = select.select(sockets, [], [], 1.0)
        current_time = time.time()

        # Clean up timeouts
        expired = [ip for ip, st in client_state.items() if current_time - st['last_seen'] > window]
        for ip in expired:
            del client_state[ip]

        for s in readable:
            data, addr = s.recvfrom(1024)
            ip = addr[0]
            knocked_port = port_map[s]
            
            # Get current progress for this IP
            state = client_state.get(ip, {'index': 0, 'last_seen': current_time})
            expected_port = sequence[state['index']]

            if knocked_port == expected_port:
                # Correct knock
                state['index'] += 1
                state['last_seen'] = current_time
                client_state[ip] = state
                logger.info(f"Hit {state['index']}/{len(sequence)} from {ip} on port {knocked_port}")

                if state['index'] == len(sequence):
                    open_port_for_ip(ip, protected_port)
                    del client_state[ip] # Reset after success
            else:
                # Incorrect knock - reset progress
                logger.info(f"Wrong knock from {ip} on {knocked_port}. Resetting.")
                if ip in client_state:
                    del client_state[ip]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sequence", default="7000,8000,9000", help="Comma-separated knock ports")
    parser.add_argument("--protected-port", type=int, default=2222)
    parser.add_argument("--window", type=float, default=5.0)
    args = parser.parse_args()

    seq_list = [int(p) for p in args.sequence.split(",")]
    init_firewall(args.protected_port)
    listen_for_knocks(seq_list, args.window, args.protected_port)