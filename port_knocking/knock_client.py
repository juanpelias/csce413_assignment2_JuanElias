#!/usr/bin/env python3
import argparse
import socket
import time
import sys

def send_knock(target, port, delay):
    try:
        # UDP is best for knocking (no handshake needed)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'Knock', (target, port))
        print(f"[*] Knock sent to {target}:{port} (UDP)")
        sock.close()
    except Exception as e:
        print(f"[-] Error knocking {port}: {e}")
    time.sleep(delay)

def check_access(target, port):
    print(f"[*] Checking access to protected port {port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((target, port))
        print(f"[+] SUCCESS! Port {port} is open!")
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        print(f"[-] LOCKED. Port {port} is closed/dropped.")
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--sequence", default="7000,8000,9000")
    parser.add_argument("--protected-port", type=int, default=2222)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    seq = [int(p) for p in args.sequence.split(",")]

    print(f"--- Performing Knock Sequence: {args.sequence} ---")
    for port in seq:
        send_knock(args.target, port, args.delay)
    
    if args.check:
        time.sleep(0.5) # Allow server split-second to process rule
        check_access(args.target, args.protected_port)

if __name__ == "__main__":
    main()