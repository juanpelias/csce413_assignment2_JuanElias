#!/usr/bin/env python3
from scapy.all import sniff, TCP, IP, Raw
import sys

def packet_handler(packet):
    # We only care about TCP packets with a payload (Raw data)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        
        # Check if traffic is to/from MySQL port 3306
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        if src_port == 3306 or dst_port == 3306:
            payload = packet[Raw].load
            
            try:
                # Attempt to decode as ASCII/UTF-8 to see if it's human-readable
                decoded_payload = payload.decode('utf-8', errors='ignore')
                
                # Filter out empty or uninteresting packets to reduce noise
                # We are looking for SQL keywords or user data
                keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "user", "pass", "admin"]
                
                # Check if any keyword exists in the payload (Case insensitive)
                is_suspicious = any(key in decoded_payload.upper() for key in keywords)
                
                print(f"\n[*] Packet: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}")
                
                if is_suspicious:
                    print(f"    [!] CRITICAL: Cleartext SQL Detected!")
                    print(f"    [>] Payload: {decoded_payload}")
                else:
                    # Print a snippet of the raw bytes if it's not obvious text
                    print(f"    [i] Raw Data: {payload[:50]}...")

            except Exception as e:
                print(f"[!] Error parsing packet: {e}")

print("[*] Starting MySQL Sniffer on port 3306...")
print("[*] Waiting for traffic... (Press Ctrl+C to stop)")

# Sniff on loopback (lo) because the containers are likely talking locally or over a docker bridge.
# If 'lo' doesn't work, try 'docker0' or remove the 'iface' argument to let Scapy guess.
try:
    sniff(filter="tcp port 3306", prn=packet_handler, store=0, iface="lo") 
except Exception:
    # Fallback if specific interface fails
    print("[!] Loopback sniff failed, trying default interface...")
    sniff(filter="tcp port 3306", prn=packet_handler, store=0)