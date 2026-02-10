#!/usr/bin/env python3
"""
Port Scanner - Assignment 2: Network Security
Meets Minimum Requirements:
- Argument parsing for target/range
- TCP Connect Scan
- Service/Banner Detection (Passive & Active)
- Multi-threaded speed
- Graceful Error Handling
"""

import socket
import argparse
import concurrent.futures
from datetime import datetime
import sys

def grab_banner(s, target):
    """
    Attempts to grab a banner from a connected socket.
    Strategies:
    1. Passive: Wait for server to send (SSH, SMTP, FTP)
    2. Active (HTTP): Send a HEAD request
    3. Active (Generic): Send a newline
    """
    s.settimeout(2.0) # Increase timeout slightly for SSH
    
    # 1. Passive Listen (SSH/FTP/SMTP usually speak first)
    try:
        banner = s.recv(1024).decode(errors='ignore').strip()
        if banner:
            return banner
    except Exception:
        pass

    # 2. Active HTTP Probe (If passive failed, try to speak HTTP)
    try:
        probe = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
        s.sendall(probe)
        response = s.recv(1024).decode(errors='ignore')
        
        if "HTTP/" in response:
            # Extract the 'Server' header if it exists
            lines = response.split('\r\n')
            status_line = lines[0] # e.g., "HTTP/1.1 200 OK"
            server_version = ""
            
            for line in lines:
                if line.lower().startswith("server:"):
                    server_version = line[8:].strip() # Grab text after "Server: "
                    break
            
            # Return specific version if found, otherwise default status
            if server_version:
                return f"{status_line} | Version: {server_version}"
            return status_line

        # If it echoed our probe exactly, it's an Echo Server, not HTTP
        if "HEAD / HTTP/1.0" in response:
             return "ECHO SERVICE DETECTED"
             
    except Exception:
        pass

    return None

def scan_port(target, port, timeout=1.0):
    """Scan a single port and return result if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # connect_ex returns 0 on success
            if s.connect_ex((target, port)) == 0:
                banner = grab_banner(s, target)
                return {"port": port, "open": True, "banner": banner}
    except Exception:
        pass
    return None

def guess_service(port, banner):
    """Identify service based on port and banner content."""
    # Known default ports
    common_ports = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 3306: "mysql", 3389: "rdp", 
        6379: "redis", 8080: "http-alt", 8888: "secret_api"
    }

    service = common_ports.get(port, "unknown")

    # Refine based on banner info if available
    if banner:
        b_lower = banner.lower()
        if "ssh" in b_lower: service = "ssh"
        elif "http" in b_lower or "html" in b_lower: service = "http"
        elif "ftp" in b_lower: service = "ftp"
        elif "mysql" in b_lower: service = "mysql"
        elif "smtp" in b_lower: service = "smtp"
    
    return service

def scan_range(target, start_port, end_port, timeout):
    print(f"[*] Scanning {target} ports {start_port}-{end_port}...")
    start_time = datetime.now()
    
    open_ports = []
    
    # Generate port list
    ports = range(start_port, end_port + 1)
    total_ports = len(ports)
    
    # ThreadPoolExecutor for concurrency
    # Lowered workers slightly to prevent system file descriptor limits on some OS
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, target, p, timeout): p for p in ports}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
            
            # Optional: Simple progress indicator for large ranges
            completed += 1
            if total_ports > 500 and completed % 100 == 0:
                print(f"    Progress: {completed}/{total_ports} ports scanned...", end='\r')

    if total_ports > 500:
        print(" " * 40, end='\r') # Clear progress line

    duration = datetime.now() - start_time
    print(f"[*] Scan completed in {duration.total_seconds():.2f}s")
    
    return sorted(open_ports, key=lambda x: x['port'])

def main():
    parser = argparse.ArgumentParser(description="Custom TCP Port Scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--start", type=int, default=1, help="Start port")
    parser.add_argument("--end", type=int, default=1024, help="End port")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout")
    
    args = parser.parse_args()
    
    # 1. Validate Target
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"[*] Target resolved: {args.target} -> {target_ip}")
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)

    # 2. Run Scan
    results = scan_range(target_ip, args.start, args.end, args.timeout)

    # 3. Display Results in a Table
    print(f"\n{'-'*65}")
    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
    print(f"{'-'*65}")

    if not results:
        print("No open ports found.")
    else:
        for r in results:
            port_str = f"{r['port']}/tcp"
            banner_str = r['banner'] if r['banner'] else ""
            service_str = guess_service(r['port'], banner_str)
            
            # Truncate long banners for display
            if len(banner_str) > 30:
                banner_str = banner_str[:27] + "..."
                
            print(f"{port_str:<8} {'OPEN':<10} {service_str:<15} {banner_str}")
    print(f"{'-'*65}\n")

if __name__ == "__main__":
    main()