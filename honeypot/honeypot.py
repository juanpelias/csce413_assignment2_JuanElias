#!/usr/bin/env python3
"""
SSH Honeypot Implementation using Paramiko
"""

import socket
import threading
import time
import paramiko
import os

# Import our custom logger
from logger import create_logger

# Initialize Logger
logger = create_logger()

# Configuration
HOST_KEY_FILE = "/app/server.key"
BIND_IP = "0.0.0.0"
BIND_PORT = 2225

def generate_host_key():
    """Generate a host key if it doesn't exist."""
    if not os.path.exists(HOST_KEY_FILE):
        logger.info("Generating new RSA host key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_FILE)
    return paramiko.RSAKey(filename=HOST_KEY_FILE)

class HoneypotServer(paramiko.ServerInterface):
    """
    The brain of the honeypot. It decides how to handle SSH events.
    """
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        Log every login attempt and accept them all.
        """
        logger.info(f"LOGIN ATTEMPT: IP={self.client_ip} User={username} Password={password}")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_connection(client_sock, addr, host_key):
    """
    Handle the SSH session for a connected attacker.
    """
    ip = addr[0]
    logger.info(f"CONNECTION: New connection from {ip}")
    
    transport = paramiko.Transport(client_sock)
    try:
        transport.add_server_key(host_key)
        server = HoneypotServer(ip)
        
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            logger.warning("SSH negotiation failed.")
            return

        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)
        if not server.event.is_set():
            channel.close()
            return

        # --- FAKE SHELL ---
        channel.send("Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)\r\n\r\n")
        channel.send("System information disabled due to load.\r\n")
        
        prompt = "root@server:~# "
        channel.send(prompt)
        
        command_buffer = ""
        while True:
            recv = channel.recv(1024)
            if not recv:
                break
            
            data = recv.decode('utf-8', errors='ignore')
            
            if '\r' in data or '\n' in data:
                cmd = command_buffer.strip()
                if cmd:
                    logger.info(f"COMMAND EXEC: IP={ip} Cmd='{cmd}'")
                
                channel.send("\r\n")
                
                if cmd == "exit":
                    channel.send("logout\r\n")
                    break
                elif cmd == "ls":
                    channel.send("Documents  Downloads  passwords.txt  server.py\r\n")
                elif cmd == "whoami":
                    channel.send("root\r\n")
                elif cmd == "pwd":
                    channel.send("/root\r\n")
                elif cmd:
                    channel.send(f"bash: {cmd}: command not found\r\n")
                
                channel.send(prompt)
                command_buffer = ""
            elif data == '\x7f' or data == '\b':
                if len(command_buffer) > 0:
                    command_buffer = command_buffer[:-1]
                    channel.send('\b \b') 
            else:
                channel.send(data)
                command_buffer += data

        channel.close()
    
    except Exception as e:
        logger.error(f"Error handling connection: {e}")
    finally:
        transport.close()
        logger.info(f"DISCONNECT: Closed connection from {ip}")

def run_honeypot():
    host_key = generate_host_key()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((BIND_IP, BIND_PORT))
    except Exception as e:
        logger.error(f"Bind failed: {e}")
        return

    sock.listen(100)
    logger.info(f"Honeypot listening on {BIND_IP}:{BIND_PORT} (SSH)")

    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(client, addr, host_key))
            t.start()
        except Exception as e:
            logger.error(f"Accept failed: {e}")

if __name__ == "__main__":
    run_honeypot()