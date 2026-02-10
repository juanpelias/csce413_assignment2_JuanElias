# Port Knocking Implementation

## Overview
This project implements a **Port Knocking** security mechanism. It hides a protected service (running on TCP Port 2222) behind a firewall that drops all incoming connections by default. 

To access the service, a client must send a specific "secret knock" sequence of UDP packets to the server. Once the correct sequence is detected, the firewall temporarily opens the port for that specific IP address.

## Features
* **Zero-Port Exposure:** The protected service (Port 2222) appears "closed" or "filtered" to scanners (nmap, netcat) until the knock is received.
* **Packet Sniffing:** The server uses raw sockets in Python to listen for UDP packets on specific ports without actually opening them.
* **Dynamic Firewall Management:** Automatically updates `iptables` rules to allow/block IPs based on successful knocks.
* **Automated Demo:** Includes a shell script (`demo.sh`) to demonstrate the full attack/access lifecycle.

## Files
* `knock_server.py`: The daemon that listens for knocks and modifies firewall rules.
* `knock_client.py`: The client tool used to send the secret knock sequence.
* `Dockerfile`: Builds the environment with Python, iptables, and netcat.
* `demo.sh`: An automated script to build, run, and test the project.

## Installation & Setup

### Prerequisites
* Docker installed on the host machine.
* Root privileges (required for `iptables` inside Docker).

### 1. Build the Docker Image
Navigate to the `port_knocking` directory and build the image:

```bash
docker build -t port_knocker .