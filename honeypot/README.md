# Honeypot 

## Overview
Implements a **High-Interaction SSH Honeypot** designed to deceive attackers into thinking they have gained access to a vulnerable Ubuntu server. 

Unlike simple "low-interaction" honeypots that only open a port, this system uses the Python `paramiko` library to emulate a full SSH session. It allows attackers to log in with **any** password, provides a fake interactive shell, and silently logs every keystroke and command they execute.

## Features
* **Fake Authentication:** Accepts all username/password combinations to maximize attacker engagement.
* **Interactive Shell:** Simulates a realistic terminal prompt (`root@server:~#`).
* **File System Emulation:** Responds to common Linux commands (`ls`, `pwd`, `whoami`, `exit`) to maintain the illusion.
* **Comprehensive Logging:** detailed logs of:
    * Source IP addresses
    * Authentication attempts (usernames/passwords)
    * Exact commands entered by the attacker
    * Timestamps for forensic analysis

## Architecture & Design
The solution is containerized using Docker and consists of two main Python components:

1.  **`honeypot.py` (The Core):**
    * Initializes a socket listener on port 2222.
    * Uses `paramiko` to handle SSH encryption and negotiation.
    * Spawns a new thread for every connection to handle multiple attackers simultaneously.
    * Contains the "Fake Shell" logic that parses user input and returns pre-defined responses.

2.  **`logger.py` (The Observer):**
    * A centralized logging module.
    * Writes events to both the console (standard output) and a persistent file (`/app/logs/honeypot.log`).
    * Ensures logs are formatted cleanly for easy parsing: `TIMESTAMP - LEVEL - MESSAGE`.

## Installation & Setup

### Prerequisites
* Docker installed on the host machine.

### 1. Build the Docker Image
Navigate to the `honeypot` directory and build the image:

```bash
docker build -t ssh_honeypot .