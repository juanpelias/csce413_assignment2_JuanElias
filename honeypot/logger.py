"""Logging helpers for the honeypot."""

import logging
import os
import sys

LOG_PATH = "/app/logs/honeypot.log"

def create_logger():
    """
    Sets up a logger that writes to both a file and the console.
    """
    # 1. Ensure the log directory exists
    log_dir = os.path.dirname(LOG_PATH)
    os.makedirs(log_dir, exist_ok=True)

    # 2. Configure the Logger
    logger = logging.getLogger("Honeypot")
    logger.setLevel(logging.INFO)
    
    # Avoid adding duplicate handlers if function is called twice
    if logger.hasHandlers():
        logger.handlers.clear()

    # 3. Create Formatter
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # 4. File Handler (Writes to disk)
    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # 5. Stream Handler (Writes to Docker logs/Console)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger