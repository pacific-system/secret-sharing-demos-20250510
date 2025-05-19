#!/usr/bin/env python3
"""
Configuration parameters for the improved homomorphic encryption implementation.
"""

import os
import random
import platform
import hashlib

# Basic security parameters
KEY_SIZE_BYTES = 32
PAILLIER_KEY_BITS = 1024  # Smaller for testing, use 2048+ for production
BLOCK_SIZE = 16
MAX_CHUNK_SIZE = 512

# Dynamic entropy sources
def get_system_entropy():
    """Get entropy from system sources to mix into the key generation"""
    entropy_sources = [
        str(os.getpid()),
        platform.node(),
        platform.platform(),
        str(random.randint(1, 1000000)),
        str(os.times())
    ]

    # Combine all sources and hash them
    combined = '|'.join(entropy_sources).encode('utf-8')
    return hashlib.sha256(combined).digest()

# Location for key files
KEY_DIR = "keys"
if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR, exist_ok=True)

# Default output location for encrypted files
OUTPUT_DIR = "encrypted"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

# Default output location for decrypted files
DECRYPTED_DIR = "decrypted"
if not os.path.exists(DECRYPTED_DIR):
    os.makedirs(DECRYPTED_DIR, exist_ok=True)

# Initialize a system RNG with entropy from the system
SYSTEM_RNG = random.Random(int.from_bytes(get_system_entropy(), byteorder='big'))