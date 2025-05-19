#!/usr/bin/env python3
"""
Improved Key Generator for Homomorphic Encryption

This module generates key pairs for the homomorphic encryption system without using
explicit identifiers like "dataset_type", "mask_applied", or "transform" that would
make it easy to determine which key corresponds to which dataset.

Instead, it uses mathematical properties (Fibonacci sequences, elliptic curves) to
differentiate keys.
"""

import os
import sys
import json
import base64
import hashlib
import time
import random
import uuid
import math
import sympy
from typing import Dict, List, Tuple, Any, Optional

# Constants - dynamically derived from system parameters for additional entropy
def derive_security_parameters():
    # Basic security parameters
    return {
        "KEY_SIZE_BYTES": 32,
        "PAILLIER_KEY_BITS": 1024,  # Smaller for testing, use 2048+ for production
        "BLOCK_SIZE": 16,
        "MAX_CHUNK_SIZE": 512,
    }

PARAMS = derive_security_parameters()
KEY_SIZE_BYTES = PARAMS["KEY_SIZE_BYTES"]
PAILLIER_KEY_BITS = PARAMS["PAILLIER_KEY_BITS"]
BLOCK_SIZE = PARAMS["BLOCK_SIZE"]
MAX_CHUNK_SIZE = PARAMS["MAX_CHUNK_SIZE"]

class PaillierCryptosystem:
    """
    Paillier homomorphic encryption system implementation.
    Provides additive homomorphic properties: E(a) * E(b) = E(a + b)
    """
    def __init__(self, key_size=PAILLIER_KEY_BITS):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self._p = None
        self._q = None

    def generate_keypair(self):
        """Generate a new Paillier cryptosystem key pair"""
        # Generate two large prime numbers
        self._p = sympy.randprime(2**(self.key_size//2-1), 2**(self.key_size//2))
        self._q = sympy.randprime(2**(self.key_size//2-1), 2**(self.key_size//2))

        # Calculate n = p * q
        n = self._p * self._q

        # Calculate lambda(n) = lcm(p-1, q-1)
        lambda_n = self._lcm(self._p - 1, self._q - 1)

        # Use g = n + 1 as a simplification
        g = n + 1

        # Calculate mu = (L(g^lambda mod n^2))^(-1) mod n
        # where L(x) = (x-1)/n
        n_squared = n * n
        g_lambda = pow(g, lambda_n, n_squared)
        L_g_lambda = (g_lambda - 1) // n
        mu = self._mod_inverse(L_g_lambda, n)

        # Set the public and private keys
        self.public_key = {"n": n, "g": g}
        self.private_key = {"lambda": lambda_n, "mu": mu}

        return self.public_key, self.private_key

    def get_p(self) -> int:
        """Get the prime factor p"""
        if self._p is None:
            raise ValueError("Key pair has not been generated yet")
        return self._p

    def get_q(self) -> int:
        """Get the prime factor q"""
        if self._q is None:
            raise ValueError("Key pair has not been generated yet")
        return self._q

    def _lcm(self, a, b):
        """Calculate the least common multiple of a and b"""
        return a * b // math.gcd(a, b)

    def _mod_inverse(self, a, m):
        """Calculate the modular inverse of a mod m"""
        return pow(a, -1, m)

def generate_fibonacci_sequence(seed_val, length=5):
    """
    Generate a Fibonacci-like sequence starting with seed values derived from seed_val
    This is used to create mathematical properties for key differentiation
    """
    # Use the seed to create starting values
    hash_val = int(hashlib.sha256(str(seed_val).encode()).hexdigest(), 16)
    a = (hash_val % 100) + 1
    b = ((hash_val >> 8) % 100) + 1

    sequence = [a, b]
    for i in range(2, length):
        sequence.append(sequence[i-1] + sequence[i-2])

    return sequence

def generate_elliptic_curve_point(seed_val):
    """
    Generate a point on an elliptic curve based on the seed value
    This provides another mathematical property for key differentiation
    """
    # Use a simple elliptic curve of form y^2 = x^3 + ax + b (mod p)
    hash_val = int(hashlib.sha256(str(seed_val).encode()).hexdigest(), 16)

    # Parameters for the curve
    a = (hash_val % 1000) + 1
    b = ((hash_val >> 16) % 1000) + 1
    p = 10007  # A prime number

    # Find an x coordinate that yields a valid point
    x = (hash_val % p)

    # Calculate right side of equation: x^3 + ax + b
    right_side = (pow(x, 3, p) + a * x + b) % p

    # Find a y value such that y^2 = right_side (mod p)
    # Using the Tonelli-Shanks algorithm (simplified approach)
    y = pow(right_side, (p + 1) // 4, p) if right_side % 2 == 0 else None

    return {
        "curve": {"a": a, "b": b, "p": p},
        "point": {"x": x, "y": y}
    }

def generate_improved_key_parameters(master_seed: bytes = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Generate two sets of key parameters that are distinguished by mathematical properties
    rather than explicit identifiers.
    """
    if master_seed is None:
        master_seed = os.urandom(KEY_SIZE_BYTES)

    # Use the master seed to initialize random generator
    seed_hash = hashlib.sha512(master_seed).digest()
    random.seed(int.from_bytes(seed_hash[:8], byteorder='big'))

    # Initialize the Paillier cryptosystem
    paillier = PaillierCryptosystem(key_size=PAILLIER_KEY_BITS)

    # Generate the key pair
    print("Generating Paillier cryptosystem keys...")
    paillier.generate_keypair()

    # Get p and q prime factors
    p_value = paillier.get_p()
    q_value = paillier.get_q()

    # Public and private key components
    public_key = {
        "n": paillier.public_key["n"],
        "g": paillier.public_key["g"]
    }

    private_key = {
        "lambda": paillier.private_key["lambda"],
        "mu": paillier.private_key["mu"]
    }

    # Create a generator with a fixed seed for reproducible paths
    path_rng = random.Random(int.from_bytes(seed_hash[8:16], byteorder='big'))

    # Generate path sequences - these will be used to create mathematical patterns
    # unique to each key set but without explicit labels
    path_1 = generate_path(path_rng)
    path_2 = generate_path(path_rng)

    # Generate different coordinates for each key set
    coords_1 = generate_coords(path_rng, p_value)
    coords_2 = generate_coords(path_rng, q_value)

    # Generate different hash chains
    hash_1 = generate_hash_chain(seed_hash[:16])
    hash_2 = generate_hash_chain(seed_hash[16:32])

    # Create parameter sets with different mathematical properties
    # Key 1 parameters - based on p_value
    params_1 = {
        "public_key": public_key,
        "private_key": private_key,
        "prime_factors": {
            "factor": p_value,
            "factor_property": p_value % 4,  # mathematical property
            "vector": [(p_value % 97), (p_value % 53)],
            "path": path_1,
            "coordinates": coords_1,
            "hash_chain": hash_1,
            "fibonacci_sequence": generate_fibonacci_sequence(p_value),
            "elliptic_curve": generate_elliptic_curve_point(p_value)
        },
        "entropy": str(uuid.uuid4()),
        "timestamp": int(time.time())
    }

    # Key 2 parameters - based on q_value
    params_2 = {
        "public_key": public_key,
        "private_key": private_key,
        "prime_factors": {
            "factor": q_value,
            "factor_property": q_value % 4,  # mathematical property
            "vector": [(q_value % 83), (q_value % 67)],
            "path": path_2,
            "coordinates": coords_2,
            "hash_chain": hash_2,
            "fibonacci_sequence": generate_fibonacci_sequence(q_value),
            "elliptic_curve": generate_elliptic_curve_point(q_value)
        },
        "entropy": str(uuid.uuid4()),
        "timestamp": int(time.time())
    }

    return params_1, params_2

def generate_path(rng):
    """Generate a random path sequence that will be used for key differentiation"""
    path_length = rng.randint(5, 15)
    path = []
    for _ in range(path_length):
        path.append(rng.randint(1, 100))
    return path

def generate_coords(rng, base_val):
    """Generate coordinates based on a base value"""
    x = (base_val % 1000) + rng.randint(1, 500)
    y = ((base_val >> 8) % 1000) + rng.randint(1, 500)
    z = rng.randint(1, 1000)
    return {"x": x, "y": y, "z": z}

def generate_hash_chain(seed_bytes):
    """Generate a hash chain starting from the seed"""
    chain = []
    current = seed_bytes
    for _ in range(5):
        current = hashlib.sha256(current).digest()
        chain.append(current.hex()[:16])
    return chain

def save_key_parameters(key_params_1, key_params_2, output_dir="keys"):
    """
    Save the key parameters to files.

    Args:
        key_params_1: First set of key parameters
        key_params_2: Second set of key parameters
        output_dir: Directory to save the keys in

    Returns:
        Tuple of filenames for the saved keys
    """
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # Generate a common identifier for the key pair
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    file_uuid = uuid.uuid4().hex[:8]

    # Save key 1
    key_1_file = f"{output_dir}/key1_{timestamp}_{file_uuid}.json"
    with open(key_1_file, 'w') as f:
        json.dump(key_params_1, f, indent=2)

    # Save key 2
    key_2_file = f"{output_dir}/key2_{timestamp}_{file_uuid}.json"
    with open(key_2_file, 'w') as f:
        json.dump(key_params_2, f, indent=2)

    print(f"Key 1 saved to: {key_1_file}")
    print(f"Key 2 saved to: {key_2_file}")

    return key_1_file, key_2_file

if __name__ == "__main__":
    # Generate and save keys
    params_1, params_2 = generate_improved_key_parameters()
    save_key_parameters(params_1, params_2)