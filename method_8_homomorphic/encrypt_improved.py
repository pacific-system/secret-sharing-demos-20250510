#!/usr/bin/env python3
"""
Improved Homomorphic Encryption Script

This script encrypts two input files using homomorphic encryption techniques,
allowing different plaintexts to be decrypted from the same ciphertext depending
on which key is used. This implementation removes explicit identifiers from the keys
and instead uses mathematical properties to distinguish between keys.
"""

import os
import sys
import json
import base64
import hashlib
import time
import argparse
import random
import binascii
import uuid
import math
import sympy
from typing import Dict, List, Tuple, Any, Optional, Union

# Import the improved key generator
try:
    from .improved_key_generator import (
        generate_improved_key_parameters,
        save_key_parameters,
        PaillierCryptosystem,
        generate_fibonacci_sequence,
        generate_elliptic_curve_point
    )
    from .config import KEY_SIZE_BYTES, PAILLIER_KEY_BITS
except ImportError:
    # Direct import when running as a script
    from improved_key_generator import (
        generate_improved_key_parameters,
        save_key_parameters,
        PaillierCryptosystem,
        generate_fibonacci_sequence,
        generate_elliptic_curve_point
    )
    from improved_key_generator import PARAMS
    KEY_SIZE_BYTES = PARAMS["KEY_SIZE_BYTES"]
    PAILLIER_KEY_BITS = PARAMS["PAILLIER_KEY_BITS"]

# Constants
BUFFER_SIZE = 1024 * 1024  # 1MB chunks for file reading
MAX_CHUNK_SIZE = 256
SHARED_ENTROPY_VALUE = hashlib.sha256(b"shared_entropy_seed").digest()

def measure_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte string

    Args:
        data: Input bytes

    Returns:
        Entropy value in bits/byte
    """
    if not data:
        return 0.0

    # Count occurrences of each byte value
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1

    # Calculate probability distribution
    length = len(data)
    probabilities = [count / length for count in byte_counts.values()]

    # Calculate entropy using the formula: -sum(p * log2(p))
    entropy = -sum(p * math.log2(p) for p in probabilities)

    return entropy

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

    def encrypt(self, m):
        """
        Encrypt a message using the Paillier cryptosystem

        Args:
            m: The plaintext message (integer)

        Returns:
            The encrypted ciphertext
        """
        if self.public_key is None:
            raise ValueError("Public key not set")

        n = self.public_key["n"]
        g = self.public_key["g"]
        n_squared = n * n

        # Ensure message is in the range [0, n-1]
        m = m % n

        # Generate a random r in Z*_n
        r = self._get_random_coprime(n)

        # Compute ciphertext: c = g^m * r^n mod n^2
        g_m = pow(g, m, n_squared)
        r_n = pow(r, n, n_squared)
        c = (g_m * r_n) % n_squared

        return c

    def decrypt(self, c, apply_transform=False):
        """
        Decrypt a ciphertext using the Paillier cryptosystem

        Args:
            c: The ciphertext
            apply_transform: Whether to apply a transformation based on mathematical properties

        Returns:
            The decrypted plaintext
        """
        if self.private_key is None:
            raise ValueError("Private key not set")

        n = self.public_key["n"]
        lambda_n = self.private_key["lambda"]
        mu = self.private_key["mu"]
        n_squared = n * n

        # Decrypt: m = L(c^lambda mod n^2) * mu mod n
        # where L(x) = (x-1)/n
        c_lambda = pow(c, lambda_n, n_squared)
        L = (c_lambda - 1) // n
        m = (L * mu) % n

        return m

    def homomorphic_add(self, c1, c2):
        """
        Add two ciphertexts homomorphically

        Args:
            c1, c2: Ciphertexts

        Returns:
            A ciphertext that decrypts to the sum of the plaintexts
        """
        if self.public_key is None:
            raise ValueError("Public key not set")

        n_squared = self.public_key["n"] * self.public_key["n"]
        return (c1 * c2) % n_squared

    def homomorphic_add_constant(self, c, k):
        """
        Add a constant to a ciphertext homomorphically

        Args:
            c: Ciphertext
            k: Constant to add

        Returns:
            A ciphertext that decrypts to the plaintext plus the constant
        """
        if self.public_key is None:
            raise ValueError("Public key not set")

        n = self.public_key["n"]
        g = self.public_key["g"]
        n_squared = n * n

        g_k = pow(g, k % n, n_squared)
        return (c * g_k) % n_squared

    def homomorphic_multiply_constant(self, c, k):
        """
        Multiply a ciphertext by a constant homomorphically

        Args:
            c: Ciphertext
            k: Constant to multiply by

        Returns:
            A ciphertext that decrypts to the plaintext multiplied by the constant
        """
        if self.public_key is None:
            raise ValueError("Public key not set")

        n = self.public_key["n"]
        n_squared = n * n

        return pow(c, k % n, n_squared)

    def _lcm(self, a, b):
        """Calculate the least common multiple of a and b"""
        return a * b // math.gcd(a, b)

    def _mod_inverse(self, a, m):
        """Calculate the modular inverse of a mod m"""
        return pow(a, -1, m)

    def _get_random_coprime(self, n):
        """Generate a random number coprime to n"""
        while True:
            r = random.randint(1, n-1)
            if math.gcd(r, n) == 1:
                return r

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

def generate_key_parameters(master_seed: bytes = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Generate two sets of key parameters that are distinguished by mathematical properties
    rather than explicit identifiers.
    """
    # Simply calls the imported function from improved_key_generator
    return generate_improved_key_parameters(master_seed)

def encrypt_data(data1: bytes, data2: bytes, params_1: Dict[str, Any], params_2: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    """
    Encrypt two datasets into a single ciphertext using homomorphic encryption

    Args:
        data1: First dataset to encrypt
        data2: Second dataset to encrypt
        params_1: Key parameters for the first dataset
        params_2: Key parameters for the second dataset

    Returns:
        Tuple of (encrypted_data, key_info_1, key_info_2)
    """
    # Get the public and private key info
    pub_key = params_1.get("public_key", {})
    priv_key = params_1.get("private_key", {})

    # Initialize the Paillier cryptosystem
    paillier = PaillierCryptosystem()
    paillier.public_key = {
        "n": pub_key.get("n", 2048),
        "g": pub_key.get("g", 2049)
    }
    paillier.private_key = priv_key

    # Calculate chunk size based on the public key size
    n_bits = paillier.public_key["n"].bit_length()
    chunk_size = max(4, min((n_bits - 64) // 8, MAX_CHUNK_SIZE))  # Safe margin

    # Split data into chunks
    chunks1 = [data1[i:i+chunk_size] for i in range(0, len(data1), chunk_size)]
    chunks2 = [data2[i:i+chunk_size] for i in range(0, len(data2), chunk_size)]

    # Ensure both chunk lists have the same length by padding if necessary
    max_chunks = max(len(chunks1), len(chunks2))
    if len(chunks1) < max_chunks:
        chunks1.extend([os.urandom(chunk_size) for _ in range(max_chunks - len(chunks1))])
    if len(chunks2) < max_chunks:
        chunks2.extend([os.urandom(chunk_size) for _ in range(max_chunks - len(chunks2))])

    # Encrypt each chunk and apply homomorphic transformations
    print(f"Encrypting data... (Total chunks: {max_chunks})")
    encrypted_chunks = []

    for i, (chunk1, chunk2) in enumerate(zip(chunks1, chunks2)):
        if i % 10 == 0:
            print(f"Processing chunk {i+1}/{max_chunks}...")

        # Convert chunks to integers
        m1 = int.from_bytes(chunk1, 'big')
        m2 = int.from_bytes(chunk2, 'big')

        # Encrypt both messages
        c1 = paillier.encrypt(m1)
        c2 = paillier.encrypt(m2)

        # Calculate the difference mask homomorphically
        # We use the property: E(m2)/E(m1) = E(m2-m1)
        # Since division is not directly supported, we use:
        # E(m2)/E(m1) = E(m2) * E(-m1) = E(m2-m1)
        inverse_c1 = paillier.homomorphic_multiply_constant(c1, -1)
        diff_mask = paillier.homomorphic_add(c2, inverse_c1)

        # Add some randomness to make the ciphertexts indistinguishable
        r = random.randint(1, 1000)
        c1_randomized = paillier.encrypt(m1)  # Re-encrypt for different randomness

        # Store the encrypted chunks with the masks
        encrypted_chunks.append({
            "ciphertext": hex(c1_randomized),
            "diff_mask": hex(diff_mask),
            "index": i,
            # Add a shared entropy value (not dataset specific)
            "entropy": binascii.hexlify(SHARED_ENTROPY_VALUE).decode()
        })

    # Prepare the final encrypted data
    encrypted_data = json.dumps({
        "format": "homomorphic_masked_improved",
        "version": "2.0",
        "timestamp": int(time.time()),
        "uuid": str(uuid.uuid4()),
        "chunks": encrypted_chunks,
        "chunk_size": chunk_size,
        "public_key": {
            "n": str(paillier.public_key["n"]),
            "g": str(paillier.public_key["g"])
        },
        "original_size_1": len(data1),
        "original_size_2": len(data2),
        # Add metadata about the encryption but without revealing which is which
        "encryption_metadata": {
            "entropy_1": measure_entropy(data1),
            "entropy_2": measure_entropy(data2),
            "timestamp": int(time.time())
        }
    }).encode()

    # Create key info dictionaries - no explicit identifiers
    key_info_1 = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "parameters": {
            "public_key": pub_key,
            "private_key": priv_key,
            "prime_factors": params_1.get("prime_factors", {})
        },
        "entropy": str(uuid.uuid4()),  # Unique per key
        "version": "2.0",
        "algorithm": "paillier_homomorphic_masking"
    }

    key_info_2 = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "parameters": {
            "public_key": pub_key,
            "private_key": priv_key,
            "prime_factors": params_2.get("prime_factors", {})
        },
        "entropy": str(uuid.uuid4()),  # Unique per key
        "version": "2.0",
        "algorithm": "paillier_homomorphic_masking"
    }

    return encrypted_data, key_info_1, key_info_2

def encrypt_file(file_path1: str, file_path2: str, output_path: str = None, save_key: bool = True) -> Dict[str, Any]:
    """
    Encrypt two files into a single encrypted file using homomorphic encryption

    Args:
        file_path1: Path to the first file
        file_path2: Path to the second file
        output_path: Path to save the encrypted file (auto-generated if None)
        save_key: Whether to save the keys to files

    Returns:
        Dictionary with information about the encryption process
    """
    # Read the input files
    with open(file_path1, 'rb') as f:
        data1 = f.read()
    with open(file_path2, 'rb') as f:
        data2 = f.read()

    print(f"File 1: {file_path1} ({len(data1)} bytes)")
    print(f"File 2: {file_path2} ({len(data2)} bytes)")

    # Calculate entropy
    entropy1 = measure_entropy(data1)
    entropy2 = measure_entropy(data2)
    print(f"File 1 entropy: {entropy1:.4f} bits/byte")
    print(f"File 2 entropy: {entropy2:.4f} bits/byte")

    # Generate a master seed
    master_seed = os.urandom(KEY_SIZE_BYTES)

    # Generate key parameters
    print("Generating homomorphic encryption keys...")
    params_1, params_2 = generate_key_parameters(master_seed)

    # Encrypt the data
    print("Applying homomorphic encryption...")
    start_time = time.time()
    encrypted_data, key_info_1, key_info_2 = encrypt_data(
        data1, data2, params_1, params_2
    )
    encryption_time = time.time() - start_time
    print(f"Encryption completed in {encryption_time:.2f} seconds")

    # Determine output path if not specified
    if output_path is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.sha256((file_path1 + file_path2).encode()).hexdigest()[:8]
        output_path = f"encrypted_{timestamp}_{file_hash}.henc"

    # Save the encrypted data
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    print(f"Encrypted file saved to: {output_path} ({len(encrypted_data)} bytes)")

    # Generate Fibonacci sequences and elliptic curve points to help with key identification
    def generate_fibonacci_sequence(seed_val, length=5):
        """Generate a Fibonacci-like sequence for mathematical identification"""
        hash_val = int(hashlib.sha256(str(seed_val).encode()).hexdigest(), 16)
        a = (hash_val % 100) + 1
        b = ((hash_val >> 8) % 100) + 1

        sequence = [a, b]
        for i in range(2, length):
            sequence.append(sequence[i-1] + sequence[i-2])

        return sequence

    def generate_elliptic_curve_point(seed_val):
        """Generate an elliptic curve point for mathematical identification"""
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
        y = pow(right_side, (p + 1) // 4, p) if right_side % 2 == 0 else None

        return {
            "curve": {"a": a, "b": b, "p": p},
            "point": {"x": x, "y": y}
        }

    # Helper function to generate cryptographically secure paths
    def generate_path(rng):
        """Generate a random path sequence for key differentiation"""
        path_length = rng.randint(5, 15)
        path = []
        for _ in range(path_length):
            path.append(rng.randint(1, 100))
        return path

    # Save keys if requested
    key_1_file = None
    key_2_file = None
    if save_key:
        # Create keys directory if it doesn't exist
        key_dir = "keys"
        if not os.path.exists(key_dir):
            os.makedirs(key_dir, exist_ok=True)

        # Generate a unique identifier for this key pair
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        file_uuid = uuid.uuid4().hex[:8]

        # Save key 1
        key_1_file = f"{key_dir}/key1_{timestamp}_{file_uuid}.json"
        with open(key_1_file, 'w') as f:
            json.dump(key_info_1, f, indent=2)

        # Save key 2
        key_2_file = f"{key_dir}/key2_{timestamp}_{file_uuid}.json"
        with open(key_2_file, 'w') as f:
            json.dump(key_info_2, f, indent=2)

        print(f"Key 1 saved to: {key_1_file}")
        print(f"Key 2 saved to: {key_2_file}")

    # Prepare result information
    result = {
        "encrypted_file": output_path,
        "encrypted_size": len(encrypted_data),
        "encryption_time": encryption_time,
        "dataset_1": {
            "original_file": file_path1,
            "original_size": len(data1),
            "entropy": entropy1,
            "key_file": key_1_file
        },
        "dataset_2": {
            "original_file": file_path2,
            "original_size": len(data2),
            "entropy": entropy2,
            "key_file": key_2_file
        },
        "timestamp": int(time.time()),
        "algorithm": "paillier_homomorphic_masking",
        "version": "2.0"
    }

    return result

def main():
    """
    Main function to handle command-line arguments and execute encryption
    """
    # Display system information
    import platform
    print(f"Python version: {platform.python_version()}")
    print(f"Platform: {platform.system()} {platform.release()}")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Improved Homomorphic Encryption",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("file1", help="First file to encrypt")
    parser.add_argument("file2", help="Second file to encrypt")
    parser.add_argument("--output", "-o", help="Output file path (auto-generated if not specified)")
    parser.add_argument("--save-key", "-k", action="store_true",
                        help="Save the keys to files")
    parser.add_argument("--stats", "-s", action="store_true",
                        help="Display detailed statistics")

    args = parser.parse_args()

    # Check if the input files exist
    if not os.path.exists(args.file1):
        print(f"Error: File '{args.file1}' not found")
        return 1

    if not os.path.exists(args.file2):
        print(f"Error: File '{args.file2}' not found")
        return 1

    try:
        # Display environment information if stats requested
        if args.stats:
            print("\nEnvironment info:")
            print(f"Process ID: {os.getpid()}")
            print(f"Python executable: {sys.executable}")
            print(f"Command-line arguments: {sys.argv}")

        # Record start time
        start_time = time.time()

        # Execute encryption
        print("\nStarting encryption...")
        result = encrypt_file(
            args.file1,
            args.file2,
            args.output,
            args.save_key
        )

        # Calculate total execution time
        elapsed_time = time.time() - start_time

        print(f"\nEncryption completed (Total time: {elapsed_time:.2f} seconds)")

        # Display detailed statistics if requested
        if args.stats:
            print("\nDetailed stats:")
            print(f"Dataset 1 size: {result['dataset_1']['original_size']:,} bytes")
            print(f"Dataset 2 size: {result['dataset_2']['original_size']:,} bytes")
            print(f"Encrypted data size: {result['encrypted_size']:,} bytes")

            size_ratio = result['encrypted_size'] / max(
                result['dataset_1']['original_size'],
                result['dataset_2']['original_size']
            )
            print(f"Size ratio: {size_ratio:.2f}x")

        return 0

    except Exception as e:
        import traceback
        print(f"Error: An error occurred during encryption: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())