#!/usr/bin/env python3
"""
Improved Homomorphic Encryption Decryption Script

This script decrypts a file that was encrypted using the improved homomorphic encryption
method. It determines which dataset to decrypt based on mathematical properties of the key
rather than explicit identifiers.
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

# Import the improved key generator components
try:
    from .improved_key_generator import (
        PaillierCryptosystem,
        generate_fibonacci_sequence,
        generate_elliptic_curve_point
    )
    from .config import KEY_SIZE_BYTES, PAILLIER_KEY_BITS
except ImportError:
    # Direct import when running as a script
    from improved_key_generator import (
        PaillierCryptosystem,
        generate_fibonacci_sequence,
        generate_elliptic_curve_point
    )
    from improved_key_generator import PARAMS
    KEY_SIZE_BYTES = PARAMS["KEY_SIZE_BYTES"]
    PAILLIER_KEY_BITS = PARAMS["PAILLIER_KEY_BITS"]

def analyze_key_mathematical_properties(key_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze the mathematical properties of a key to determine its type

    This function examines various mathematical properties of the key parameters
    to determine which dataset the key is meant to decrypt. It replaces explicit
    identifiers with mathematical patterns.

    Args:
        key_params: The key parameters

    Returns:
        Dictionary with analysis results including the determined key type
    """
    # Extract relevant parameters
    prime_factors = key_params.get("parameters", {}).get("prime_factors", {})

    # Get prime factor value
    factor = prime_factors.get("factor")
    if not factor:
        raise ValueError("Invalid key format: missing prime factor")

    # Extract mathematical properties
    factor_property = prime_factors.get("factor_property")
    vector = prime_factors.get("vector", [])
    path = prime_factors.get("path", [])
    fibonacci_seq = prime_factors.get("fibonacci_sequence", [])
    elliptic_curve = prime_factors.get("elliptic_curve", {})

    # Calculate various mathematical properties to differentiate keys
    # These computations serve as "fingerprints" for the key type

    # 1. Analyze prime factor properties
    remainder_2 = factor % 2  # Is the factor odd or even?
    remainder_3 = factor % 3
    remainder_4 = factor % 4

    # 2. Check if the factor follows specific mathematical patterns
    square_property = math.isqrt(factor) ** 2 == factor

    # 3. Analyze the vector pattern (if provided)
    vector_pattern = None
    if len(vector) >= 2:
        # Look at the relationship between vector components
        if vector[0] % 2 == 0 and vector[1] % 2 == 0:
            vector_pattern = "even_even"
        elif vector[0] % 2 == 1 and vector[1] % 2 == 1:
            vector_pattern = "odd_odd"
        else:
            vector_pattern = "mixed"

    # 4. Analyze the Fibonacci sequence
    fibonacci_pattern = None
    if len(fibonacci_seq) >= 3:
        # Check if the sequence follows the Fibonacci property
        valid_fibonacci = True
        for i in range(2, len(fibonacci_seq)):
            if fibonacci_seq[i] != fibonacci_seq[i-1] + fibonacci_seq[i-2]:
                valid_fibonacci = False
                break
        fibonacci_pattern = "valid" if valid_fibonacci else "invalid"

    # 5. Analyze elliptic curve point
    ec_property = None
    if elliptic_curve and "point" in elliptic_curve and "curve" in elliptic_curve:
        point = elliptic_curve["point"]
        curve = elliptic_curve["curve"]

        if all(k in point for k in ["x", "y"]) and all(k in curve for k in ["a", "b", "p"]):
            # Verify if the point is on the curve: y^2 ≡ x^3 + ax + b (mod p)
            x, y = point["x"], point["y"]
            a, b, p = curve["a"], curve["b"], curve["p"]

            if y is not None:
                left_side = (y ** 2) % p
                right_side = (pow(x, 3, p) + a * x + b) % p
                ec_property = "valid" if left_side == right_side else "invalid"

    # 6. Additional mathematical property: Digital root
    digital_root = factor
    while digital_root >= 10:
        digital_root = sum(int(digit) for digit in str(digital_root))

    # 7. Factor property analysis: sum of digits
    digit_sum = sum(int(digit) for digit in str(factor))

    # 8. Prime factorization pattern
    def is_prime(n):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0 or n % 3 == 0:
            return False
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0:
                return False
            i += 6
        return True

    primality = is_prime(factor)

    # Combine all mathematical properties to determine key type
    # Instead of explicitly labeling "A" or "B", we use a numerical score
    # based on the mathematical properties

    # Calculate a score based on all properties
    # This score will determine which dataset to decrypt
    score = 0

    # Factor-based properties
    score += (remainder_2 * 5)
    score += (remainder_3 * 3)
    score += (remainder_4 * 7)
    score += (1 if square_property else 0) * 13
    score += digital_root * 11
    score += (digit_sum % 10) * 17
    score += (1 if primality else 0) * 19

    # Vector-based properties
    if vector_pattern == "even_even":
        score += 23
    elif vector_pattern == "odd_odd":
        score += 29
    elif vector_pattern == "mixed":
        score += 31

    # Fibonacci-based properties
    if fibonacci_pattern == "valid":
        score += 37
    elif fibonacci_pattern == "invalid":
        score += 41

    # Elliptic curve properties
    if ec_property == "valid":
        score += 43
    elif ec_property == "invalid":
        score += 47

    # The key type is determined by whether the final score is odd or even
    key_type = "data1" if score % 2 == 1 else "data2"

    # Prepare the result
    result = {
        "factor": factor,
        "mathematical_properties": {
            "remainder_mod_2": remainder_2,
            "remainder_mod_3": remainder_3,
            "remainder_mod_4": remainder_4,
            "is_perfect_square": square_property,
            "vector_pattern": vector_pattern,
            "fibonacci_pattern": fibonacci_pattern,
            "elliptic_curve_property": ec_property,
            "digital_root": digital_root,
            "digit_sum": digit_sum,
            "is_prime": primality
        },
        "mathematical_score": score,
        "determined_key_type": key_type
    }

    return result

def decrypt_data(encrypted_data: bytes, key_params: Dict[str, Any]) -> bytes:
    """
    Decrypt data that was encrypted using the improved homomorphic encryption

    Args:
        encrypted_data: The encrypted data
        key_params: Key parameters for decryption

    Returns:
        The decrypted data
    """
    # Parse the encrypted data
    try:
        encrypted_json = json.loads(encrypted_data)
    except json.JSONDecodeError:
        raise ValueError("Invalid encrypted data: not valid JSON")

    # Check the format
    format_version = encrypted_json.get("format", "")
    if not format_version.startswith("homomorphic_masked"):
        raise ValueError(f"Unsupported encryption format: {format_version}")

    # Get the chunk size
    chunk_size = encrypted_json.get("chunk_size", 0)
    if chunk_size <= 0:
        raise ValueError("Invalid chunk size in encrypted data")

    # Get the public key from the encrypted data
    pubkey_n = int(encrypted_json.get("public_key", {}).get("n", "0"))
    pubkey_g = int(encrypted_json.get("public_key", {}).get("g", "0"))

    if pubkey_n == 0 or pubkey_g == 0:
        raise ValueError("Invalid public key in encrypted data")

    # Get private key from the key parameters
    private_key = key_params.get("parameters", {}).get("private_key", {})
    if not private_key:
        raise ValueError("Private key not found in key parameters")

    lambda_n = private_key.get("lambda", 0)
    mu = private_key.get("mu", 0)

    if lambda_n == 0 or mu == 0:
        raise ValueError("Invalid private key parameters")

    # Initialize the Paillier cryptosystem
    paillier = PaillierCryptosystem()
    paillier.public_key = {"n": pubkey_n, "g": pubkey_g}
    paillier.private_key = {"lambda": lambda_n, "mu": mu}

    # Determine which dataset to decrypt based on mathematical properties
    # This replaces the explicit dataset type identifier
    analysis = analyze_key_mathematical_properties(key_params)
    key_type = analysis.get("determined_key_type")

    print(f"Key analysis determined mathematical properties: score={analysis['mathematical_score']}")

    # Get the encrypted chunks
    chunks = encrypted_json.get("chunks", [])
    if not chunks:
        raise ValueError("No encrypted chunks found")

    # Sort chunks by index to ensure correct order
    chunks.sort(key=lambda x: x.get("index", 0))

    # Decrypt each chunk
    decrypted_chunks = []

    print(f"Decrypting data using mathematically determined key type: {key_type}")
    print(f"Decrypting {len(chunks)} chunks...")

    for i, chunk in enumerate(chunks):
        if i % 10 == 0:
            print(f"Processing chunk {i+1}/{len(chunks)}...")

        # Get the encrypted values
        ciphertext_hex = chunk.get("ciphertext", "")
        diff_mask_hex = chunk.get("diff_mask", "")

        if not ciphertext_hex or not diff_mask_hex:
            raise ValueError(f"Invalid chunk data at index {i}")

        # Convert from hex to integers
        ciphertext = int(ciphertext_hex, 16)
        diff_mask = int(diff_mask_hex, 16)

        # Decrypt based on the key type
        if key_type == "data1":
            # Directly decrypt the ciphertext
            plaintext = paillier.decrypt(ciphertext)
        else:  # key_type == "data2"
            # Apply the mask before decrypting
            # E(m2) = E(m1) * E(m2-m1)
            combined = paillier.homomorphic_add(ciphertext, diff_mask)
            plaintext = paillier.decrypt(combined)

        # Convert integer to bytes
        plaintext_bytes = plaintext.to_bytes(
            (plaintext.bit_length() + 7) // 8, 'big'
        )

        # Ensure the chunk has the correct size
        # We need to either truncate or pad
        if len(plaintext_bytes) > chunk_size:
            plaintext_bytes = plaintext_bytes[:chunk_size]
        elif len(plaintext_bytes) < chunk_size:
            plaintext_bytes = plaintext_bytes.rjust(chunk_size, b'\x00')

        decrypted_chunks.append(plaintext_bytes)

    # Combine all chunks
    decrypted_data = b''.join(decrypted_chunks)

    # Truncate to the original size
    original_size_key = "original_size_1" if key_type == "data1" else "original_size_2"
    original_size = encrypted_json.get(original_size_key, len(decrypted_data))

    return decrypted_data[:original_size]

def decrypt_file(encrypted_file_path: str, key_file_path: str, output_path: str = None) -> Dict[str, Any]:
    """
    Decrypt a file that was encrypted using the improved homomorphic encryption

    Args:
        encrypted_file_path: Path to the encrypted file
        key_file_path: Path to the key file
        output_path: Path to save the decrypted file (auto-generated if None)

    Returns:
        Dictionary with information about the decryption process
    """
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    # Read the key file
    with open(key_file_path, 'r') as f:
        key_params = json.load(f)

    # Analyze the key mathematically
    key_analysis = analyze_key_mathematical_properties(key_params)

    print(f"Encrypted file: {encrypted_file_path} ({len(encrypted_data)} bytes)")
    print(f"Key file: {key_file_path}")
    print(f"Key type determined by mathematical analysis: {key_analysis['determined_key_type']}")

    # Decrypt the data
    print("\nDecrypting data...")
    start_time = time.time()
    decrypted_data = decrypt_data(encrypted_data, key_params)
    decryption_time = time.time() - start_time
    print(f"Decryption completed in {decryption_time:.2f} seconds")

    # Determine output path if not specified
    if output_path is None:
        key_type = key_analysis['determined_key_type']
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.sha256(encrypted_file_path.encode()).hexdigest()[:8]
        output_path = f"decrypted_{key_type}_{timestamp}_{file_hash}"

    # Save the decrypted data
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decrypted file saved to: {output_path} ({len(decrypted_data)} bytes)")

    # Prepare result information
    result = {
        "encrypted_file": encrypted_file_path,
        "key_file": key_file_path,
        "decrypted_file": output_path,
        "decrypted_size": len(decrypted_data),
        "decryption_time": decryption_time,
        "key_type": key_analysis['determined_key_type'],
        "key_analysis": key_analysis,
        "timestamp": int(time.time())
    }

    return result

def main():
    """
    Main function to handle command-line arguments and execute decryption
    """
    # Display system information
    import platform
    print(f"Python version: {platform.python_version()}")
    print(f"Platform: {platform.system()} {platform.release()}")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Improved Homomorphic Encryption Decryption",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("encrypted_file", help="Encrypted file to decrypt")
    parser.add_argument("key_file", help="Key file to use for decryption")
    parser.add_argument("--output", "-o", help="Output file path (auto-generated if not specified)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Display verbose key analysis")
    parser.add_argument("--stats", "-s", action="store_true",
                        help="Display detailed statistics")

    args = parser.parse_args()

    # Check if the input files exist
    if not os.path.exists(args.encrypted_file):
        print(f"Error: File '{args.encrypted_file}' not found")
        return 1

    if not os.path.exists(args.key_file):
        print(f"Error: File '{args.key_file}' not found")
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

        # Execute decryption
        print("\nStarting decryption...")
        result = decrypt_file(
            args.encrypted_file,
            args.key_file,
            args.output
        )

        # Calculate total execution time
        elapsed_time = time.time() - start_time

        print(f"\nDecryption completed (Total time: {elapsed_time:.2f} seconds)")

        # Display verbose key analysis if requested
        if args.verbose:
            print("\nDetailed mathematical key analysis:")
            for k, v in result["key_analysis"]["mathematical_properties"].items():
                print(f"  {k}: {v}")
            print(f"Mathematical score: {result['key_analysis']['mathematical_score']}")

        # Display detailed statistics if requested
        if args.stats:
            print("\nDetailed stats:")
            print(f"Encrypted file size: {os.path.getsize(args.encrypted_file):,} bytes")
            print(f"Decrypted file size: {result['decrypted_size']:,} bytes")
            print(f"Decryption rate: {result['decrypted_size'] / max(1, result['decryption_time']):,.2f} bytes/sec")

        return 0

    except Exception as e:
        import traceback
        print(f"Error: An error occurred during decryption: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())