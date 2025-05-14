#!/usr/bin/env python3

import random
import math
import json
import os
import base64
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional, Any, Union

import sympy

from method_8_homomorphic.homomorphic import (
    PaillierCrypto,
    ElGamalCrypto,
    mod_inverse,
    save_keys,
    load_keys,
    derive_key_from_password,
    serialize_encrypted_data,
    deserialize_encrypted_data
)

# 定数
PAILLIER_KEY_BITS = 2048  # Paillier暗号の鍵ビット長（デフォルト）
ELGAMAL_KEY_BITS = 2048   # ElGamal暗号の鍵ビット長（デフォルト）