#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式 - 改良版鍵生成機能

明示的な識別子を使わず、数学的特性のみによって鍵を区別する実装
"""

import os
import sys
import json
import base64
import hashlib
import time
import random
import binascii
import math
import sympy
from typing import Dict, List, Tuple, Union, Any

# セキュリティパラメータ
KEY_SIZE_BYTES = 32
PAILLIER_KEY_BITS = 1024

class PaillierCryptosystem:
    """Paillier準同型暗号システム（簡略版）"""

    def __init__(self, key_size=PAILLIER_KEY_BITS):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self._p = None
        self._q = None

    def generate_keypair(self):
        """鍵ペアを生成"""
        # 2つの大きな素数p, qを生成
        self._p = sympy.randprime(2**(self.key_size//2-1), 2**(self.key_size//2))
        self._q = sympy.randprime(2**(self.key_size//2-1), 2**(self.key_size//2))

        # n = p * q
        n = self._p * self._q
        n_squared = n * n

        # λ(n) = lcm(p-1, q-1)
        lambda_n = self._lcm(self._p - 1, self._q - 1)

        # g = n + 1 (簡易化した生成子)
        g = n + 1

        # μ = L(g^λ mod n^2)^(-1) mod n
        g_lambda = pow(g, lambda_n, n_squared)
        L_g_lambda = (g_lambda - 1) // n
        mu = self._mod_inverse(L_g_lambda, n)

        # 公開鍵と秘密鍵の設定
        self.public_key = {"n": n, "g": g}
        self.private_key = {"lambda": lambda_n, "mu": mu}

        return self.public_key, self.private_key

    def get_p(self) -> int:
        """素因数pを取得"""
        if self._p is None:
            raise ValueError("鍵ペアがまだ生成されていません")
        return self._p

    def get_q(self) -> int:
        """素因数qを取得"""
        if self._q is None:
            raise ValueError("鍵ペアがまだ生成されていません")
        return self._q

    def _lcm(self, a, b):
        """最小公倍数を計算"""
        return a * b // math.gcd(a, b)

    def _mod_inverse(self, a, m):
        """mod mでのaの逆元を計算"""
        return pow(a, -1, m)

def generate_fibonacci_sequence(seed_val, length=5):
    """
    シード値からフィボナッチ数列を生成
    数学的特性による暗黙的な識別に利用
    """
    rng = random.Random(seed_val)
    start = rng.randint(1, 100)
    a, b = start, start + rng.randint(1, 10)
    seq = [a, b]
    for _ in range(length - 2):
        a, b = b, a + b
        seq.append(b)
    return seq

def generate_elliptic_curve_point(seed_val):
    """
    シード値から楕円曲線上の点を生成
    異なる鍵の生成に数学的多様性を提供
    """
    rng = random.Random(seed_val)
    a = rng.randint(1, 100)
    b = rng.randint(1, 100)
    x = rng.randint(1, 1000)
    # y^2 = x^3 + ax + b の曲線上の点を生成
    y_squared = (x**3 + a*x + b) % 10000
    # 平方根の近似値（実際の楕円曲線計算ではないが、数学的特性として十分）
    y = int(math.sqrt(y_squared))
    return {"a": a, "b": b, "x": x, "y": y}

def generate_improved_key_parameters(master_seed: bytes = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    改良版：準同型暗号鍵パラメータのペアを生成

    明示的な識別子を使用せず、数学的特性に基づいて暗黙的に区別できる鍵ペアを生成

    Args:
        master_seed: マスターシード

    Returns:
        2つの異なる鍵パラメータ
    """
    if master_seed is None:
        master_seed = os.urandom(KEY_SIZE_BYTES)

    # マスターシードからハッシュ値を生成
    seed_hash = hashlib.sha512(master_seed).digest()
    random.seed(int.from_bytes(seed_hash[:8], byteorder='big'))

    # Paillier暗号システムの初期化と鍵生成
    paillier = PaillierCryptosystem(key_size=PAILLIER_KEY_BITS)
    paillier.generate_keypair()

    # 共通の公開鍵と秘密鍵
    public_key = {
        "n": paillier.public_key["n"],
        "g": paillier.public_key["g"]
    }
    private_key = {
        "lambda": paillier.private_key["lambda"],
        "mu": paillier.private_key["mu"]
    }

    # 素因数を取得
    p_value = paillier.get_p()
    q_value = paillier.get_q()

    # 個別のシード値を生成（素因数に基づく）
    seed_1 = hashlib.sha256(str(p_value).encode() + master_seed).digest()
    seed_2 = hashlib.sha256(str(q_value).encode() + master_seed).digest()

    # 乱数生成器の初期化
    rng_1 = random.Random(int.from_bytes(seed_1[:8], 'big'))
    rng_2 = random.Random(int.from_bytes(seed_2[:8], 'big'))

    # 時間ベースの共通エントロピー値（識別子を含まない）
    time_entropy = f"{time.time()}:{os.urandom(8).hex()}"

    # 動的パス生成（数値のみを使用）
    def generate_path(rng):
        """乱数生成器から導出経路を生成（数値のみ）"""
        segments = [rng.randint(0, 99) for _ in range(5)]
        return f"m/{segments[0]}/{segments[1]}/{segments[2]}/{segments[3]}/{segments[4]}"

    # 楕円曲線パラメータ
    ec_point_1 = generate_elliptic_curve_point(int.from_bytes(seed_1[:4], 'big'))
    ec_point_2 = generate_elliptic_curve_point(int.from_bytes(seed_2[:4], 'big'))

    # フィボナッチ数列
    fib_seq_1 = generate_fibonacci_sequence(int.from_bytes(seed_1[4:8], 'big'))
    fib_seq_2 = generate_fibonacci_sequence(int.from_bytes(seed_2[4:8], 'big'))

    # 座標生成（両方とも類似する範囲内だが、値は異なる）
    def generate_coords(rng, base_val):
        """座標値を生成"""
        return {
            "x": (base_val % 1000) + rng.randint(500, 700),
            "y": (base_val * rng.randint(30, 40)) % 2000,
            "z": rng.randint(1000, 3000)
        }

    # ハッシュチェーン生成（明示的識別なし）
    def generate_hash_chain(seed_bytes):
        """シード値からハッシュチェーンを生成"""
        h1 = hashlib.sha256(seed_bytes).digest()
        h2 = hashlib.sha256(h1).digest()
        h3 = hashlib.sha256(h2).digest()
        return hashlib.sha256(h1 + h2 + h3).hexdigest()

    # 数学的行列式
    matrix_det_1 = rng_1.randint(10, 99)  # 明示的な識別子を避ける
    matrix_det_2 = rng_2.randint(10, 99)  # 明示的な識別子を避ける

    # 1つ目の鍵パラメータ
    key_params_1 = {
        "public_key": public_key,
        "private_key": private_key,
        "modulus_component": {
            "prime_factor": p_value,
            "derivation_path": generate_path(rng_1),
            "factor_property": p_value % 100,
            "coordinates": generate_coords(rng_1, p_value),
            "curve_point": ec_point_1
        },
        "cipher_props": {
            "hash_chain": generate_hash_chain(seed_1),
            "vector": fib_seq_1,
            "matrix_determinant": matrix_det_1,
            "transform_matrix": [
                [rng_1.randint(1, 10), rng_1.randint(1, 10)],
                [rng_1.randint(1, 10), rng_1.randint(1, 10)]
            ]
        },
        "entropy": time_entropy  # 両方の鍵で同じエントロピー値
    }

    # 2つ目の鍵パラメータ
    key_params_2 = {
        "public_key": public_key,
        "private_key": private_key,
        "modulus_component": {
            "prime_factor": q_value,
            "derivation_path": generate_path(rng_2),
            "factor_property": q_value % 100,
            "coordinates": generate_coords(rng_2, q_value),
            "curve_point": ec_point_2
        },
        "cipher_props": {
            "hash_chain": generate_hash_chain(seed_2),
            "vector": fib_seq_2,
            "matrix_determinant": matrix_det_2,
            "transform_matrix": [
                [rng_2.randint(1, 10), rng_2.randint(1, 10)],
                [rng_2.randint(1, 10), rng_2.randint(1, 10)]
            ]
        },
        "entropy": time_entropy  # 両方の鍵で同じエントロピー値
    }

    return key_params_1, key_params_2

def save_key_parameters(key_params_1, key_params_2, output_dir="keys"):
    """
    生成された鍵パラメータを保存

    両方の鍵ファイル名とパラメータに識別子を使わない設計
    ファイル名は生成時刻とUUIDで区別
    """
    # 出力ディレクトリの作成
    os.makedirs(output_dir, exist_ok=True)

    # 共通のタイムスタンプ
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    # 一意のUUID
    uuid_1 = binascii.hexlify(os.urandom(4)).decode()
    uuid_2 = binascii.hexlify(os.urandom(4)).decode()

    # 非識別的なファイル名
    key_file_1 = f"{output_dir}/key_params_{timestamp}_{uuid_1}.json"
    key_file_2 = f"{output_dir}/key_params_{timestamp}_{uuid_2}.json"

    # 鍵パラメータの保存
    with open(key_file_1, 'w') as f:
        json.dump(key_params_1, f, indent=2, default=str)

    with open(key_file_2, 'w') as f:
        json.dump(key_params_2, f, indent=2, default=str)

    return key_file_1, key_file_2

# テスト用メイン関数
if __name__ == "__main__":
    # ランダムなマスターシードの生成
    master_seed = os.urandom(KEY_SIZE_BYTES)

    print("改良版鍵生成を実行中...")
    key_params_1, key_params_2 = generate_improved_key_parameters(master_seed)

    print("鍵パラメータを保存中...")
    key_file_1, key_file_2 = save_key_parameters(key_params_1, key_params_2)

    print(f"鍵ファイル1: {key_file_1}")
    print(f"鍵ファイル2: {key_file_2}")

    print("\n鍵1とファイル1の特性:")
    print(f"Entropy: {key_params_1['entropy']}")
    print(f"Matrix determinant: {key_params_1['cipher_props']['matrix_determinant']}")
    print(f"Vector (Fibonacci): {key_params_1['cipher_props']['vector']}")

    print("\n鍵2とファイル2の特性:")
    print(f"Entropy: {key_params_2['entropy']}")
    print(f"Matrix determinant: {key_params_2['cipher_props']['matrix_determinant']}")
    print(f"Vector (Fibonacci): {key_params_2['cipher_props']['vector']}")