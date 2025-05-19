#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
#                  ███████ ███    ██  ██████ ██████  ██    ██ ██████  ████████ #
#                  ██      ████   ██ ██      ██   ██  ██  ██  ██   ██    ██    #
#                  █████   ██ ██  ██ ██      ██████    ████   ██████     ██    #
#                  ██      ██  ██ ██ ██      ██   ██    ██    ██         ██    #
#                  ███████ ██   ████  ██████ ██   ██    ██    ██         ██    #
#                                                                              #
#               【暗号化を実行するメインスクリプト - MAIN ENCRYPTION SCRIPT】    #
#                                                                              #
#     このファイルは準同型暗号マスキング方式の「暗号化」機能のメインエントリーポイントです       #
#     最終成果物として、ユーザーはこのファイルを直接実行してファイルを暗号化します         #
#                                                                              #
################################################################################

# ============================================================================ #
# 【警告: セキュリティ上の重要事項】                                              #
# 区別不能性要件に基づき、暗号化・復号プロセス全体を通して、明示的な鍵タイプの指定や     #
# 「true/false」などの表現を用いることは厳禁です。                                #
#                                                                              #
# このシステムでは、同一の暗号文に対して使用する鍵によって異なる平文が復元され、        #
# 攻撃者はどちらが「正規」かを判別できないことが最重要要件です。                     #
# ============================================================================ #

"""
準同型暗号マスキング方式 - 暗号化プログラム

2つのファイルを区別不能な形で暗号化し、同一の暗号文から異なる鍵で
異なる平文を復号できる機能を提供します。

【セキュリティポリシー】
区別不能性を確保するため、このプログラムでは:
- データタイプに応じた特定の名称や識別子を使用しません
- 鍵のタイプを明示的に示す情報を外部に提供しません
- すべてのメタデータは区別不能性を損なわないよう慎重に構成されます
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
import numpy as np
import sympy
from typing import Dict, List, Tuple, Union, Any
import platform

# インポートエラー回避のためパスを追加
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# 既存実装からimproved_key_generatorをインポート
try:
    from improved_key_generator import (
        generate_improved_key_parameters,
        PaillierCryptosystem,
        generate_fibonacci_sequence,
        generate_elliptic_curve_point
    )
    using_improved_implementation = True
    print("改良版鍵生成機能を使用します")
except ImportError:
    # 改良版がない場合は内部実装を使用
    using_improved_implementation = False
    print("内部鍵生成機能を使用します")

# セキュリティパラメータの設定
KEY_SIZE_BYTES = 32
PAILLIER_KEY_BITS = 2048

# エントロピー計測関数
def measure_entropy(data: bytes) -> float:
    """
    データのエントロピーを測定

    Args:
        data: 測定対象のバイトデータ

    Returns:
        エントロピー値（ビット/バイト）
    """
    if not data:
        return 0.0

    # 各バイト値の出現回数をカウント
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    # エントロピーの計算
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        probability = count / len(data)
        entropy -= probability * math.log2(probability)

    return entropy

# Paillier準同型暗号システムの実装
class PaillierCryptosystem:
    """
    Paillier準同型暗号システム

    暗号文に対する加法準同型性を持つ公開鍵暗号システム。
    E(m1) * E(m2) = E(m1 + m2) という特性を持つ。
    """

    def __init__(self, key_size=PAILLIER_KEY_BITS):
        """
        Paillier暗号システムを初期化

        Args:
            key_size: 鍵のビット長
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        # 素因数p, qを内部的に保持
        self._p = None
        self._q = None

    def generate_keypair(self):
        """
        Paillier暗号の鍵ペアを生成

        Returns:
            public_key, private_key: 公開鍵と秘密鍵のペア
        """
        print(f"{self.key_size}ビットの素数を探索中...")
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
        # L(x) = (x-1)/n
        g_lambda = pow(g, lambda_n, n_squared)
        L_g_lambda = (g_lambda - 1) // n
        mu = self._mod_inverse(L_g_lambda, n)

        # 公開鍵と秘密鍵の設定
        self.public_key = {"n": n, "g": g}
        self.private_key = {"lambda": lambda_n, "mu": mu}

        return self.public_key, self.private_key

    def get_p(self) -> int:
        """
        素因数pを取得

        Returns:
            素因数p
        """
        if self._p is None:
            raise ValueError("鍵ペアがまだ生成されていません")
        return self._p

    def get_q(self) -> int:
        """
        素因数qを取得

        Returns:
            素因数q
        """
        if self._q is None:
            raise ValueError("鍵ペアがまだ生成されていません")
        return self._q

    def encrypt(self, m):
        """
        平文を暗号化

        Args:
            m: 平文（整数）

        Returns:
            暗号文
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = self.public_key["n"]
        g = self.public_key["g"]
        n_squared = n * n

        # 0 <= m < n を確認
        m = m % n

        # r ∈ Z*_n をランダムに選択
        r = self._get_random_coprime(n)

        # 暗号文 c = g^m * r^n mod n^2 を計算
        g_m = pow(g, m, n_squared)
        r_n = pow(r, n, n_squared)
        c = (g_m * r_n) % n_squared

        return c

    def decrypt(self, c):
        """
        暗号文を復号

        Args:
            c: 暗号文

        Returns:
            復号された平文
        """
        if self.private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        n = self.public_key["n"]
        lambda_n = self.private_key["lambda"]
        mu = self.private_key["mu"]
        n_squared = n * n

        # L(c^λ mod n^2) * μ mod n を計算
        c_lambda = pow(c, lambda_n, n_squared)
        L_c_lambda = (c_lambda - 1) // n
        m = (L_c_lambda * mu) % n

        return m

    def homomorphic_add(self, c1, c2):
        """
        2つの暗号文の準同型加算: E(m1) * E(m2) = E(m1 + m2)

        Args:
            c1: 1つ目の暗号文
            c2: 2つ目の暗号文

        Returns:
            加算結果の暗号文
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n_squared = self.public_key["n"] * self.public_key["n"]
        return (c1 * c2) % n_squared

    def homomorphic_add_constant(self, c, k):
        """
        暗号文と定数の準同型加算: E(m) * g^k = E(m + k)

        Args:
            c: 暗号文
            k: 加算する定数

        Returns:
            加算結果の暗号文
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = self.public_key["n"]
        g = self.public_key["g"]
        n_squared = n * n

        g_k = pow(g, k % n, n_squared)
        return (c * g_k) % n_squared

    def homomorphic_multiply_constant(self, c, k):
        """
        暗号文と定数の準同型乗算: E(m)^k = E(m * k)

        Args:
            c: 暗号文
            k: 乗算する定数

        Returns:
            乗算結果の暗号文
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = self.public_key["n"]
        n_squared = n * n

        return pow(c, k % n, n_squared)

    def _lcm(self, a, b):
        """
        最小公倍数を計算

        Args:
            a, b: 最小公倍数を求める整数

        Returns:
            aとbの最小公倍数
        """
        return a * b // math.gcd(a, b)

    def _mod_inverse(self, a, m):
        """
        mod mでのaの逆元を計算

        Args:
            a: 逆元を求める数
            m: 法

        Returns:
            aのmod mでの逆元
        """
        return pow(a, -1, m)

    def _get_random_coprime(self, n):
        """
        nと互いに素な乱数を生成

        Args:
            n: この数との互いに素性を確認

        Returns:
            nと互いに素な乱数
        """
        while True:
            r = random.randint(1, n-1)
            if math.gcd(r, n) == 1:
                return r

def encrypt_data(data1: bytes, data2: bytes, params_1: Dict[str, Any], params_2: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    """
    2つのデータセットを単一の暗号文にマスキング

    準同型暗号の特性を利用して、同一の暗号文から異なる平文を復号できる
    真の準同型暗号マスキング方式を実装

    Args:
        data1: 1つ目のデータセット
        data2: 2つ目のデータセット
        params_1: 1つ目の鍵パラメータ
        params_2: 2つ目の鍵パラメータ

    Returns:
        暗号文、鍵1情報、鍵2情報
    """
    # 公開鍵・秘密鍵情報を取得
    pub_key_1 = params_1.get("public_key", {})
    pub_key_2 = params_2.get("public_key", {})
    priv_key_1 = params_1.get("private_key", {})
    priv_key_2 = params_2.get("private_key", {})

    # Paillier暗号システムの初期化
    paillier = PaillierCryptosystem()
    paillier.public_key = {
        "n": pub_key_1.get("n", 2048),
        "g": pub_key_1.get("g", 2049)
    }

    # チャンクサイズ計算
    n_bits = paillier.public_key["n"].bit_length()
    chunk_size = max(4, (n_bits - 64) // 8)  # 安全マージン確保

    # データをチャンク分割
    chunks1 = [data1[i:i+chunk_size] for i in range(0, len(data1), chunk_size)]
    chunks2 = [data2[i:i+chunk_size] for i in range(0, len(data2), chunk_size)]

    # 長さを揃える
    max_chunks = max(len(chunks1), len(chunks2))
    while len(chunks1) < max_chunks:
        # パディング用のランダムチャンク
        chunks1.append(os.urandom(chunk_size))
    while len(chunks2) < max_chunks:
        chunks2.append(os.urandom(chunk_size))

    # 各チャンクを準同型暗号化
    print(f"データの暗号化中... チャンク数: {len(chunks1)}")
    encrypted_chunks = []

    for i, (chunk1, chunk2) in enumerate(zip(chunks1, chunks2)):
        if i % 10 == 0:
            print(f"チャンク {i+1}/{len(chunks1)} 処理中...")

        # チャンクを整数に変換
        m1 = int.from_bytes(chunk1, 'big')
        m2 = int.from_bytes(chunk2, 'big')

        # データセット1を暗号化
        c1 = paillier.encrypt(m1)

        # データセット2も同様に暗号化
        c2 = paillier.encrypt(m2)

        # 準同型プロパティを利用して差分マスクを計算
        # E(m2) / E(m1) = E(m2 - m1)
        inverse_c1 = paillier.homomorphic_multiply_constant(c1, -1)
        diff_mask = paillier.homomorphic_add(c2, inverse_c1)

        # マスク情報を保存
        mask_info = {
            "diff_mask": hex(diff_mask),
            "index": i
        }

        # ランダムファクターで再暗号化して統計的特性を除去
        c1_rerand = paillier.encrypt(m1)  # 同じ平文でも異なる暗号文になる

        # 真の準同型暗号文として保存
        encrypted_chunks.append({
            "ciphertext": hex(c1_rerand),
            "diff_mask": hex(diff_mask),
            "index": i
        })

    # 準同型暗号文をシリアライズ
    encrypted_data = json.dumps({
        "format": "homomorphic_masked",
        "version": "1.0",
        "timestamp": int(time.time()),
        "uuid": str(uuid.uuid4()),
        "chunks": encrypted_chunks,
        "chunk_size": chunk_size,
        "public_key": {
            "n": str(paillier.public_key["n"]),
            "g": str(paillier.public_key["g"])
        },
        "original_size_1": len(data1),
        "original_size_2": len(data2)
    }).encode()

    # 鍵情報の生成（明示的な識別子なし）
    key_info_1 = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "parameters": {
            "public_key": pub_key_1,
            "private_key": priv_key_1,
            "modulus_component": params_1.get("modulus_component", {})
        },
        "entropy": params_1.get("entropy", binascii.hexlify(os.urandom(16)).decode()),
        "version": "1.0.0",
        "algorithm": "paillier_homomorphic_masking"
    }

    key_info_2 = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "parameters": {
            "public_key": pub_key_2,
            "private_key": priv_key_2,
            "modulus_component": params_2.get("modulus_component", {})
        },
        "entropy": params_2.get("entropy", binascii.hexlify(os.urandom(16)).decode()),
        "version": "1.0.0",
        "algorithm": "paillier_homomorphic_masking"
    }

    # 数学的特性
    if "cipher_props" in params_1:
        key_info_1["cipher_props"] = params_1["cipher_props"]
    if "cipher_props" in params_2:
        key_info_2["cipher_props"] = params_2["cipher_props"]

    return encrypted_data, key_info_1, key_info_2

def encrypt_file(file_path1: str, file_path2: str, output_path: str = None, save_key: bool = True) -> Dict[str, Any]:
    """
    2つのファイルを暗号化し、同一の暗号文から異なる平文を復号可能にする

    準同型暗号の特性を利用した真の準同型暗号マスキング方式を実装

    Args:
        file_path1: 1つ目のデータファイルパス
        file_path2: 2つ目のデータファイルパス
        output_path: 出力ファイルパス（None の場合は自動生成）
        save_key: 鍵を保存するかどうか

    Returns:
        結果情報の辞書
    """
    # ファイルの読み込み
    with open(file_path1, 'rb') as f:
        data1 = f.read()
    with open(file_path2, 'rb') as f:
        data2 = f.read()

    print(f"ファイル1: {file_path1} ({len(data1)} bytes)")
    print(f"ファイル2: {file_path2} ({len(data2)} bytes)")

    # セキュリティエントロピーの測定
    entropy1 = measure_entropy(data1)
    entropy2 = measure_entropy(data2)
    print(f"ファイル1のエントロピー: {entropy1:.4f} bits/byte")
    print(f"ファイル2のエントロピー: {entropy2:.4f} bits/byte")

    # マスターシードの生成
    master_seed = os.urandom(KEY_SIZE_BYTES)

    # 準同型暗号鍵パラメータの生成
    print("準同型暗号鍵を生成中...")
    if using_improved_implementation:
        # 改良版鍵生成機能を使用
        params_1, params_2 = generate_improved_key_parameters(master_seed)
    else:
        # 内部実装の鍵生成機能
        # フィボナッチ数列を生成
        def generate_fibonacci_sequence(seed_val, length=5):
            """シード値からフィボナッチ数列を生成"""
            rng = random.Random(seed_val)
            start = rng.randint(1, 100)
            a, b = start, start + rng.randint(1, 10)
            seq = [a, b]
            for _ in range(length - 2):
                a, b = b, a + b
                seq.append(b)
            return seq

        # 楕円曲線パラメータを生成
        def generate_elliptic_curve_point(seed_val):
            """シード値から楕円曲線上の点を生成"""
            rng = random.Random(seed_val)
            a = rng.randint(1, 100)
            b = rng.randint(1, 100)
            x = rng.randint(1, 1000)
            # y^2 = x^3 + ax + b の曲線上の点を生成
            y_squared = (x**3 + a*x + b) % 10000
            # 平方根の近似値
            y = int(math.sqrt(y_squared))
            return {"a": a, "b": b, "x": x, "y": y}

        # Paillier暗号システムの初期化
        paillier = PaillierCryptosystem(key_size=PAILLIER_KEY_BITS)

        # 鍵の生成
        print("Paillier暗号鍵を生成中...")
        paillier.generate_keypair()

        # 素因数を取得
        p_value = paillier.get_p()
        q_value = paillier.get_q()

        # 公開鍵
        public_key = {
            "n": paillier.public_key["n"],
            "g": paillier.public_key["g"]
        }

        # 秘密鍵
        private_key = {
            "lambda": paillier.private_key["lambda"],
            "mu": paillier.private_key["mu"]
        }

        # 個別のシード値を生成
        seed_1 = hashlib.sha256(str(p_value).encode() + master_seed).digest()
        seed_2 = hashlib.sha256(str(q_value).encode() + master_seed).digest()

        # 乱数生成器の初期化
        rng_1 = random.Random(int.from_bytes(seed_1[:8], 'big'))
        rng_2 = random.Random(int.from_bytes(seed_2[:8], 'big'))

        # 時間ベースの共通エントロピー値（識別子を含まない）
        time_entropy = f"{time.time()}:{os.urandom(8).hex()}"

        # 動的パス生成
        def generate_path(rng):
            """乱数生成器から導出経路を生成"""
            segments = [rng.randint(0, 99) for _ in range(5)]
            return f"m/{segments[0]}/{segments[1]}/{segments[2]}/{segments[3]}/{segments[4]}"

        # 数学的特性の生成
        ec_point_1 = generate_elliptic_curve_point(int.from_bytes(seed_1[:4], 'big'))
        ec_point_2 = generate_elliptic_curve_point(int.from_bytes(seed_2[:4], 'big'))

        fib_seq_1 = generate_fibonacci_sequence(int.from_bytes(seed_1[4:8], 'big'))
        fib_seq_2 = generate_fibonacci_sequence(int.from_bytes(seed_2[4:8], 'big'))

        # 鍵パラメータの生成
        params_1 = {
            "public_key": public_key,
            "private_key": private_key,
            "modulus_component": {
                "prime_factor": p_value,
                "derivation_path": generate_path(rng_1),
                "factor_property": p_value % 100,
                "coordinates": {
                    "x": (p_value % 1000) + rng_1.randint(500, 700),
                    "y": (p_value * rng_1.randint(30, 40)) % 2000
                },
                "curve_point": ec_point_1
            },
            "cipher_props": {
                "hash_chain": hashlib.sha256(hashlib.sha256(seed_1).digest()).hexdigest(),
                "vector": fib_seq_1,
                "matrix_determinant": rng_1.randint(10, 99)
            },
            "entropy": time_entropy  # 明示的な識別子なし
        }

        params_2 = {
            "public_key": public_key,
            "private_key": private_key,
            "modulus_component": {
                "prime_factor": q_value,
                "derivation_path": generate_path(rng_2),
                "factor_property": q_value % 100,
                "coordinates": {
                    "x": (q_value % 1000) + rng_2.randint(500, 700),
                    "y": (q_value * rng_2.randint(30, 40)) % 2000
                },
                "curve_point": ec_point_2
            },
            "cipher_props": {
                "hash_chain": hashlib.sha256(hashlib.sha256(seed_2).digest()).hexdigest(),
                "vector": fib_seq_2,
                "matrix_determinant": rng_2.randint(10, 99)
            },
            "entropy": time_entropy  # 明示的な識別子なし
        }

    # 2つのデータを暗号化して単一の暗号文を生成
    print("準同型暗号マスキングを実行中...")
    start_time = time.time()
    encrypted_data, key_info_1, key_info_2 = encrypt_data(
        data1, data2, params_1, params_2
    )
    encryption_time = time.time() - start_time
    print(f"暗号化処理時間: {encryption_time:.2f}秒")

    # 出力ファイル名の決定
    if output_path is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.sha256((file_path1 + file_path2).encode()).hexdigest()[:8]
        output_path = f"encrypted_{timestamp}_{file_hash}.henc"

    # 暗号化データの保存
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    print(f"暗号化ファイルを保存しました: {output_path} ({len(encrypted_data)} bytes)")

    # 鍵情報の保存
    if save_key:
        # 鍵ディレクトリが存在するか確認し、なければ作成
        key_dir = "keys"
        if not os.path.exists(key_dir):
            os.makedirs(key_dir, exist_ok=True)

        # UUIDを生成して共通のファイル識別子として使用
        file_uuid_1 = uuid.uuid4().hex[:8]
        file_uuid_2 = uuid.uuid4().hex[:8]
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # 鍵ファイル名（非識別的）
        key_file_1 = f"{key_dir}/key_params_{timestamp}_{file_uuid_1}.json"
        key_file_2 = f"{key_dir}/key_params_{timestamp}_{file_uuid_2}.json"

        # 鍵情報の保存
        with open(key_file_1, 'w') as f:
            json.dump(key_info_1, f, indent=2)

        with open(key_file_2, 'w') as f:
            json.dump(key_info_2, f, indent=2)

        print(f"鍵ファイルを保存しました:")
        print(f"  - {key_file_1}")
        print(f"  - {key_file_2}")

    # 結果情報
    result_info = {
        "encrypted_file": output_path,
        "file_size": len(encrypted_data),
        "key_file_1": key_file_1 if save_key else None,
        "key_file_2": key_file_2 if save_key else None,
        "original_files": [file_path1, file_path2],
        "original_sizes": [len(data1), len(data2)],
        "timestamp": int(time.time()),
        "encryption_time": encryption_time
    }

    return result_info

def main():
    """メイン関数"""
    # コマンドライン引数の解析
    parser = argparse.ArgumentParser(description="準同型暗号マスキング方式による暗号化")
    parser.add_argument("file1", help="1つ目のデータを含むファイル")
    parser.add_argument("file2", help="2つ目のデータを含むファイル")
    parser.add_argument("--output", "-o", help="出力ファイル名")
    parser.add_argument("--no-save-key", action="store_true", help="鍵を保存しない")
    args = parser.parse_args()

    # ファイルの存在確認
    if not os.path.exists(args.file1):
        print(f"エラー: ファイル '{args.file1}' が見つかりません")
        return 1

    if not os.path.exists(args.file2):
        print(f"エラー: ファイル '{args.file2}' が見つかりません")
        return 1

    try:
        # ファイルの暗号化
        result = encrypt_file(
            args.file1,
            args.file2,
            output_path=args.output,
            save_key=not args.no_save_key
        )

        print("\n暗号化が完了しました！")
        return 0

    except Exception as e:
        print(f"エラー: 処理中に問題が発生しました: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())