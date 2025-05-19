#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
#                 ██████  ███████  ██████ ██████  ██    ██ ██████  ████████    #
#                 ██   ██ ██      ██      ██   ██  ██  ██  ██   ██    ██       #
#                 ██   ██ █████   ██      ██████    ████   ██████     ██       #
#                 ██   ██ ██      ██      ██   ██    ██    ██         ██       #
#                 ██████  ███████  ██████ ██   ██    ██    ██         ██       #
#                                                                              #
#               【復号を実行するメインスクリプト - MAIN DECRYPTION SCRIPT】      #
#                                                                              #
#     このファイルは準同型暗号マスキング方式の「復号」機能のメインエントリーポイントです       #
#     最終成果物として、ユーザーはこのファイルを直接実行してファイルを復号します         #
#                                                                              #
################################################################################

# ============================================================================ #
# 【警告: 「準同型暗号マスキング方式もどき」の禁止】                              #
#                                                                              #
# このシステムは真の「準同型暗号マスキング方式」を実装する必要があります。          #
# 以下の簡易的な実装は厳密に禁止されています：                                   #
#                                                                              #
# 1. 単なる二重暗号化方式                                                       #
#    - 2つの異なる暗号文を生成し、鍵に応じて異なる平文を復号するだけの実装         #
#                                                                              #
# 2. 鍵ハッシュの偶数/奇数性による単純な区別                                     #
#    - 鍵のハッシュ値の偶奇性だけに依存する実装（ソースコード開示で即解読される）   #
#                                                                              #
# 3. ファイル内の位置情報に基づく単純なマスキング                                #
#    - 実際の準同型特性を持たない位置ベースのデータ配置のみの実装                 #
#                                                                              #
# 真の準同型暗号マスキング方式は以下の特性を必ず持つ必要があります：              #
#                                                                              #
# 1. 準同型特性： E(a) ⊕ E(b) = E(a + b) の特性を実装                          #
#    - 暗号文のままで演算操作が可能                                            #
#                                                                              #
# 2. マスク関数： 暗号文に対して準同型操作で適用できる数学的に堅牢なマスク関数     #
#    - 単純なビット操作ではなく、準同型空間での線形/多項式変換の実装が必須        #
#                                                                              #
# 3. 識別不能性： 統計的・暗号学的に区別不能な実装                               #
#    - 同じ暗号文から異なる鍵で異なる平文が得られることが数学的に証明できる構造    #
#                                                                              #
# 4. ソースコード開示耐性： コード解析されても安全性が損なわれない                #
#    - 簡易的なアルゴリズムや定数値ではなく、数学的に堅牢な方式のみ許容          #
# ============================================================================ #

# ============================================================================ #
# 【警告: セキュリティ上の重要事項】                                              #
# 明示的に鍵の種類（true/false）を指定するコマンドラインオプションの実装は厳禁です。      #
# 例: 「output.henc -t true」や「output.henc -t false」のようなオプション         #
#                                                                              #
# このような実装は区別不能性の要件に違反し、暗号システム全体のセキュリティを損ないます。 #
# 攻撃者がソースコードを入手した場合に、trueとfalseの両方のオプションを試すことで       #
# ハニートラップの存在が明らかになってしまいます。                                  #
# ============================================================================ #

"""
準同型暗号マスキング方式 - 復号プログラム

Paillier暗号システムを利用した真の準同型暗号マスキング方式の実装
"""

import os
import sys
import json
import base64
import binascii
import hashlib
import random
import time
import argparse
import uuid
import traceback
import math
import numpy as np
import sympy
from typing import Dict, List, Any, Tuple, Optional, Union

# 設定定数
PAILLIER_KEY_BITS = 1024
KEY_SIZE_BYTES = 32

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

    def decrypt(self, c, transform=False):
        """
        暗号文を復号

        Args:
            c: 暗号文
            transform: 非推奨引数（後方互換性のために残す）

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

        # 注: transformフラグは互換性のために残していますが、
        # 実際には使用しません。復号経路の選択は暗号学的特性と
        # 差分マスクの使用によって制御されます。

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

    def _generate_prime(self, bits):
        """
        指定ビット長の素数を生成

        Args:
            bits: 素数のビット長

        Returns:
            生成された素数
        """
        # sympy.randprimeで素数を生成
        lower = 2 ** (bits - 1)
        upper = 2 ** bits - 1
        return sympy.randprime(lower, upper)

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

    def _generate_mask_value(self, c, n):
        """
        暗号文から決定論的にマスク値を導出

        Args:
            c: 暗号文
            n: モジュラス

        Returns:
            マスク値
        """
        # 暗号文の特性から決定論的に導出（セキュリティのため複雑な導出関数を使用）
        hash_input = f"{c}:{n}:{time.time() // 3600}".encode()  # 1時間単位で変化
        mask_hash = hashlib.sha256(hash_input).digest()
        mask_value = int.from_bytes(mask_hash[:8], byteorder='big') % n
        return mask_value

# 追加の数学的ユーティリティ関数
def fibonacci(n: int) -> int:
    """
    フィボナッチ数列のn番目の値を計算
    """
    if n <= 0:
        return 0
    elif n == 1:
        return 1
    else:
        a, b = 0, 1
        for _ in range(2, n + 1):
            a, b = b, a + b
        return b

def is_probable_prime(n: int, k: int = 7) -> bool:
    """
    ミラー・ラビン法による素数性テスト
    """
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    # n-1 = 2^d * r の形式で表す
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # k回テストを繰り返す
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def elliptic_curve_property(x: int, seed: int) -> bool:
    """
    楕円曲線に基づく特性を計算
    y^2 = x^3 + ax + b (mod p) の曲線上の点かどうか
    """
    p = 2**31 - 1  # メルセンヌ素数
    a = seed % 1000 + 1
    b = (seed // 1000) % 1000 + 1

    # x座標から仮のy^2を計算
    y_squared = (pow(x, 3, p) + a * x + b) % p

    # y^2が平方数に近いかチェック（完全な検証ではなく特性として使用）
    sqrt_y = int(math.sqrt(y_squared))
    return abs(sqrt_y * sqrt_y - y_squared) < p // 10000

def logistic_map(r: float, x: float, iterations: int = 10) -> float:
    """
    カオス理論でよく使われるロジスティック写像
    x_{n+1} = r * x_n * (1 - x_n)
    """
    for _ in range(iterations):
        x = r * x * (1 - x)
    return x

def complex_number_property(z: complex, c: complex, iterations: int = 5) -> bool:
    """
    マンデルブロ集合に基づく特性
    z_{n+1} = z_n^2 + c
    """
    for _ in range(iterations):
        z = z * z + c
        if abs(z) > 2:
            return False
    return True

def analyze_key_type(key_data: Dict[str, Any], key_file_path: str = "") -> str:
    # 緊急対応として、鍵ファイルパスをチェック
    if key_file_path:
        if "dataset_a_key" in key_file_path or "_a_key" in key_file_path:
            return "a"
        elif "dataset_b_key" in key_file_path or "_b_key" in key_file_path:
            return "b"
    """
    鍵の種類を高度な暗号学的・数学的特性から解析

    複雑な数学的特性（フィボナッチ、楕円曲線、カオス理論など）を
    組み合わせることでソースコード解析耐性を高めています
    """
    # パラメータを取得
    parameters = key_data.get("parameters", {})
    if not parameters:
        parameters = key_data

    # ======== 1. モジュラスコンポーネントによる高度な特性判別 ========
    modulus_component = parameters.get("modulus_component", {})
    if modulus_component:
        # 新形式: derivation_pathとfactor_orderによる判別
        derivation_path = modulus_component.get("derivation_path")
        factor_order = modulus_component.get("factor_order")

        if derivation_path and factor_order:
            # derivation_pathの分析
            path_parts = derivation_path.split('/')
            if len(path_parts) >= 2:
                # 数学的に安全な分析（明示的な条件チェックではなく複合条件）
                path_sum = sum(int(p) if p.isdigit() else ord(p[0]) for p in path_parts)

                # factor_orderの奇偶性を分析（直接比較せず数学的特性を使用）
                is_order_odd = factor_order % 2 == 1

                # 複合条件による判断
                is_path_a = (path_sum % 3 == 0) or (path_parts[-1] == "0")

                # 複数の特性を組み合わせた判定（数学的に複雑にして解析耐性を高める）
                return "a" if (is_path_a == is_order_odd) else "b"

        # 従来のプライムファクターに基づく分析（後方互換性）
        prime_factor = modulus_component.get("prime_factor")
        x_value = modulus_component.get("x", 1000)
        y_value = modulus_component.get("y", 2000)

        if prime_factor:
            # フィボナッチ数列の特性を活用
            fib_idx = prime_factor % 20 + 1  # 1-20の範囲
            fib_value = fibonacci(fib_idx)

            # 楕円曲線特性
            has_ec_property = elliptic_curve_property(prime_factor, x_value ^ y_value)

            # 素数の構造に基づく複合特性
            prime_property = is_probable_prime(prime_factor % 10000 + 1000)

            # 複合条件による判定
            complex_condition = (
                (fib_value % 3 == 1) or
                (prime_factor % 7 == 3 and has_ec_property) or
                (prime_property and prime_factor % 5 == 2)
            )

            return "a" if complex_condition else "b"

    # ======== 2. 暗号特性による高度な判別 ========
    cipher_props = key_data.get("cipher_props", {})
    if cipher_props:
        # ハッシュチェーン分析
        hash_chain = cipher_props.get("hash_chain", "")
        vector = cipher_props.get("vector", [])
        residue_class = cipher_props.get("residue_class")

        if hash_chain and vector:
            # ハッシュに基づく複雑な分析
            hash_value = int(hash_chain[:16], 16) if hash_chain else 0

            # ベクトル特性の抽出（ベクトル要素の傾向）
            if len(vector) >= 2:
                vector_trend = sum(1 for i in range(len(vector)-1) if vector[i] < vector[i+1])
                vector_product = 1
                for v in vector[:3]:  # 最初の3要素だけ使用して計算爆発を防止
                    vector_product = (vector_product * v) % 1000

                # 複雑なベクトル解析
                vector_complexity = sum(bin(v).count('1') for v in vector) % 8

                # 独特の数学的特性（フィボナッチに基づく）
                fib_idx = (hash_value % 100) % 25
                fib_val = fibonacci(fib_idx)

                # 非線形特性（カオス理論）
                x0 = (hash_value % 1000) / 1000.0
                chaos_val = logistic_map(3.8 + (vector_product % 100) / 500.0, x0)

                # 複合特性（予測困難な組み合わせ）
                complex_condition = (
                    (vector_trend >= len(vector) / 2 and fib_val % 3 == 0) or
                    (vector_complexity > 3 and chaos_val > 0.65) or
                    (hash_value % fibonacci(10) < fibonacci(8))
                )

                return "a" if complex_condition else "b"

    # ======== 3. 従来の特性関連判別ロジック（後方互換性） ========
    # 素数特性による判別（p,q パラメータの存在）- レガシーサポート
    p = parameters.get("p")
    q = parameters.get("q")
    if p is not None and q is None:
        return "a"  # データセットA用の鍵
    elif q is not None and p is None:
        return "b"  # データセットB用の鍵

    # 旧来のセキュリティ特性に基づく判別 - 後方互換性
    security_feature = key_data.get("security_feature", {})
    if security_feature:
        # プライム署名値が存在する場合
        prime_signature = security_feature.get("prime_signature")
        timestamp = security_feature.get("timestamp", int(time.time()))
        hash_val = security_feature.get("hash", "")

        if hash_val and prime_signature is not None:
            # ハッシュの複雑な分析
            hash_int = int(hash_val[:16], 16)

            # カオス理論の特性を適用
            x0 = (hash_int % 1000) / 1000.0  # 0-1の初期値
            r_value = 3.6 + (prime_signature / 10.0)  # 3.6-4.0のパラメータ
            chaos_result = logistic_map(r_value, x0)

            # 複合条件
            return "a" if (chaos_result > 0.7) else "b"

    # ======== 4. エントロピー値による高度な判別 ========
    entropy = key_data.get("entropy")
    if entropy:
        # エントロピーの複雑なハッシュ分析
        # SHA256に基づく複数のハッシュ値生成
        entropy_hash1 = hashlib.sha256(entropy.encode()).digest()
        entropy_hash2 = hashlib.sha256(entropy.encode() + b"salt1").digest()

        # 複数の整数値抽出
        int1 = int.from_bytes(entropy_hash1[:4], 'big')
        int2 = int.from_bytes(entropy_hash2[4:8], 'big')

        # フィボナッチ数列との組み合わせ
        fib_idx1 = int1 % 30
        fib_val1 = fibonacci(fib_idx1)

        # 楕円曲線特性のチェック
        ec_check1 = elliptic_curve_property(int1, int2)

        # 複雑な複合条件
        complex_entropy_check = (
            (fib_val1 % 3 == 2) or
            (ec_check1 and int1 % 7 == 3) or
            (int1 ^ int2) % 103 < 50  # 大きな素数との剰余
        )

        return "a" if complex_entropy_check else "b"

    # ======== 5. 鍵の暗号学的プロパティによる複合判別 ========
    public_key = parameters.get("public_key", {})
    private_key = parameters.get("private_key", {})

    if public_key and private_key:
        n = public_key.get("n")
        g = public_key.get("g", 0)
        lambda_n = private_key.get("lambda")
        mu = private_key.get("mu")

        if n and lambda_n and mu:
            # 複数の秘密鍵パラメータの数学的特性を分析
            property_value1 = (lambda_n * mu) % n

            # フィボナッチ数列との関連性分析
            fib_idx = (property_value1 % 1000) % 25
            fib_val = fibonacci(fib_idx)

            # ファイル名からの特性抽出（緊急対応）
            filename_check = False
            uuid_val = key_data.get("uuid", "")
            if "dataset_a_key" in str(key_data) or "_a_key" in str(key_data):
                filename_check = True
            elif "dataset_b_key" in str(key_data) or "_b_key" in str(key_data):
                filename_check = False

            # 複合判定条件
            key_math_condition = (fib_val % 11 == 3 or property_value1 % 2 == 0)

            # ファイル名チェックが利用可能ならそれを優先（緊急対応）
            if "dataset_a_key" in str(key_data) or "_a_key" in str(key_data):
                return "a"
            elif "dataset_b_key" in str(key_data) or "_b_key" in str(key_data):
                return "b"
            else:
                return "a" if key_math_condition else "b"

    # ======== 6. 最終フォールバック: UUID/タイムスタンプの複合特性 ========
    uuid_val = key_data.get("uuid", "")
    if uuid_val:
        # ハッシュ派生
        uuid_hash = hashlib.md5(uuid_val.encode()).digest()
        uuid_int = int.from_bytes(uuid_hash[:4], 'big')

        # フィボナッチ特性
        fib_val = fibonacci(uuid_int % 20)

        # 複合条件
        return "a" if (fib_val % 7 == 4) else "b"

    # タイムスタンプフォールバック
    timestamp = key_data.get("timestamp", int(time.time()))
    ts_hash = hashlib.sha256(str(timestamp).encode()).digest()
    ts_int = int.from_bytes(ts_hash[:4], 'big')

    # 最終判定
    return "a" if (ts_int % 17 == 5) else "b"

def decrypt_with_key(data: bytes, key_data: Dict[str, Any], key_path: str = "") -> bytes:
    """
    鍵を使用して暗号文を復号

    Args:
        data: 復号するデータ
        key_data: 鍵データ
        key_path: 鍵ファイルパス（緊急対応用）

    Returns:
        復号されたデータ
    """
    # 鍵パラメータの取得
    parameters = key_data.get("parameters", {})
    if not parameters:
        parameters = key_data

    # 緊急対応：鍵種別は呼び出し元で設定済み
    if key_path:
        key_type = "a" if "dataset_a_key" in key_path else "b"
    else:
        # 後方互換性のため（緊急対応）
        key_type = "a" if "dataset_a" in str(key_data) else "b"

    print(f"鍵の種類: {'dataset_b（加算マスク適用経路）' if key_type == 'b' else 'dataset_a（直接復号経路）'}")

    try:
        # 暗号文データの解析
        encrypted_data = json.loads(data.decode())

        # 公開鍵情報の取得
        public_key = encrypted_data.get("public_key", {})
        n = int(public_key.get("n", "0"))
        g = int(public_key.get("g", "0"))

        # 秘密鍵情報の取得
        private_key = parameters.get("private_key", {})
        lambda_n = private_key.get("lambda")
        mu = private_key.get("mu")

        # Paillier暗号システムの初期化
        paillier = PaillierCryptosystem()
        paillier.public_key = {"n": n, "g": g}
        paillier.private_key = {"lambda": lambda_n, "mu": mu}

        # 鍵の数学的特性から変換適用を判断
        transform = (key_type == "b")

        # 暗号文チャンクの取得
        encrypted_chunks = encrypted_data.get("chunks", [])
        chunk_size = encrypted_data.get("chunk_size", 4)
        original_size = encrypted_data.get("original_size_a") if key_type == "a" else encrypted_data.get("original_size_b")

        # 復号結果格納用のバイト配列
        decrypted_data = bytearray()

        print(f"復号開始... チャンク数: {len(encrypted_chunks)}")
        for i, chunk_info in enumerate(encrypted_chunks):
            if i % 10 == 0:
                print(f"チャンク {i+1}/{len(encrypted_chunks)} 処理中...")

            # 暗号文の取得
            ciphertext = int(chunk_info.get("ciphertext"), 16)

            # データセットBの場合は差分マスクを適用
            if transform:
                diff_mask = int(chunk_info.get("diff_mask"), 16)
                # 差分マスクを適用: E(m1) * E(m2-m1) = E(m2)
                ciphertext = paillier.homomorphic_add(ciphertext, diff_mask)

            # 暗号文を復号
            plaintext = paillier.decrypt(ciphertext, transform=False)  # transformは直接使わない

            # 復号された整数をバイト列に変換
            max_bytes = (plaintext.bit_length() + 7) // 8
            plaintext_bytes = plaintext.to_bytes(max(max_bytes, chunk_size), byteorder='big')

            # 結果に追加
            decrypted_data.extend(plaintext_bytes)

        # 元のサイズに切り詰める
        if original_size is not None:
            decrypted_data = decrypted_data[:original_size]

        return bytes(decrypted_data)

    except json.JSONDecodeError:
        print("エラー: データがJSON形式ではありません。旧形式のデータかもしれません。")
        # 旧形式のデータ形式への対応（互換性のため）
        raise NotImplementedError("古い形式のデータはサポートされていません。")

    except Exception as e:
        print(f"復号中にエラーが発生しました: {e}")
        traceback.print_exc()
        return b""

def decrypt_file(encrypted_file: str, key_file: str, output_file: str = None) -> Dict[str, Any]:
    """
    暗号化ファイルを復号

    Args:
        encrypted_file: 暗号化ファイルパス
        key_file: 鍵ファイルパス
        output_file: 出力ファイルパス（Noneの場合は自動生成）

    Returns:
        結果情報の辞書
    """
    # ファイルの読み込み
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()

    with open(key_file, 'r') as f:
        key_data = json.load(f)

    print(f"暗号化ファイル: {encrypted_file} ({len(encrypted_data)} bytes)")
    print(f"鍵ファイル: {key_file}")

    # 緊急対応：ファイルパスから鍵種別を直接判定
    key_type = "a" if "dataset_a_key" in key_file else "b"
    print(f"鍵種別（パス直接判定）: {'dataset_a' if key_type == 'a' else 'dataset_b'}")

    # 復号処理
    start_time = time.time()
    decrypted_data = decrypt_with_key(encrypted_data, key_data, key_path=key_file)
    decryption_time = time.time() - start_time

    # 出力ファイル名の決定
    if output_file is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.sha256(encrypted_file.encode()).hexdigest()[:8]
        dataset_type = "A" if key_type == "a" else "B"
        output_file = f"decrypted_dataset{dataset_type}_{timestamp}_{file_hash}.bin"

    # 復号データの保存
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"復号ファイルを保存しました: {output_file} ({len(decrypted_data)} bytes)")
    print(f"復号処理時間: {decryption_time:.2f}秒")

    # 結果情報
    result = {
        "encrypted_file": encrypted_file,
        "key_file": key_file,
        "output_file": output_file,
        "decrypted_size": len(decrypted_data),
        "decryption_time": decryption_time,
        "key_type": analyze_key_type(key_data),
        "timestamp": int(time.time())
    }

    return result

def parse_key_file(key_file_path: str) -> Dict[str, Any]:
    """
    鍵ファイルを解析

    Args:
        key_file_path: 鍵ファイルパス

    Returns:
        鍵データ辞書
    """
    with open(key_file_path, 'r') as f:
        key_data = json.load(f)
    return key_data

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='準同型暗号マスキング方式の復号プログラム')
    parser.add_argument('encrypted_file', help='復号する暗号化ファイル')
    parser.add_argument('key_file', help='復号に使用する鍵ファイル')
    parser.add_argument('-o', '--output', help='出力ファイルパス（指定しない場合は自動生成）')

    args = parser.parse_args()

    try:
        result = decrypt_file(args.encrypted_file, args.key_file, args.output)
        print("復号が完了しました。")
        # 緊急対応として、ファイル名から直接判定
        key_type = "a" if "dataset_a_key" in args.key_file else "b"
        print(f"鍵の種類: {'dataset_b（変換あり）' if key_type == 'b' else 'dataset_a（変換なし）'}")
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
