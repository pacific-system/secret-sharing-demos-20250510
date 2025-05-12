#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号の基本実装

このモジュールはPaillier暗号（加法準同型）とElGamal暗号（乗法準同型）の
基本的な実装を提供します。
"""

import os
import random
import hashlib
import math
import secrets
import json
import base64
import time
from typing import Tuple, Dict, Any, Union, List, Optional
import sympy
from sympy import mod_inverse

from method_8_homomorphic.config import (
    PAILLIER_KEY_BITS,
    PAILLIER_PRECISION,
    ELGAMAL_KEY_BITS,
    KDF_ITERATIONS,
    SALT_SIZE
)


class PaillierCrypto:
    """Paillier暗号の実装（加法準同型）"""

    def __init__(self, bits: int = PAILLIER_KEY_BITS):
        """
        Paillier暗号の初期化

        Args:
            bits: 鍵のビット長
        """
        self.bits = bits
        self.precision = PAILLIER_PRECISION
        self.n = 0
        self.g = 0
        self.lambda_val = 0
        self.mu = 0
        self.public_key = None
        self.private_key = None

    def generate_keys(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """
        Paillier暗号の鍵ペアを生成

        Returns:
            (公開鍵, 秘密鍵)のタプル
        """
        # 2つの同じサイズの大きな素数を生成
        p = sympy.randprime(2**(self.bits//2-1), 2**(self.bits//2))
        q = sympy.randprime(2**(self.bits//2-1), 2**(self.bits//2))

        # n = p * q
        n = p * q

        # λ = lcm(p-1, q-1)
        lambda_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)

        # g は通常 n+1 を使用
        g = n + 1

        # μ = (L(g^λ mod n^2))^(-1) mod n
        # ここで L(x) = (x-1)/n
        # g^λ mod n^2 を計算
        g_lambda = pow(g, lambda_val, n * n)

        # L(g_lambda) = (g_lambda - 1) / n
        l_g_lambda = (g_lambda - 1) // n

        # μ = l_g_lambda^(-1) mod n
        mu = mod_inverse(l_g_lambda, n)

        # 公開鍵と秘密鍵を設定
        self.n = n
        self.g = g
        self.lambda_val = lambda_val
        self.mu = mu

        public_key = {'n': n, 'g': g}
        private_key = {'lambda': lambda_val, 'mu': mu, 'n': n, 'p': p, 'q': q}

        self.public_key = public_key
        self.private_key = private_key

        return public_key, private_key

    def encrypt(self, m: int, public_key: Dict[str, int] = None) -> int:
        """
        メッセージを暗号化

        Args:
            m: 暗号化する整数値
            public_key: 公開鍵（指定がなければ内部の鍵を使用）

        Returns:
            暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = public_key['n']
        g = public_key['g']

        # 0 <= m < n の範囲に収める
        m = m % n

        # 乱数 r (0 < r < n) を生成
        r = random.randint(1, n - 1)

        # 暗号文 c = g^m * r^n mod n^2
        n_squared = n * n
        g_m = pow(g, m, n_squared)
        r_n = pow(r, n, n_squared)
        c = (g_m * r_n) % n_squared

        return c

    def decrypt(self, c: int, private_key: Dict[str, int] = None) -> int:
        """
        暗号文を復号

        Args:
            c: 復号する暗号文
            private_key: 秘密鍵（指定がなければ内部の鍵を使用）

        Returns:
            復号された整数値
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        n = private_key['n']
        lambda_val = private_key['lambda']
        mu = private_key['mu']

        # L(c^λ mod n^2) * μ mod n を計算
        n_squared = n * n

        # c^λ mod n^2
        c_lambda = pow(c, lambda_val, n_squared)

        # L(c_lambda) = (c_lambda - 1) / n
        l_c_lambda = (c_lambda - 1) // n

        # m = L(c_lambda) * μ mod n
        m = (l_c_lambda * mu) % n

        return m

    def encrypt_float(self, m: float, public_key: Dict[str, int] = None) -> int:
        """
        浮動小数点数を暗号化

        Args:
            m: 暗号化する浮動小数点数
            public_key: 公開鍵

        Returns:
            暗号文
        """
        # 浮動小数点数を整数に変換
        m_int = int(m * self.precision)
        return self.encrypt(m_int, public_key)

    def decrypt_float(self, c: int, private_key: Dict[str, int] = None) -> float:
        """
        暗号文を浮動小数点数に復号

        Args:
            c: 復号する暗号文
            private_key: 秘密鍵

        Returns:
            復号された浮動小数点数
        """
        m_int = self.decrypt(c, private_key)
        return m_int / self.precision

    def add(self, c1: int, c2: int, public_key: Dict[str, int] = None) -> int:
        """
        暗号文同士の加算（平文では m1 + m2 に相当）

        Args:
            c1: 1つ目の暗号文
            c2: 2つ目の暗号文
            public_key: 公開鍵

        Returns:
            加算結果の暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n_squared = public_key['n'] * public_key['n']
        return (c1 * c2) % n_squared

    def add_constant(self, c: int, k: int, public_key: Dict[str, int] = None) -> int:
        """
        暗号文に定数を加算（平文では m + k に相当）

        Args:
            c: 暗号文
            k: 加算する定数
            public_key: 公開鍵

        Returns:
            加算結果の暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = public_key['n']
        g = public_key['g']
        n_squared = n * n

        # 定数がnを超えないようにする
        k = k % n

        # g^k mod n^2
        g_k = pow(g, k, n_squared)

        # c * g^k mod n^2
        return (c * g_k) % n_squared

    def multiply_constant(self, c: int, k: int, public_key: Dict[str, int] = None) -> int:
        """
        暗号文に定数を乗算（平文では m * k に相当）

        Args:
            c: 暗号文
            k: 乗算する定数
            public_key: 公開鍵

        Returns:
            乗算結果の暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n_squared = public_key['n'] * public_key['n']

        # 定数がnを超えないようにする
        k = k % public_key['n']

        # c^k mod n^2
        return pow(c, k, n_squared)

    def encrypt_bytes(self, data: bytes, public_key: Dict[str, int] = None, chunk_size: int = 128) -> List[int]:
        """
        バイトデータを暗号化

        Args:
            data: 暗号化するバイトデータ
            public_key: 公開鍵
            chunk_size: チャンクサイズ（バイト）

        Returns:
            暗号化されたチャンクのリスト
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        # データをチャンクに分割
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

        # 各チャンクを整数に変換して暗号化
        encrypted_chunks = []
        for chunk in chunks:
            # バイト列を整数に変換
            int_value = int.from_bytes(chunk, 'big')
            # 暗号化
            encrypted = self.encrypt(int_value, public_key)
            encrypted_chunks.append(encrypted)

        return encrypted_chunks

    def decrypt_bytes(self, encrypted_chunks: List[int], original_size: int,
                     private_key: Dict[str, int] = None, chunk_size: int = 128) -> bytes:
        """
        暗号化されたバイトデータを復号

        Args:
            encrypted_chunks: 暗号化されたチャンクのリスト
            original_size: 元のデータサイズ
            private_key: 秘密鍵
            chunk_size: チャンクサイズ（バイト）

        Returns:
            復号されたバイトデータ
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        # 各チャンクを復号
        decrypted_data = bytearray()
        remaining_size = original_size

        for chunk in encrypted_chunks:
            # 暗号文を復号
            int_value = self.decrypt(chunk, private_key)

            # 最後のチャンクは部分的かもしれない
            bytes_in_chunk = min(chunk_size, remaining_size)

            # 整数をバイト列に変換
            # 注：サイズを超えないよう調整
            bytes_value = int_value.to_bytes(
                (int_value.bit_length() + 7) // 8, 'big')[-bytes_in_chunk:]

            # バイト配列に追加
            decrypted_data.extend(bytes_value)

            # 残りのサイズを更新
            remaining_size -= bytes_in_chunk

        return bytes(decrypted_data)

    def save_keys(self, public_key_file: str, private_key_file: Optional[str] = None) -> None:
        """
        鍵をファイルに保存

        Args:
            public_key_file: 公開鍵の保存先ファイルパス
            private_key_file: 秘密鍵の保存先ファイルパス（省略可）
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        # 公開鍵の保存
        with open(public_key_file, 'w') as f:
            json.dump(self.public_key, f)

        # 秘密鍵の保存（指定されている場合）
        if private_key_file is not None and self.private_key is not None:
            with open(private_key_file, 'w') as f:
                json.dump(self.private_key, f)

    def load_keys(self, public_key_file: str, private_key_file: Optional[str] = None) -> None:
        """
        ファイルから鍵を読み込み

        Args:
            public_key_file: 公開鍵ファイルのパス
            private_key_file: 秘密鍵ファイルのパス（省略可）
        """
        # 公開鍵の読み込み
        with open(public_key_file, 'r') as f:
            self.public_key = json.load(f)

        # 秘密鍵の読み込み（指定されている場合）
        if private_key_file is not None:
            try:
                with open(private_key_file, 'r') as f:
                    self.private_key = json.load(f)
            except FileNotFoundError:
                self.private_key = None


class ElGamalCrypto:
    """ElGamal暗号の実装（乗法準同型）"""

    def __init__(self, bits: int = ELGAMAL_KEY_BITS):
        """
        ElGamal暗号の初期化

        Args:
            bits: 鍵のビット長
        """
        self.bits = bits
        self.p = 0
        self.g = 0
        self.y = 0
        self.x = 0
        self.public_key = None
        self.private_key = None

    def generate_keys(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """
        ElGamal暗号の鍵ペアを生成

        Returns:
            (公開鍵, 秘密鍵)のタプル
        """
        # 大きな素数pを生成
        self.p = sympy.randprime(2**(self.bits-1), 2**self.bits)

        # 原始根gを見つける
        while True:
            self.g = random.randint(2, self.p - 1)
            if pow(self.g, (self.p - 1) // 2, self.p) != 1:  # 原始根の簡易チェック
                break

        # 秘密鍵x (1 < x < p-1) を生成
        self.x = random.randint(2, self.p - 2)

        # 公開鍵y = g^x mod p を計算
        self.y = pow(self.g, self.x, self.p)

        # 公開鍵と秘密鍵を設定
        public_key = {'p': self.p, 'g': self.g, 'y': self.y}
        private_key = {'x': self.x, 'p': self.p}

        self.public_key = public_key
        self.private_key = private_key

        return public_key, private_key

    def encrypt(self, m: int, public_key: Dict[str, int] = None) -> Tuple[int, int]:
        """
        メッセージを暗号化

        Args:
            m: 暗号化する整数値 (1 < m < p-1)
            public_key: 公開鍵

        Returns:
            (c1, c2)の暗号文ペア
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        p = public_key['p']
        g = public_key['g']
        y = public_key['y']

        # メッセージが範囲内にあることを確認
        if m <= 0 or m >= p:
            m = m % (p - 1)
            if m == 0:
                m = 1

        # 一時的な乱数k (1 < k < p-1) を生成
        k = random.randint(2, p - 2)

        # c1 = g^k mod p
        c1 = pow(g, k, p)

        # c2 = m * y^k mod p
        y_k = pow(y, k, p)
        c2 = (m * y_k) % p

        return (c1, c2)

    def decrypt(self, ciphertext: Tuple[int, int], private_key: Dict[str, int] = None) -> int:
        """
        暗号文を復号

        Args:
            ciphertext: (c1, c2)の暗号文ペア
            private_key: 秘密鍵

        Returns:
            復号された整数値
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        c1, c2 = ciphertext
        x = private_key['x']
        p = private_key['p']

        # s = c1^x mod p
        s = pow(c1, x, p)

        # m = c2 * s^(-1) mod p
        s_inv = mod_inverse(s, p)
        m = (c2 * s_inv) % p

        return m

    def multiply(self, c1: Tuple[int, int], c2: Tuple[int, int], public_key: Dict[str, int] = None) -> Tuple[int, int]:
        """
        暗号文同士の乗算（平文では m1 * m2 に相当）

        Args:
            c1: 1つ目の暗号文ペア (a1, b1)
            c2: 2つ目の暗号文ペア (a2, b2)
            public_key: 公開鍵

        Returns:
            乗算結果の暗号文ペア
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        p = public_key['p']

        # c1 = (a1, b1), c2 = (a2, b2)
        a1, b1 = c1
        a2, b2 = c2

        # 暗号文の乗算: (a1*a2, b1*b2)
        a_result = (a1 * a2) % p
        b_result = (b1 * b2) % p

        return (a_result, b_result)

    def pow_constant(self, c: Tuple[int, int], k: int, public_key: Dict[str, int] = None) -> Tuple[int, int]:
        """
        暗号文の定数乗（平文では m^k に相当）

        Args:
            c: 暗号文ペア (a, b)
            k: 指数
            public_key: 公開鍵

        Returns:
            指数乗算結果の暗号文ペア
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        p = public_key['p']

        a, b = c

        # 暗号文の指数乗: (a^k, b^k)
        a_result = pow(a, k, p)
        b_result = pow(b, k, p)

        return (a_result, b_result)

    def encrypt_bytes(self, data: bytes, public_key: Dict[str, int] = None, chunk_size: int = 64) -> List[Tuple[int, int]]:
        """
        バイトデータを暗号化

        Args:
            data: 暗号化するバイトデータ
            public_key: 公開鍵
            chunk_size: チャンクサイズ（バイト）

        Returns:
            暗号化されたチャンクのリスト
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        # ElGamalで扱える数値の上限
        p = public_key['p']
        max_value = p - 1

        # チャンクサイズを調整（p以下の整数となるように）
        max_bytes = (max_value.bit_length() + 7) // 8 - 1
        chunk_size = min(chunk_size, max_bytes)

        # データをチャンクに分割
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

        # 各チャンクを整数に変換して暗号化
        encrypted_chunks = []
        for chunk in chunks:
            # バイト列を整数に変換
            int_value = int.from_bytes(chunk, 'big')
            # 値が範囲内にあることを確認
            if int_value >= max_value:
                int_value = int_value % max_value
            if int_value == 0:
                int_value = 1  # ElGamalでは0を暗号化できないため
            # 暗号化
            encrypted = self.encrypt(int_value, public_key)
            encrypted_chunks.append(encrypted)

        return encrypted_chunks

    def decrypt_bytes(self, encrypted_chunks: List[Tuple[int, int]], original_size: int,
                     private_key: Dict[str, int] = None, chunk_size: int = 64) -> bytes:
        """
        暗号化されたバイトデータを復号

        Args:
            encrypted_chunks: 暗号化されたチャンクのリスト
            original_size: 元のデータサイズ
            private_key: 秘密鍵
            chunk_size: チャンクサイズ（バイト）

        Returns:
            復号されたバイトデータ
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        # 各チャンクを復号
        decrypted_data = bytearray()
        remaining_size = original_size

        for chunk in encrypted_chunks:
            # 暗号文を復号
            int_value = self.decrypt(chunk, private_key)

            # 最後のチャンクは部分的かもしれない
            bytes_in_chunk = min(chunk_size, remaining_size)

            # 整数をバイト列に変換
            bytes_value = int_value.to_bytes(
                (int_value.bit_length() + 7) // 8, 'big')[-bytes_in_chunk:]

            # バイト配列に追加
            decrypted_data.extend(bytes_value)

            # 残りのサイズを更新
            remaining_size -= bytes_in_chunk

        return bytes(decrypted_data)

    def save_keys(self, public_key_file: str, private_key_file: Optional[str] = None) -> None:
        """
        鍵をファイルに保存

        Args:
            public_key_file: 公開鍵の保存先ファイルパス
            private_key_file: 秘密鍵の保存先ファイルパス（省略可）
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        # 公開鍵の保存
        with open(public_key_file, 'w') as f:
            json.dump(self.public_key, f)

        # 秘密鍵の保存（指定されている場合）
        if private_key_file is not None and self.private_key is not None:
            with open(private_key_file, 'w') as f:
                json.dump(self.private_key, f)

    def load_keys(self, public_key_file: str, private_key_file: Optional[str] = None) -> None:
        """
        ファイルから鍵を読み込み

        Args:
            public_key_file: 公開鍵ファイルのパス
            private_key_file: 秘密鍵ファイルのパス（省略可）
        """
        # 公開鍵の読み込み
        with open(public_key_file, 'r') as f:
            self.public_key = json.load(f)

        # 秘密鍵の読み込み（指定されている場合）
        if private_key_file is not None:
            try:
                with open(private_key_file, 'r') as f:
                    self.private_key = json.load(f)
            except FileNotFoundError:
                self.private_key = None


# 鍵管理とシリアライズのユーティリティ関数
def save_keys(public_key: Dict[str, int], private_key: Dict[str, int],
             public_key_file: str, private_key_file: str) -> None:
    """
    公開鍵と秘密鍵をファイルに保存

    Args:
        public_key: 公開鍵
        private_key: 秘密鍵
        public_key_file: 公開鍵の保存先
        private_key_file: 秘密鍵の保存先
    """
    # 公開鍵の保存
    with open(public_key_file, 'w') as f:
        json.dump(public_key, f)

    # 秘密鍵の保存
    with open(private_key_file, 'w') as f:
        json.dump(private_key, f)


def load_keys(public_key_file: str, private_key_file: Optional[str] = None) -> Tuple[Dict[str, int], Optional[Dict[str, int]]]:
    """
    ファイルから鍵を読み込む

    Args:
        public_key_file: 公開鍵ファイル
        private_key_file: 秘密鍵ファイル（省略可）

    Returns:
        (public_key, private_key)
    """
    # 公開鍵の読み込み
    with open(public_key_file, 'r') as f:
        public_key = json.load(f)

    # 秘密鍵の読み込み（指定されている場合）
    private_key = None
    if private_key_file:
        try:
            with open(private_key_file, 'r') as f:
                private_key = json.load(f)
        except FileNotFoundError:
            pass  # 秘密鍵ファイルが見つからない場合は None のままにする

    return public_key, private_key


def derive_key_from_password(password: str, salt: Optional[bytes] = None, crypto_type: str = "paillier", bits: int = None) -> Tuple[Dict[str, Any], Dict[str, Any], bytes]:
    """
    パスワードから鍵ペアを導出（固定的に生成）

    同じパスワードとソルトからは同じ鍵ペアが生成されます。

    Args:
        password: パスワード文字列
        salt: ソルト（省略時はランダム生成）
        crypto_type: 暗号方式 ("paillier" または "elgamal")
        bits: 鍵のビット長（省略時はデフォルト値）

    Returns:
        (public_key, private_key, salt)
    """
    # ソルトがなければ生成
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    # パスワードと塩からシード値を導出
    seed_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        KDF_ITERATIONS,
        dklen=32
    )
    seed = int.from_bytes(seed_bytes, 'big')

    # シード値から疑似乱数生成器を初期化
    random.seed(seed)

    # 暗号方式に応じて鍵を生成
    if crypto_type.lower() == "paillier":
        bits = bits or PAILLIER_KEY_BITS
        paillier = PaillierCrypto(bits=bits)
        public_key, private_key = paillier.generate_keys()
    elif crypto_type.lower() == "elgamal":
        bits = bits or ELGAMAL_KEY_BITS
        elgamal = ElGamalCrypto(bits=bits)
        public_key, private_key = elgamal.generate_keys()
    else:
        raise ValueError(f"サポートされていない暗号方式: {crypto_type}")

    return public_key, private_key, salt


def serialize_encrypted_data(encrypted_chunks: Union[List[int], List[Tuple[int, int]]],
                          original_size: int,
                          crypto_type: str = "paillier",
                          additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    暗号化データをシリアライズ可能な形式に変換

    Args:
        encrypted_chunks: 暗号化されたチャンクのリスト
        original_size: 元のデータサイズ
        crypto_type: 暗号方式 ("paillier" または "elgamal")
        additional_data: 追加のメタデータ

    Returns:
        シリアライズ可能な辞書
    """
    # 暗号化チャンクを16進数文字列に変換
    if crypto_type.lower() == "paillier":
        hex_chunks = [hex(chunk) for chunk in encrypted_chunks]
    elif crypto_type.lower() == "elgamal":
        hex_chunks = [(hex(c1), hex(c2)) for c1, c2 in encrypted_chunks]
    else:
        raise ValueError(f"サポートされていない暗号方式: {crypto_type}")

    # データを辞書に格納
    result = {
        "format": "homomorphic_encrypted",
        "version": "1.0",
        "crypto_type": crypto_type,
        "chunks": hex_chunks,
        "original_size": original_size,
        "timestamp": int(time.time())
    }

    # 追加のメタデータがあれば追加
    if additional_data:
        result.update(additional_data)

    return result


def deserialize_encrypted_data(data: Dict[str, Any]) -> Tuple[Union[List[int], List[Tuple[int, int]]], int, str]:
    """
    シリアライズされた暗号化データを復元

    Args:
        data: シリアライズされたデータ辞書

    Returns:
        (encrypted_chunks, original_size, crypto_type)
    """
    # フォーマットチェック
    if data.get("format") != "homomorphic_encrypted":
        raise ValueError("サポートされていないフォーマットです")

    # バージョンチェック
    if data.get("version") != "1.0":
        raise ValueError("サポートされていないバージョンです")

    # 暗号方式の取得
    crypto_type = data.get("crypto_type", "paillier")

    # 暗号化チャンクを16進数文字列から復元
    original_size = data["original_size"]

    # Paillierの場合は整数のリスト
    if crypto_type.lower() == "paillier":
        encrypted_chunks = [int(chunk, 16) for chunk in data["chunks"]]
    # ElGamalの場合はタプルのリスト
    elif crypto_type.lower() == "elgamal":
        encrypted_chunks = [(int(c1, 16), int(c2, 16)) for c1, c2 in data["chunks"]]
    else:
        raise ValueError(f"サポートされていない暗号方式: {crypto_type}")

    return encrypted_chunks, original_size, crypto_type


# 準同型暗号のハイブリッド利用例とデモ機能
def homomorphic_demo():
    """
    準同型暗号のデモ
    """
    print("=== Paillier暗号（加法準同型）デモ ===")
    paillier = PaillierCrypto(bits=1024)  # より小さい鍵サイズでデモ実行
    public_key, private_key = paillier.generate_keys()

    m1 = 42
    m2 = 73

    c1 = paillier.encrypt(m1, public_key)
    c2 = paillier.encrypt(m2, public_key)

    # 暗号文同士の加算
    c_add = paillier.add(c1, c2, public_key)

    # 復号
    decrypted = paillier.decrypt(c_add, private_key)

    print(f"m1 = {m1}, m2 = {m2}")
    print(f"m1 + m2 = {m1 + m2}")
    print(f"復号結果 = {decrypted}")

    # 定数倍のテスト
    k = 5
    c_mul = paillier.multiply_constant(c1, k, public_key)
    decrypted_mul = paillier.decrypt(c_mul, private_key)
    print(f"\nm1 * {k} = {m1 * k}")
    print(f"復号結果 = {decrypted_mul}")

    # バイトデータのテスト
    test_text = "これは準同型暗号のテストです。Hello, Homomorphic Encryption!"
    test_bytes = test_text.encode('utf-8')

    print(f"\nテキストのバイナリ暗号化テスト: {test_text}")
    # バイナリデータの暗号化
    encrypted_chunks = paillier.encrypt_bytes(test_bytes, public_key)
    print(f"暗号化チャンク数: {len(encrypted_chunks)}")

    # バイナリデータの復号
    decrypted_bytes = paillier.decrypt_bytes(encrypted_chunks, len(test_bytes), private_key)
    decrypted_text = decrypted_bytes.decode('utf-8')
    print(f"復号テキスト: {decrypted_text}")
    print(f"復号成功: {test_text == decrypted_text}")

    # パスワードからの鍵導出テスト
    print("\n=== パスワードからの鍵導出テスト ===")
    password = "secure_password_123"
    salt = os.urandom(SALT_SIZE)

    # 1回目の導出
    pub1, priv1, _ = derive_key_from_password(password, salt, "paillier", 1024)

    # 2回目の導出（同じパスワードとソルト）
    pub2, priv2, _ = derive_key_from_password(password, salt, "paillier", 1024)

    # 鍵の比較
    print(f"同じパスワードとソルトからの鍵一貫性: {pub1['n'] == pub2['n']}")

    # Paillier暗号文のシリアライズテスト
    print("\n=== 暗号文のシリアライズテスト ===")
    serialized = serialize_encrypted_data(encrypted_chunks, len(test_bytes), "paillier")
    print(f"シリアライズ結果のキー: {list(serialized.keys())}")

    # デシリアライズテスト
    deserialized_chunks, original_size, crypto_type = deserialize_encrypted_data(serialized)
    print(f"デシリアライズしたチャンク数: {len(deserialized_chunks)}")
    print(f"元のサイズ: {original_size}, 暗号方式: {crypto_type}")

    # デシリアライズしたデータの復号テスト
    decrypted_bytes2 = paillier.decrypt_bytes(deserialized_chunks, original_size, private_key)
    decrypted_text2 = decrypted_bytes2.decode('utf-8')
    print(f"シリアライズ・デシリアライズ後の復号テキスト: {decrypted_text2}")
    print(f"シリアライズ・デシリアライズの成功: {test_text == decrypted_text2}")

    print("\n=== ElGamal暗号（乗法準同型）デモ ===")
    elgamal = ElGamalCrypto(bits=512)  # より小さい鍵サイズでデモ実行
    public_key, private_key = elgamal.generate_keys()

    m1 = 11
    m2 = 7

    c1 = elgamal.encrypt(m1, public_key)
    c2 = elgamal.encrypt(m2, public_key)

    # 暗号文同士の乗算
    c_mul = elgamal.multiply(c1, c2, public_key)

    # 復号
    decrypted = elgamal.decrypt(c_mul, private_key)

    print(f"m1 = {m1}, m2 = {m2}")
    print(f"m1 * m2 = {m1 * m2}")
    print(f"復号結果 = {decrypted}")


if __name__ == "__main__":
    homomorphic_demo()
