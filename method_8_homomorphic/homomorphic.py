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
from typing import Tuple, Dict, Any, Union, List
import sympy
from sympy import mod_inverse

from method_8_homomorphic.config import (
    PAILLIER_KEY_BITS,
    PAILLIER_PRECISION,
    ELGAMAL_KEY_BITS
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
        private_key = {'lambda': lambda_val, 'mu': mu, 'n': n}

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

        n = public_key['n']
        g = public_key['g']
        n_squared = n * n

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

        n_squared = public_key['n'] * public_key['n']

        # c^k mod n^2
        return pow(c, k, n_squared)


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

        p = public_key['p']

        a, b = c

        # 暗号文の指数乗: (a^k, b^k)
        a_result = pow(a, k, p)
        b_result = pow(b, k, p)

        return (a_result, b_result)


# 準同型暗号のハイブリッド利用例
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
