#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号モジュールのテスト

このスクリプトは、準同型暗号モジュール（PaillierCryptoとElGamalCrypto）の
機能をテストし、準同型演算が正しく機能することを検証します。
"""

import os
import sys
import time
import unittest
import random
import binascii
import hashlib
import base64
import json
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any, List, Tuple, Union

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, serialize_encrypted_data, deserialize_encrypted_data
)


class TestPaillierCrypto(unittest.TestCase):
    """Paillier暗号（加法準同型）のテスト"""

    def setUp(self):
        """テスト準備"""
        self.paillier = PaillierCrypto(bits=1024)  # テスト用に小さなビット長
        self.public_key, self.private_key = self.paillier.generate_keys()

    def test_encrypt_decrypt_int(self):
        """整数の暗号化と復号をテスト"""
        plaintext = 42
        ciphertext = self.paillier.encrypt(plaintext, self.public_key)
        decrypted = self.paillier.decrypt(ciphertext, self.private_key)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_float(self):
        """浮動小数点数の暗号化と復号をテスト"""
        plaintext = 3.14159
        ciphertext = self.paillier.encrypt_float(plaintext, self.public_key)
        decrypted = self.paillier.decrypt_float(ciphertext, self.private_key)
        # 浮動小数点の丸め誤差を考慮（精度を2桁に緩和）
        self.assertAlmostEqual(plaintext, decrypted, places=2)

    def test_encrypt_decrypt_bytes(self):
        """バイト列の暗号化と復号をテスト"""
        plaintext = b"Hello, Homomorphic Encryption!"
        encrypted_chunks = self.paillier.encrypt_bytes(plaintext, self.public_key)
        decrypted = self.paillier.decrypt_bytes(encrypted_chunks, len(plaintext), self.private_key)
        self.assertEqual(plaintext, decrypted)

    def test_homomorphic_addition(self):
        """準同型加算のテスト"""
        m1 = 25
        m2 = 17

        c1 = self.paillier.encrypt(m1, self.public_key)
        c2 = self.paillier.encrypt(m2, self.public_key)

        # 暗号文同士の加算
        c_add = self.paillier.add(c1, c2, self.public_key)

        # 復号して検証
        decrypted = self.paillier.decrypt(c_add, self.private_key)

        self.assertEqual(m1 + m2, decrypted)

    def test_homomorphic_add_constant(self):
        """定数加算のテスト"""
        m = 42
        k = 7

        c = self.paillier.encrypt(m, self.public_key)

        # 暗号文に定数を加算
        c_add = self.paillier.add_constant(c, k, self.public_key)

        # 復号して検証
        decrypted = self.paillier.decrypt(c_add, self.private_key)

        self.assertEqual(m + k, decrypted)

    def test_homomorphic_multiply_constant(self):
        """定数乗算のテスト"""
        m = 13
        k = 5

        c = self.paillier.encrypt(m, self.public_key)

        # 暗号文に定数を乗算
        c_mul = self.paillier.multiply_constant(c, k, self.public_key)

        # 復号して検証
        decrypted = self.paillier.decrypt(c_mul, self.private_key)

        self.assertEqual(m * k, decrypted)

    def test_key_serialization(self):
        """鍵のシリアライズとデシリアライズをテスト"""
        # 鍵をファイルに保存
        public_key_file = "test_output/paillier_public.json"
        private_key_file = "test_output/paillier_private.json"

        os.makedirs("test_output", exist_ok=True)

        self.paillier.save_keys(public_key_file, private_key_file)

        # 新しいインスタンスを作成して鍵をロード
        new_paillier = PaillierCrypto(bits=1024)
        new_paillier.load_keys(public_key_file, private_key_file)

        # 元の鍵と新しい鍵で同じ暗号化と復号ができるか検証
        plaintext = 999
        ciphertext = self.paillier.encrypt(plaintext, self.public_key)
        decrypted = new_paillier.decrypt(ciphertext, new_paillier.private_key)

        self.assertEqual(plaintext, decrypted)


class TestElGamalCrypto(unittest.TestCase):
    """ElGamal暗号（乗法準同型）のテスト"""

    def setUp(self):
        """テスト準備"""
        self.elgamal = ElGamalCrypto(bits=512)  # テスト用に小さなビット長
        self.public_key, self.private_key = self.elgamal.generate_keys()

    def test_encrypt_decrypt_int(self):
        """整数の暗号化と復号をテスト"""
        plaintext = 42
        ciphertext = self.elgamal.encrypt(plaintext, self.public_key)
        decrypted = self.elgamal.decrypt(ciphertext, self.private_key)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_bytes(self):
        """バイト列の暗号化と復号をテスト"""
        plaintext = b"Hello, ElGamal Encryption!"
        encrypted_chunks = self.elgamal.encrypt_bytes(plaintext, self.public_key)
        decrypted = self.elgamal.decrypt_bytes(encrypted_chunks, len(plaintext), self.private_key)
        self.assertEqual(plaintext, decrypted)

    def test_homomorphic_multiplication(self):
        """準同型乗算のテスト"""
        m1 = 7
        m2 = 6

        c1 = self.elgamal.encrypt(m1, self.public_key)
        c2 = self.elgamal.encrypt(m2, self.public_key)

        # 暗号文同士の乗算
        c_mul = self.elgamal.multiply(c1, c2, self.public_key)

        # 復号して検証
        decrypted = self.elgamal.decrypt(c_mul, self.private_key)

        self.assertEqual(m1 * m2, decrypted)

    def test_homomorphic_pow_constant(self):
        """定数冪乗のテスト"""
        m = 3
        k = 4  # m^4 = 3^4 = 81

        c = self.elgamal.encrypt(m, self.public_key)

        # 暗号文の定数冪乗
        c_pow = self.elgamal.pow_constant(c, k, self.public_key)

        # 復号して検証
        decrypted = self.elgamal.decrypt(c_pow, self.private_key)

        self.assertEqual(m ** k, decrypted)

    def test_key_serialization(self):
        """鍵のシリアライズとデシリアライズをテスト"""
        # 鍵をファイルに保存
        public_key_file = "test_output/elgamal_public.json"
        private_key_file = "test_output/elgamal_private.json"

        os.makedirs("test_output", exist_ok=True)

        self.elgamal.save_keys(public_key_file, private_key_file)

        # 新しいインスタンスを作成して鍵をロード
        new_elgamal = ElGamalCrypto(bits=512)
        new_elgamal.load_keys(public_key_file, private_key_file)

        # 元の鍵と新しい鍵で同じ暗号化と復号ができるか検証
        plaintext = 55
        ciphertext = self.elgamal.encrypt(plaintext, self.public_key)
        decrypted = new_elgamal.decrypt(ciphertext, new_elgamal.private_key)

        self.assertEqual(plaintext, decrypted)


class TestKeyDerivation(unittest.TestCase):
    """鍵導出関数のテスト"""

    def test_derive_key_from_password(self):
        """パスワードからの鍵導出をテスト"""
        password = "secure_password_123"
        salt = os.urandom(16)

        # 1回目の導出
        pub1, priv1, salt1 = derive_key_from_password(password, salt, "paillier", 1024)

        # 2回目の導出（同じパスワードとソルト）
        pub2, priv2, salt2 = derive_key_from_password(password, salt, "paillier", 1024)

        # 鍵が一致することを確認
        self.assertEqual(pub1['n'], pub2['n'])
        self.assertEqual(pub1['g'], pub2['g'])
        self.assertEqual(priv1['lambda'], priv2['lambda'])
        self.assertEqual(priv1['mu'], priv2['mu'])
        self.assertEqual(priv1['p'], priv2['p'])
        self.assertEqual(priv1['q'], priv2['q'])

    def test_derive_elgamal_key(self):
        """ElGamal鍵の導出をテスト"""
        password = "secure_password_456"
        salt = os.urandom(16)

        # ElGamal鍵を導出
        pub, priv, _ = derive_key_from_password(password, salt, "elgamal", 512)

        # 鍵の形式を確認
        self.assertIn('p', pub)
        self.assertIn('g', pub)
        self.assertIn('y', pub)
        self.assertIn('x', priv)
        self.assertIn('p', priv)

        # 導出された鍵で暗号化と復号をテスト
        elgamal = ElGamalCrypto(bits=512)
        elgamal.public_key = pub
        elgamal.private_key = priv

        plaintext = 42
        ciphertext = elgamal.encrypt(plaintext, pub)
        decrypted = elgamal.decrypt(ciphertext, priv)

        self.assertEqual(plaintext, decrypted)


class TestSerialization(unittest.TestCase):
    """暗号文のシリアライズとデシリアライズのテスト"""

    def test_paillier_serialization(self):
        """Paillier暗号文のシリアライズとデシリアライズをテスト"""
        paillier = PaillierCrypto(bits=1024)
        pub, priv = paillier.generate_keys()

        # テストデータ
        data = b"This is a test for serialization."
        original_size = len(data)

        # 暗号化
        encrypted_chunks = paillier.encrypt_bytes(data, pub)

        # シリアライズ
        serialized = serialize_encrypted_data(encrypted_chunks, original_size, "paillier")

        # デシリアライズ
        deserialized_chunks, deserialized_size, crypto_type = deserialize_encrypted_data(serialized)

        # 復号
        decrypted = paillier.decrypt_bytes(deserialized_chunks, deserialized_size, priv)

        # 元のデータと一致するか確認
        self.assertEqual(data, decrypted)
        self.assertEqual(original_size, deserialized_size)
        self.assertEqual("paillier", crypto_type)

    def test_elgamal_serialization(self):
        """ElGamal暗号文のシリアライズとデシリアライズをテスト"""
        elgamal = ElGamalCrypto(bits=512)
        pub, priv = elgamal.generate_keys()

        # テストデータ
        data = b"This is a test for ElGamal serialization."
        original_size = len(data)

        # 暗号化
        encrypted_chunks = elgamal.encrypt_bytes(data, pub)

        # シリアライズ
        serialized = serialize_encrypted_data(encrypted_chunks, original_size, "elgamal")

        # デシリアライズ
        deserialized_chunks, deserialized_size, crypto_type = deserialize_encrypted_data(serialized)

        # 復号
        decrypted = elgamal.decrypt_bytes(deserialized_chunks, deserialized_size, priv)

        # 元のデータと一致するか確認
        self.assertEqual(data, decrypted)
        self.assertEqual(original_size, deserialized_size)
        self.assertEqual("elgamal", crypto_type)


def generate_homomorphic_operations_chart():
    """
    準同型演算の挙動を視覚化したチャートを生成
    """
    # 測定データ用の配列
    plaintexts = list(range(1, 11))
    addition_results = []
    multiplication_results = []

    # Paillier暗号の初期化
    paillier = PaillierCrypto(bits=1024)
    pub_p, priv_p = paillier.generate_keys()

    # ElGamal暗号の初期化
    elgamal = ElGamalCrypto(bits=512)
    pub_e, priv_e = elgamal.generate_keys()

    # 加法準同型のテスト
    base_value = 5
    base_cipher = paillier.encrypt(base_value, pub_p)

    for i in plaintexts:
        # 暗号文に定数を加算
        cipher_add = paillier.add_constant(base_cipher, i, pub_p)
        # 復号
        result_add = paillier.decrypt(cipher_add, priv_p)
        addition_results.append(result_add)

    # 乗法準同型のテスト
    base_value = 2
    base_cipher = elgamal.encrypt(base_value, pub_e)

    for i in plaintexts:
        # 暗号文の冪乗
        cipher_pow = elgamal.pow_constant(base_cipher, i, pub_e)
        # 復号
        result_pow = elgamal.decrypt(cipher_pow, priv_e)
        multiplication_results.append(result_pow)

    # プロットの作成
    plt.figure(figsize=(10, 6))

    # 加法準同型のプロット
    plt.subplot(1, 2, 1)
    plt.plot(plaintexts, addition_results, 'bo-', label='Encrypted Addition')
    plt.plot(plaintexts, [base_value + i for i in plaintexts], 'r--', label='Expected (5+x)')
    plt.xlabel('Value Added')
    plt.ylabel('Result')
    plt.title('Paillier Additive Homomorphism')
    plt.legend()
    plt.grid(True)

    # 乗法準同型のプロット
    plt.subplot(1, 2, 2)
    plt.plot(plaintexts, multiplication_results, 'go-', label='Encrypted Exponentiation')
    plt.plot(plaintexts, [base_value ** i for i in plaintexts], 'r--', label='Expected (2^x)')
    plt.xlabel('Exponent')
    plt.ylabel('Result')
    plt.title('ElGamal Multiplicative Homomorphism')
    plt.legend()
    plt.grid(True)

    plt.tight_layout()

    # 出力ディレクトリの作成
    os.makedirs("test_output", exist_ok=True)

    # 現在のタイムスタンプを取得してファイル名に使用
    timestamp = int(time.time())
    filename = f"test_output/homomorphic_operations_{timestamp}.png"

    # 画像を保存
    plt.savefig(filename)
    print(f"Chart saved as {filename}")

    return filename


if __name__ == "__main__":
    # テストの実行
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

    # 準同型演算のチャートを生成
    chart_file = generate_homomorphic_operations_chart()
    print(f"Homomorphic operations chart generated: {chart_file}")