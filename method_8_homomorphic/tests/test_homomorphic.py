#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号のテスト

このモジュールは、Paillier暗号（加法準同型）とElGamal暗号（乗法準同型）の
基本機能と準同型性をテストします。
"""

import unittest
import os
import sys
import random

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.homomorphic import PaillierCrypto, ElGamalCrypto


class TestPaillierCrypto(unittest.TestCase):
    """Paillier暗号（加法準同型）のテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
        self.public_key, self.private_key = self.paillier.generate_keys()

    def test_encrypt_decrypt(self):
        """暗号化と復号の基本機能テスト"""
        message = 42
        encrypted = self.paillier.encrypt(message, self.public_key)
        decrypted = self.paillier.decrypt(encrypted, self.private_key)
        self.assertEqual(message, decrypted)

    def test_homomorphic_addition(self):
        """加法準同型性テスト"""
        m1 = 15
        m2 = 27

        # 個別に暗号化
        c1 = self.paillier.encrypt(m1, self.public_key)
        c2 = self.paillier.encrypt(m2, self.public_key)

        # 暗号文同士の加算
        c_add = self.paillier.add(c1, c2, self.public_key)

        # 復号
        decrypted = self.paillier.decrypt(c_add, self.private_key)

        # 平文での加算結果と一致するか確認
        self.assertEqual(m1 + m2, decrypted)

    def test_homomorphic_scalar_multiplication(self):
        """スカラー乗算のテスト"""
        m = 13
        k = 5

        # 暗号化
        c = self.paillier.encrypt(m, self.public_key)

        # 暗号文に定数を乗算
        c_mul = self.paillier.multiply_constant(c, k, self.public_key)

        # 復号
        decrypted = self.paillier.decrypt(c_mul, self.private_key)

        # 平文での乗算結果と一致するか確認
        self.assertEqual(m * k, decrypted)

    def test_add_constant(self):
        """定数加算のテスト"""
        m = 29
        k = 16

        # 暗号化
        c = self.paillier.encrypt(m, self.public_key)

        # 暗号文に定数を加算
        c_add = self.paillier.add_constant(c, k, self.public_key)

        # 復号
        decrypted = self.paillier.decrypt(c_add, self.private_key)

        # 平文での加算結果と一致するか確認
        self.assertEqual(m + k, decrypted)

    def test_complex_operations(self):
        """複合操作のテスト"""
        m1 = 7
        m2 = 11
        k1 = 3
        k2 = 5

        # 暗号化
        c1 = self.paillier.encrypt(m1, self.public_key)
        c2 = self.paillier.encrypt(m2, self.public_key)

        # 複合操作: (m1 * k1) + (m2 * k2) = (7 * 3) + (11 * 5) = 21 + 55 = 76
        c1_mul = self.paillier.multiply_constant(c1, k1, self.public_key)
        c2_mul = self.paillier.multiply_constant(c2, k2, self.public_key)
        c_add = self.paillier.add(c1_mul, c2_mul, self.public_key)

        # 復号
        decrypted = self.paillier.decrypt(c_add, self.private_key)

        # 平文での演算結果と一致するか確認
        self.assertEqual((m1 * k1) + (m2 * k2), decrypted)

    def test_float_operations(self):
        """浮動小数点数の操作テスト"""
        m1 = 3.14
        m2 = 2.71

        # 暗号化
        c1 = self.paillier.encrypt_float(m1, self.public_key)
        c2 = self.paillier.encrypt_float(m2, self.public_key)

        # 加算
        c_add = self.paillier.add(c1, c2, self.public_key)

        # 復号
        decrypted = self.paillier.decrypt_float(c_add, self.private_key)

        # 浮動小数点の誤差を許容
        self.assertAlmostEqual(m1 + m2, decrypted, places=2)


class TestElGamalCrypto(unittest.TestCase):
    """ElGamal暗号（乗法準同型）のテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.elgamal = ElGamalCrypto(bits=512)  # テスト用に小さいビット数
        self.public_key, self.private_key = self.elgamal.generate_keys()

    def test_encrypt_decrypt(self):
        """暗号化と復号の基本機能テスト"""
        message = 42
        encrypted = self.elgamal.encrypt(message, self.public_key)
        decrypted = self.elgamal.decrypt(encrypted, self.private_key)
        self.assertEqual(message, decrypted)

    def test_homomorphic_multiplication(self):
        """乗法準同型性テスト"""
        m1 = 7
        m2 = 5

        # 個別に暗号化
        c1 = self.elgamal.encrypt(m1, self.public_key)
        c2 = self.elgamal.encrypt(m2, self.public_key)

        # 暗号文同士の乗算
        c_mul = self.elgamal.multiply(c1, c2, self.public_key)

        # 復号
        decrypted = self.elgamal.decrypt(c_mul, self.private_key)

        # 平文での乗算結果と一致するか確認
        self.assertEqual(m1 * m2, decrypted)

    def test_homomorphic_exponentiation(self):
        """指数乗のテスト"""
        m = 3
        k = 4

        # 暗号化
        c = self.elgamal.encrypt(m, self.public_key)

        # 暗号文の冪乗
        c_pow = self.elgamal.pow_constant(c, k, self.public_key)

        # 復号
        decrypted = self.elgamal.decrypt(c_pow, self.private_key)

        # 平文での指数乗結果と一致するか確認
        self.assertEqual(m ** k, decrypted)

    def test_complex_operations(self):
        """複合操作のテスト"""
        m1 = 2
        m2 = 3
        k = 2

        # 暗号化
        c1 = self.elgamal.encrypt(m1, self.public_key)
        c2 = self.elgamal.encrypt(m2, self.public_key)

        # 複合操作: (m1 * m2)^k = (2 * 3)^2 = 6^2 = 36
        c_mul = self.elgamal.multiply(c1, c2, self.public_key)
        c_pow = self.elgamal.pow_constant(c_mul, k, self.public_key)

        # 復号
        decrypted = self.elgamal.decrypt(c_pow, self.private_key)

        # 平文での演算結果と一致するか確認
        self.assertEqual((m1 * m2) ** k, decrypted)


if __name__ == '__main__':
    unittest.main()
