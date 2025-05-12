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
import time
import matplotlib.pyplot as plt
import numpy as np

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, save_keys, load_keys,
    serialize_encrypted_data, deserialize_encrypted_data
)


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

    def test_binary_data(self):
        """バイナリデータの暗号化と復号テスト"""
        original_data = b"Hello, Homomorphic Encryption! \xf0\x9f\x94\x92"

        # バイナリデータの暗号化
        encrypted_chunks = self.paillier.encrypt_bytes(original_data, self.public_key)

        # 暗号化されたデータの復号
        decrypted_data = self.paillier.decrypt_bytes(encrypted_chunks, len(original_data), self.private_key)

        # 元のデータと一致するか確認
        self.assertEqual(original_data, decrypted_data)

    def test_key_save_load(self):
        """鍵の保存と読み込みテスト"""
        # 一時ファイルパス
        public_key_file = "test_output/paillier_public.json"
        private_key_file = "test_output/paillier_private.json"

        # 鍵の保存
        self.paillier.save_keys(public_key_file, private_key_file)

        # 新しいインスタンスで鍵を読み込み
        new_paillier = PaillierCrypto()
        new_paillier.load_keys(public_key_file, private_key_file)

        # 元のメッセージ
        message = 42

        # 元のインスタンスで暗号化
        encrypted = self.paillier.encrypt(message, self.public_key)

        # 新しいインスタンスで復号
        decrypted = new_paillier.decrypt(encrypted, new_paillier.private_key)

        # 結果が一致するか確認
        self.assertEqual(message, decrypted)


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

    def test_binary_data(self):
        """バイナリデータの暗号化と復号テスト"""
        original_data = b"Hello, Homomorphic Encryption! \xf0\x9f\x94\x92"

        # バイナリデータの暗号化
        encrypted_chunks = self.elgamal.encrypt_bytes(original_data, self.public_key)

        # 暗号化されたデータの復号
        decrypted_data = self.elgamal.decrypt_bytes(encrypted_chunks, len(original_data), self.private_key)

        # 元のデータと一致するか確認
        self.assertEqual(original_data, decrypted_data)

    def test_key_save_load(self):
        """鍵の保存と読み込みテスト"""
        # 一時ファイルパス
        public_key_file = "test_output/elgamal_public.json"
        private_key_file = "test_output/elgamal_private.json"

        # 鍵の保存
        self.elgamal.save_keys(public_key_file, private_key_file)

        # 新しいインスタンスで鍵を読み込み
        new_elgamal = ElGamalCrypto()
        new_elgamal.load_keys(public_key_file, private_key_file)

        # 元のメッセージ
        message = 42

        # 元のインスタンスで暗号化
        encrypted = self.elgamal.encrypt(message, self.public_key)

        # 新しいインスタンスで復号
        decrypted = new_elgamal.decrypt(encrypted, new_elgamal.private_key)

        # 結果が一致するか確認
        self.assertEqual(message, decrypted)


class TestKeyDerivation(unittest.TestCase):
    """鍵導出機能のテスト"""

    def test_password_based_key_derivation(self):
        """パスワードからの鍵導出テスト"""
        password = "secure_password_123"
        # 固定のソルトを使用してテストの再現性を確保
        salt = b'fixed_salt_12345'

        # PBKDFから導出したキーでの暗号化と復号をテスト
        pub1, priv1, _ = derive_key_from_password(password, salt, "paillier")

        # Paillierインスタンスを作成し鍵をセット
        paillier = PaillierCrypto()
        paillier.public_key = pub1
        paillier.private_key = priv1

        # 暗号化と復号のテスト
        message = 42
        encrypted = paillier.encrypt(message, pub1)
        decrypted = paillier.decrypt(encrypted, priv1)

        # 復号結果が元のメッセージと一致するか確認
        self.assertEqual(message, decrypted)

        # ElGamal暗号での鍵導出テスト
        pub_el, priv_el, _ = derive_key_from_password(password, salt, "elgamal")

        # ElGamalインスタンスを作成し鍵をセット
        elgamal = ElGamalCrypto()
        elgamal.public_key = pub_el
        elgamal.private_key = priv_el

        # 暗号化と復号のテスト
        message = 42
        encrypted = elgamal.encrypt(message, pub_el)
        decrypted = elgamal.decrypt(encrypted, priv_el)

        # 復号結果が元のメッセージと一致するか確認
        self.assertEqual(message, decrypted)

    def test_serialization(self):
        """シリアライズとデシリアライズのテスト"""
        # Paillier暗号でのテスト
        paillier = PaillierCrypto(bits=1024)
        public_key, private_key = paillier.generate_keys()

        # テストデータ
        test_data = b"Testing serialization and deserialization"

        # 暗号化
        encrypted_chunks = paillier.encrypt_bytes(test_data, public_key)

        # シリアライズ
        serialized = serialize_encrypted_data(encrypted_chunks, len(test_data), "paillier")

        # デシリアライズ
        deserialized_chunks, original_size, crypto_type = deserialize_encrypted_data(serialized)

        # デシリアライズしたデータで復号
        decrypted_data = paillier.decrypt_bytes(deserialized_chunks, original_size, private_key)

        # 元のデータと一致するか確認
        self.assertEqual(test_data, decrypted_data)
        self.assertEqual(crypto_type, "paillier")


class TestPerformance(unittest.TestCase):
    """準同型暗号のパフォーマンステスト"""

    def setUp(self):
        """テスト前の準備"""
        # テスト用に小さいビット数
        self.paillier_sizes = [512, 1024]
        self.elgamal_sizes = [256, 512]

        # 各操作の実行時間を記録
        self.paillier_times = {size: {'encrypt': [], 'decrypt': [], 'add': [], 'mul_const': []}
                              for size in self.paillier_sizes}
        self.elgamal_times = {size: {'encrypt': [], 'decrypt': [], 'multiply': [], 'pow_const': []}
                             for size in self.elgamal_sizes}

    def test_paillier_performance(self):
        """Paillier暗号のパフォーマンステスト"""
        num_trials = 10  # 各テストの試行回数

        for size in self.paillier_sizes:
            paillier = PaillierCrypto(bits=size)
            public_key, private_key = paillier.generate_keys()

            for _ in range(num_trials):
                message = random.randint(1, 10000)

                # 暗号化の時間測定
                start_time = time.time()
                encrypted = paillier.encrypt(message, public_key)
                self.paillier_times[size]['encrypt'].append(time.time() - start_time)

                # 復号の時間測定
                start_time = time.time()
                _ = paillier.decrypt(encrypted, private_key)
                self.paillier_times[size]['decrypt'].append(time.time() - start_time)

                # もう一つのメッセージを暗号化
                message2 = random.randint(1, 10000)
                encrypted2 = paillier.encrypt(message2, public_key)

                # 加算の時間測定
                start_time = time.time()
                _ = paillier.add(encrypted, encrypted2, public_key)
                self.paillier_times[size]['add'].append(time.time() - start_time)

                # 定数倍の時間測定
                constant = random.randint(1, 100)
                start_time = time.time()
                _ = paillier.multiply_constant(encrypted, constant, public_key)
                self.paillier_times[size]['mul_const'].append(time.time() - start_time)

    def test_elgamal_performance(self):
        """ElGamal暗号のパフォーマンステスト"""
        num_trials = 10  # 各テストの試行回数

        for size in self.elgamal_sizes:
            elgamal = ElGamalCrypto(bits=size)
            public_key, private_key = elgamal.generate_keys()

            for _ in range(num_trials):
                message = random.randint(1, 1000)

                # 暗号化の時間測定
                start_time = time.time()
                encrypted = elgamal.encrypt(message, public_key)
                self.elgamal_times[size]['encrypt'].append(time.time() - start_time)

                # 復号の時間測定
                start_time = time.time()
                _ = elgamal.decrypt(encrypted, private_key)
                self.elgamal_times[size]['decrypt'].append(time.time() - start_time)

                # もう一つのメッセージを暗号化
                message2 = random.randint(1, 1000)
                encrypted2 = elgamal.encrypt(message2, public_key)

                # 乗算の時間測定
                start_time = time.time()
                _ = elgamal.multiply(encrypted, encrypted2, public_key)
                self.elgamal_times[size]['multiply'].append(time.time() - start_time)

                # 指数乗の時間測定
                exponent = random.randint(1, 10)
                start_time = time.time()
                _ = elgamal.pow_constant(encrypted, exponent, public_key)
                self.elgamal_times[size]['pow_const'].append(time.time() - start_time)

    def test_generate_performance_graph(self):
        """パフォーマンスグラフの生成"""
        # Paillierのパフォーマンステスト
        self.test_paillier_performance()

        # ElGamalのパフォーマンステスト
        self.test_elgamal_performance()

        # 結果の平均を計算
        paillier_avg = {size: {op: np.mean(times) for op, times in ops.items()}
                       for size, ops in self.paillier_times.items()}
        elgamal_avg = {size: {op: np.mean(times) for op, times in ops.items()}
                      for size, ops in self.elgamal_times.items()}

        # グラフのプロット
        plt.figure(figsize=(14, 10))

        # Paillierのパフォーマンスグラフ
        plt.subplot(2, 1, 1)
        bar_width = 0.15
        index = np.arange(len(self.paillier_sizes))

        for i, op in enumerate(['encrypt', 'decrypt', 'add', 'mul_const']):
            values = [paillier_avg[size][op] * 1000 for size in self.paillier_sizes]  # ミリ秒に変換
            plt.bar(index + i * bar_width, values, bar_width, label=op)

        plt.title('Paillier Cryptosystem Performance')
        plt.xlabel('Key Size (bits)')
        plt.ylabel('Execution Time (ms)')
        plt.xticks(index + bar_width * 1.5, self.paillier_sizes)
        plt.legend()
        plt.grid(True, alpha=0.3)

        # ElGamalのパフォーマンスグラフ
        plt.subplot(2, 1, 2)
        index = np.arange(len(self.elgamal_sizes))

        for i, op in enumerate(['encrypt', 'decrypt', 'multiply', 'pow_const']):
            values = [elgamal_avg[size][op] * 1000 for size in self.elgamal_sizes]  # ミリ秒に変換
            plt.bar(index + i * bar_width, values, bar_width, label=op)

        plt.title('ElGamal Cryptosystem Performance')
        plt.xlabel('Key Size (bits)')
        plt.ylabel('Execution Time (ms)')
        plt.xticks(index + bar_width * 1.5, self.elgamal_sizes)
        plt.legend()
        plt.grid(True, alpha=0.3)

        plt.tight_layout()

        # グラフの保存
        plt.savefig("test_output/cryptography_performance.png")

        # グラフが生成されていることを確認
        self.assertTrue(os.path.exists("test_output/cryptography_performance.png"))


if __name__ == '__main__':
    unittest.main()
