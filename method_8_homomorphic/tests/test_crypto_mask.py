#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスク関数のテスト

このスクリプトは、準同型暗号マスク関数（CryptoMask、MaskFunctionGenerator、
AdvancedMaskFunctionGenerator）の機能をテストし、マスク適用と除去が
正しく機能することを検証します。
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
    derive_key_from_password
)
from method_8_homomorphic.crypto_mask import (
    CryptoMask, MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)


class TestCryptoMask(unittest.TestCase):
    """従来のCryptoMaskクラスのテスト"""

    def setUp(self):
        """テスト準備"""
        self.crypto_mask = CryptoMask()
        self.crypto_mask.initialize()

    def test_generate_mask_params(self):
        """マスクパラメータ生成のテスト"""
        key = os.urandom(32)
        salt = os.urandom(16)

        # マスクパラメータの生成
        mask_params = self.crypto_mask.generate_mask_params(key, salt)

        # パラメータの形式を確認
        self.assertIn('paillier', mask_params)
        self.assertIn('elgamal', mask_params)
        self.assertIn('seed', mask_params)

        # パライエパラメータの確認
        paillier_params = mask_params['paillier']
        self.assertIn('offset', paillier_params)
        self.assertIn('scale', paillier_params)
        self.assertIn('transform', paillier_params)

        # ElGamalパラメータの確認
        elgamal_params = mask_params['elgamal']
        self.assertIn('multiplier', elgamal_params)
        self.assertIn('power', elgamal_params)
        self.assertIn('transform', elgamal_params)

    def test_apply_mask_and_remove_mask(self):
        """マスクの適用と除去のテスト"""
        # テストデータ
        test_data = b"This is a test for crypto masking."

        # 鍵とソルトの生成
        key = os.urandom(32)
        salt = os.urandom(16)

        # マスクパラメータの生成
        mask_params = self.crypto_mask.generate_mask_params(key, salt)

        # マスクの適用
        masked_data = self.crypto_mask.apply_mask_to_data(test_data, mask_params)

        # 真の鍵でマスクを除去
        unmasked_true = self.crypto_mask.remove_mask_from_data(masked_data, mask_params, 'true')

        # 偽の鍵でマスクを除去
        unmasked_false = self.crypto_mask.remove_mask_from_data(masked_data, mask_params, 'false')

        # 真の鍵で復元されたデータが元のデータと一致するか検証
        self.assertEqual(test_data, unmasked_true)

        # 偽の鍵で復元されたデータが元のデータと異なるか検証
        self.assertNotEqual(test_data, unmasked_false)


class TestMaskFunctionGenerator(unittest.TestCase):
    """MaskFunctionGeneratorクラスのテスト"""

    def setUp(self):
        """テスト準備"""
        self.paillier = PaillierCrypto(bits=1024)
        public_key, private_key = self.paillier.generate_keys()
        self.paillier.public_key = public_key
        self.paillier.private_key = private_key

        # マスク関数生成器の初期化
        self.seed = os.urandom(32)
        self.mask_generator = MaskFunctionGenerator(self.paillier, self.seed)

    def test_generate_mask_pair(self):
        """マスク関数ペアの生成テスト"""
        # マスク関数ペアの生成
        true_mask, false_mask = self.mask_generator.generate_mask_pair()

        # マスクの形式の確認
        self.assertEqual("true_mask", true_mask["type"])
        self.assertEqual("false_mask", false_mask["type"])

        # シードが同じであることを確認
        self.assertEqual(true_mask["seed"], false_mask["seed"])

        # パラメータの存在確認
        self.assertIn("params", true_mask)
        self.assertIn("params", false_mask)

        # パラメータの形式確認
        for mask in [true_mask, false_mask]:
            params = mask["params"]
            self.assertIn("additive", params)
            self.assertIn("multiplicative", params)

            # リスト形式であることを確認
            self.assertIsInstance(params["additive"], list)
            self.assertIsInstance(params["multiplicative"], list)

    def test_apply_mask_and_remove_mask(self):
        """マスクの適用と除去のテスト"""
        # テストデータ（整数）
        plaintext = 42

        # 暗号化
        ciphertext = self.paillier.encrypt(plaintext, self.paillier.public_key)

        # マスク関数ペアの生成
        true_mask, false_mask = self.mask_generator.generate_mask_pair()

        # 真のマスクを適用
        masked_true = self.mask_generator.apply_mask([ciphertext], true_mask)

        # 偽のマスクを適用
        masked_false = self.mask_generator.apply_mask([ciphertext], false_mask)

        # マスク適用後の値を復号（マスクによって変更されていることを確認）
        decrypted_masked_true = self.paillier.decrypt(masked_true[0], self.paillier.private_key)
        decrypted_masked_false = self.paillier.decrypt(masked_false[0], self.paillier.private_key)

        # マスク適用後の値が元の値と異なることを確認
        self.assertNotEqual(plaintext, decrypted_masked_true)
        self.assertNotEqual(plaintext, decrypted_masked_false)

        # マスクを除去
        unmasked_true = self.mask_generator.remove_mask(masked_true, true_mask)
        unmasked_false = self.mask_generator.remove_mask(masked_false, false_mask)

        # マスク除去後の値を復号
        decrypted_unmasked_true = self.paillier.decrypt(unmasked_true[0], self.paillier.private_key)
        decrypted_unmasked_false = self.paillier.decrypt(unmasked_false[0], self.paillier.private_key)

        # マスク除去後の値が元の値と一致することを確認
        self.assertEqual(plaintext, decrypted_unmasked_true)
        self.assertEqual(plaintext, decrypted_unmasked_false)

    def test_transform_between_true_false(self):
        """真偽変換のテスト"""
        # テストデータ（バイト列）
        true_text = b"This is a true text."
        false_text = b"This is a false text."

        # バイト列を整数に変換
        true_int = int.from_bytes(true_text, 'big')
        false_int = int.from_bytes(false_text, 'big')

        # 暗号化
        true_encrypted = [self.paillier.encrypt(true_int, self.paillier.public_key)]
        false_encrypted = [self.paillier.encrypt(false_int, self.paillier.public_key)]

        # 変換
        masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
            self.paillier, true_encrypted, false_encrypted, self.mask_generator
        )

        # 区別不可能な形式に変換
        indistinguishable = create_indistinguishable_form(
            masked_true, masked_false, true_mask, false_mask
        )

        # 各鍵タイプで抽出
        for key_type in ["true", "false"]:
            chunks, mask_info = extract_by_key_type(indistinguishable, key_type)

            # シードからマスクを再生成
            seed = base64.b64decode(mask_info["seed"])
            new_mask_generator = MaskFunctionGenerator(self.paillier, seed)
            true_mask_new, false_mask_new = new_mask_generator.generate_mask_pair()

            # 鍵タイプに応じたマスクを選択
            if key_type == "true":
                mask = true_mask_new
            else:
                mask = false_mask_new

            # マスク除去
            unmasked = new_mask_generator.remove_mask(chunks, mask)

            # 復号
            decrypted_int = self.paillier.decrypt(unmasked[0], self.paillier.private_key)

            # 整数をバイト列に変換
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')

            # 期待される結果と比較
            expected = true_text if key_type == "true" else false_text
            self.assertEqual(expected, decrypted_bytes)


class TestAdvancedMaskFunctionGenerator(unittest.TestCase):
    """AdvancedMaskFunctionGeneratorクラスのテスト"""

    def setUp(self):
        """テスト準備"""
        self.paillier = PaillierCrypto(bits=1024)
        public_key, private_key = self.paillier.generate_keys()
        self.paillier.public_key = public_key
        self.paillier.private_key = private_key

        # 高度なマスク関数生成器の初期化
        self.seed = os.urandom(32)
        self.adv_mask_generator = AdvancedMaskFunctionGenerator(self.paillier, self.seed)

    def test_advanced_mask_functionality(self):
        """高度なマスク関数の機能テスト"""
        # テストデータ（整数）
        plaintext = 999

        # 暗号化
        ciphertext = self.paillier.encrypt(plaintext, self.paillier.public_key)

        # マスク関数ペアの生成
        true_mask, false_mask = self.adv_mask_generator.generate_mask_pair()

        # マスク適用
        masked_true = self.adv_mask_generator.apply_advanced_mask([ciphertext], true_mask)
        masked_false = self.adv_mask_generator.apply_advanced_mask([ciphertext], false_mask)

        # マスク除去
        unmasked_true = self.adv_mask_generator.remove_advanced_mask(masked_true, true_mask)
        unmasked_false = self.adv_mask_generator.remove_advanced_mask(masked_false, false_mask)

        # 復号
        decrypted_true = self.paillier.decrypt(unmasked_true[0], self.paillier.private_key)
        decrypted_false = self.paillier.decrypt(unmasked_false[0], self.paillier.private_key)

        # 元の値と一致することを確認
        self.assertEqual(plaintext, decrypted_true)
        self.assertEqual(plaintext, decrypted_false)


def generate_mask_effect_visualization():
    """
    マスク関数の効果を視覚化したチャートを生成
    """
    # Paillier暗号の初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # マスク関数生成器の初期化
    seed = os.urandom(32)
    mask_generator = MaskFunctionGenerator(paillier, seed)
    true_mask, false_mask = mask_generator.generate_mask_pair()

    # テストデータの範囲
    test_values = list(range(10, 60, 5))
    original_values = []
    masked_true_values = []
    masked_false_values = []

    # 各テスト値に対してマスクを適用
    for value in test_values:
        encrypted = paillier.encrypt(value, public_key)

        # 真のマスクを適用
        masked_true = mask_generator.apply_mask([encrypted], true_mask)
        decrypted_true = paillier.decrypt(masked_true[0], private_key)

        # 偽のマスクを適用
        masked_false = mask_generator.apply_mask([encrypted], false_mask)
        decrypted_false = paillier.decrypt(masked_false[0], private_key)

        original_values.append(value)
        masked_true_values.append(decrypted_true)
        masked_false_values.append(decrypted_false)

    # チャートの作成
    plt.figure(figsize=(10, 8))

    # オリジナル値とマスク適用後の値の比較
    plt.subplot(2, 1, 1)
    plt.plot(test_values, original_values, 'ko-', label='Original Values')
    plt.plot(test_values, masked_true_values, 'bo-', label='Masked (True Key)')
    plt.plot(test_values, masked_false_values, 'ro-', label='Masked (False Key)')
    plt.xlabel('Original Values')
    plt.ylabel('Value after Masking')
    plt.title('Effect of Masking on Original Values')
    plt.legend()
    plt.grid(True)

    # マスク適用の影響を示す棒グラフ
    plt.subplot(2, 1, 2)
    width = 0.35
    plt.bar([x - width/2 for x in range(len(test_values))],
            [abs(masked_true_values[i] - original_values[i]) for i in range(len(test_values))],
            width, label='True Mask Difference')
    plt.bar([x + width/2 for x in range(len(test_values))],
            [abs(masked_false_values[i] - original_values[i]) for i in range(len(test_values))],
            width, label='False Mask Difference')
    plt.xlabel('Test Value Index')
    plt.ylabel('Absolute Difference')
    plt.title('Difference between Original and Masked Values')
    plt.xticks(range(len(test_values)), test_values)
    plt.legend()
    plt.grid(True)

    plt.tight_layout()

    # 出力ディレクトリの作成
    os.makedirs("test_output", exist_ok=True)

    # 現在のタイムスタンプを取得してファイル名に使用
    timestamp = int(time.time())
    filename = f"test_output/mask_effect_visualization_{timestamp}.png"

    # 画像を保存
    plt.savefig(filename)
    print(f"Mask effect visualization saved as {filename}")

    return filename


def create_randomization_graphs():
    """
    暗号文の分布をランダム化する効果を視覚化
    """
    # Paillier暗号の初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # 同じ平文の暗号化を複数回行い分布を確認
    plaintext = 42
    samples = 100
    raw_ciphertexts = []

    for _ in range(samples):
        ciphertext = paillier.encrypt(plaintext, public_key)
        raw_ciphertexts.append(ciphertext % 1000000)  # モジュロを取って値を小さくする

    # マスク関数生成器を使用
    seed = os.urandom(32)
    mask_generator = MaskFunctionGenerator(paillier, seed)
    true_mask, false_mask = mask_generator.generate_mask_pair()

    # 同じ暗号文にマスクを適用
    ciphertext = paillier.encrypt(plaintext, public_key)
    masked_ciphertexts = []

    for _ in range(samples):
        # 毎回異なるシードでマスク生成器を作成
        new_seed = os.urandom(32)
        new_mask_generator = MaskFunctionGenerator(paillier, new_seed)
        new_true_mask, _ = new_mask_generator.generate_mask_pair()

        # マスク適用
        masked = new_mask_generator.apply_mask([ciphertext], new_true_mask)
        masked_ciphertexts.append(masked[0] % 1000000)  # モジュロを取って値を小さくする

    # チャートの作成
    plt.figure(figsize=(12, 6))

    # 通常の暗号化の分布
    plt.subplot(1, 2, 1)
    plt.hist(raw_ciphertexts, bins=20, alpha=0.7, color='blue')
    plt.xlabel('Ciphertext Value (mod 1000000)')
    plt.ylabel('Frequency')
    plt.title('Distribution of Raw Ciphertexts')
    plt.grid(True)

    # マスク適用後の分布
    plt.subplot(1, 2, 2)
    plt.hist(masked_ciphertexts, bins=20, alpha=0.7, color='green')
    plt.xlabel('Ciphertext Value (mod 1000000)')
    plt.ylabel('Frequency')
    plt.title('Distribution of Masked Ciphertexts')
    plt.grid(True)

    plt.tight_layout()

    # 出力ディレクトリの作成
    os.makedirs("test_output", exist_ok=True)

    # 現在のタイムスタンプを取得してファイル名に使用
    timestamp = int(time.time())
    filename = f"test_output/randomize_ciphertext_distribution_{timestamp}.png"

    # 画像を保存
    plt.savefig(filename)
    print(f"Ciphertext distribution chart saved as {filename}")

    return filename


if __name__ == "__main__":
    # テストの実行
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

    # 視覚化グラフの生成
    mask_chart = generate_mask_effect_visualization()
    distribution_chart = create_randomization_graphs()

    print(f"Mask effect visualization: {mask_chart}")
    print(f"Ciphertext distribution: {distribution_chart}")