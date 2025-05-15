#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の単体テスト

このスクリプトは、準同型暗号マスキング方式の基本機能を
単体テストします。
"""

import os
import sys
import json
import time
import random
import hashlib
import base64
import binascii
import unittest
from typing import Dict, List, Any, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 必要なモジュールをインポート
from config import (
    TEST_OUTPUT_DIR,
    KEY_SIZE_BYTES,
    PAILLIER_KEY_BITS
)

from homomorphic import (
    PaillierCrypto,
    derive_key_from_password
)

from crypto_mask import (
    MaskFunctionGenerator,
    AdvancedMaskFunctionGenerator
)

from indistinguishable import (
    IndistinguishableWrapper
)

class HomomorphicTest(unittest.TestCase):
    """
    準同型暗号マスキング方式の単体テスト
    """

    def setUp(self):
        """テスト前の準備"""
        # テスト出力ディレクトリの作成
        os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

        # テスト用鍵の生成
        self.test_password = "test_password_for_unit_tests"
        self.master_key = derive_key_from_password(self.test_password, KEY_SIZE_BYTES)

        # 真/偽の鍵を導出
        seed = hashlib.sha256(self.master_key).digest()
        self.true_key = hashlib.pbkdf2_hmac('sha256', seed, b'true', 10000, KEY_SIZE_BYTES)
        self.false_key = hashlib.pbkdf2_hmac('sha256', seed, b'false', 10000, KEY_SIZE_BYTES)

        # Paillier暗号インスタンスの作成
        self.paillier = PaillierCrypto(key_bits=PAILLIER_KEY_BITS, key_bytes=self.master_key)

    def test_paillier_encryption_decryption(self):
        """Paillier暗号の基本的な暗号化・復号テスト"""
        print("\n=== Paillier暗号の基本テスト ===")

        # テスト値
        test_value = 12345

        # 暗号化
        encrypted = self.paillier.encrypt(test_value)
        self.assertIsNotNone(encrypted)
        self.assertNotEqual(encrypted, test_value)

        # 復号
        decrypted = self.paillier.decrypt(encrypted)
        self.assertEqual(decrypted, test_value)

        print(f"✅ 暗号化・復号テスト成功: {test_value} → {encrypted} → {decrypted}")

    def test_paillier_homomorphic_addition(self):
        """Paillier暗号の準同型加算テスト"""
        print("\n=== Paillier暗号の準同型加算テスト ===")

        # テスト値
        a = 42
        b = 73
        expected_sum = a + b

        # 暗号化
        encrypted_a = self.paillier.encrypt(a)
        encrypted_b = self.paillier.encrypt(b)

        # 暗号文同士の加算
        encrypted_sum = self.paillier.add(encrypted_a, encrypted_b)

        # 復号
        decrypted_sum = self.paillier.decrypt(encrypted_sum)

        # 検証
        self.assertEqual(decrypted_sum, expected_sum)

        print(f"✅ 準同型加算テスト成功: {a} + {b} = {decrypted_sum}")

    def test_paillier_homomorphic_multiplication(self):
        """Paillier暗号の準同型乗算テスト（スカラー倍）"""
        print("\n=== Paillier暗号の準同型乗算テスト ===")

        # テスト値
        a = 7
        k = 6
        expected_product = a * k

        # 暗号化
        encrypted_a = self.paillier.encrypt(a)

        # 暗号文と平文定数の乗算
        encrypted_product = self.paillier.multiply(encrypted_a, k)

        # 復号
        decrypted_product = self.paillier.decrypt(encrypted_product)

        # 検証
        self.assertEqual(decrypted_product, expected_product)

        print(f"✅ 準同型乗算テスト成功: {a} × {k} = {decrypted_product}")

    def test_paillier_float_encryption(self):
        """Paillier暗号の浮動小数点数暗号化テスト"""
        print("\n=== Paillier暗号の浮動小数点数テスト ===")

        # テスト値
        test_float = 3.14159
        precision = 5

        # 暗号化
        encrypted = self.paillier.encrypt_float(test_float, precision)

        # 復号
        decrypted = self.paillier.decrypt_float(encrypted, precision)

        # 誤差許容範囲での検証
        self.assertAlmostEqual(decrypted, test_float, places=precision-1)

        print(f"✅ 浮動小数点数テスト成功: {test_float} → {decrypted}")

    def test_paillier_serialization(self):
        """Paillier暗号の鍵シリアライズテスト"""
        print("\n=== Paillier暗号の鍵シリアライズテスト ===")

        # 鍵のシリアライズ
        serialized_public = self.paillier.serialize_public_key()
        serialized_private = self.paillier.serialize_private_key()

        # 新しいインスタンスを作成
        new_paillier = PaillierCrypto(key_bits=PAILLIER_KEY_BITS)

        # シリアライズされた鍵をロード
        new_paillier.load_serialized_public_key(serialized_public)
        new_paillier.load_serialized_private_key(serialized_private)

        # テスト値
        test_value = 54321

        # 元のインスタンスで暗号化
        encrypted = self.paillier.encrypt(test_value)

        # 新しいインスタンスで復号
        decrypted = new_paillier.decrypt(encrypted)

        # 検証
        self.assertEqual(decrypted, test_value)

        print(f"✅ 鍵シリアライズテスト成功: {test_value} → {encrypted} → {decrypted}")

    def test_mask_function(self):
        """マスク関数のテスト"""
        print("\n=== マスク関数テスト ===")

        # 基本マスク関数
        mask_gen = MaskFunctionGenerator(self.true_key)
        mask_func = mask_gen.generate_mask_function()

        # テスト値
        test_value = 98765

        # マスク適用
        masked = mask_func.mask(test_value)

        # マスク除去
        unmasked = mask_func.unmask(masked)

        # 検証
        self.assertEqual(unmasked, test_value)

        print(f"✅ 基本マスク関数テスト成功: {test_value} → {masked} → {unmasked}")

        # 高度なマスク関数
        adv_mask_gen = AdvancedMaskFunctionGenerator(self.true_key)
        adv_mask_func = adv_mask_gen.generate_mask_function()

        # マスク適用
        adv_masked = adv_mask_func.mask(test_value)

        # マスク除去
        adv_unmasked = adv_mask_func.unmask(adv_masked)

        # 検証
        self.assertEqual(adv_unmasked, test_value)

        print(f"✅ 高度マスク関数テスト成功: {test_value} → {adv_masked} → {adv_unmasked}")

    def test_indistinguishable_wrapper(self):
        """IndistinguishableWrapperのテスト"""
        print("\n=== 識別不能性ラッパーテスト ===")

        # ラッパーの作成
        wrapper = IndistinguishableWrapper()

        # シードの生成
        seed = wrapper.generate_seed(self.true_key, b'salt')
        self.assertIsNotNone(seed)

        # データの難読化
        test_data = b"This is a test string for obfuscation"
        obfuscated = wrapper.obfuscate_data(test_data)

        # 難読化の検証
        self.assertNotEqual(obfuscated, test_data)

        # 難読化の解除
        deobfuscated = wrapper.deobfuscate_data(obfuscated)

        # 検証
        self.assertEqual(deobfuscated, test_data)

        print(f"✅ 識別不能性ラッパーテスト成功")
        print(f"   元データ: {test_data}")
        print(f"   難読化: {obfuscated[:50]}...")
        print(f"   元に戻す: {deobfuscated}")

    def test_time_equalizer(self):
        """時間均等化機能のテスト"""
        print("\n=== 時間均等化テスト ===")

        wrapper = IndistinguishableWrapper()

        # 早く終わる関数
        def fast_function():
            return "Fast result"

        # 遅い関数
        def slow_function():
            time.sleep(0.1)
            return "Slow result"

        # 時間計測
        start_fast = time.time()
        fast_result = wrapper.time_equalizer(fast_function)
        fast_time = time.time() - start_fast

        start_slow = time.time()
        slow_result = wrapper.time_equalizer(slow_function)
        slow_time = time.time() - start_slow

        # 結果の検証
        self.assertEqual(fast_result, "Fast result")
        self.assertEqual(slow_result, "Slow result")

        # 最小実行時間の検証
        self.assertGreaterEqual(fast_time, 0.05)  # 最小50msの待機

        print(f"✅ 時間均等化テスト成功")
        print(f"   高速関数の実行時間: {fast_time:.4f}秒")
        print(f"   低速関数の実行時間: {slow_time:.4f}秒")

def main():
    """単体テストを実行"""
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

if __name__ == "__main__":
    print("===== 準同型暗号マスキング方式の単体テスト =====")
    print(f"テスト開始時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # 単体テストを実行
    main()

    print(f"\nテスト終了時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("===== テスト完了 =====")