#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の暗号化・復号統合テスト

このスクリプトは、準同型暗号マスキング方式の暗号化と復号の統合機能を
テストします。実際のファイルを使用して機能を検証し、様々なテキストサイズや
エッジケースを含みます。
"""

import os
import sys
import time
import json
import random
import hashlib
import base64
import binascii
import unittest
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any, List, Tuple, Union
import tempfile
import shutil

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, serialize_encrypted_data, deserialize_encrypted_data
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)
from method_8_homomorphic.key_analyzer_robust import analyze_key_type
from method_8_homomorphic.encrypt import encrypt_file
from method_8_homomorphic.decrypt import decrypt_file


class TestEncryptDecryptIntegration(unittest.TestCase):
    """暗号化・復号の統合テスト"""

    def setUp(self):
        """テスト前の準備"""
        # テスト出力ディレクトリの作成
        os.makedirs("test_output", exist_ok=True)

        # テスト用一時ディレクトリの作成
        self.temp_dir = tempfile.mkdtemp()

        # テスト用のファイルパス
        self.test_file_true = os.path.join(self.temp_dir, "test_true.txt")
        self.test_file_false = os.path.join(self.temp_dir, "test_false.txt")
        self.encrypted_file = os.path.join(self.temp_dir, "encrypted.hcm")

        # テスト用のキーパス
        self.true_key_path = os.path.join(self.temp_dir, "true_key.key")
        self.false_key_path = os.path.join(self.temp_dir, "false_key.key")

        # テスト用のデータを作成
        self.test_data_true = "This is a true message with important information.\n" * 5
        self.test_data_false = "This is a false message with misleading information.\n" * 5

        # テストファイルの書き込み
        with open(self.test_file_true, 'w') as f:
            f.write(self.test_data_true)

        with open(self.test_file_false, 'w') as f:
            f.write(self.test_data_false)

        # パスワード
        self.password = "test_password_secure_123"

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # テスト用一時ディレクトリの削除
        shutil.rmtree(self.temp_dir)

    def test_basic_encrypt_decrypt(self):
        """基本的な暗号化・復号のテスト"""
        # 暗号化の実行
        encrypt_result = encrypt_file(
            input_file=self.test_file_true,
            true_text_file=self.test_file_true,
            false_text_file=self.test_file_false,
            output_file=self.encrypted_file,
            true_key_file=self.true_key_path,
            false_key_file=self.false_key_path,
            password=self.password,
            crypto_type="paillier",
            bits=1024
        )

        self.assertTrue(encrypt_result["success"])
        self.assertTrue(os.path.exists(self.encrypted_file))

        # true_keyでの復号
        true_output_file = os.path.join(self.temp_dir, "decrypted_true.txt")
        true_decrypt_result = decrypt_file(
            input_file=self.encrypted_file,
            output_file=true_output_file,
            key_type="true",
            key_file=self.true_key_path,
            password=self.password
        )

        self.assertTrue(true_decrypt_result["success"])

        # false_keyでの復号
        false_output_file = os.path.join(self.temp_dir, "decrypted_false.txt")
        false_decrypt_result = decrypt_file(
            input_file=self.encrypted_file,
            output_file=false_output_file,
            key_type="false",
            key_file=self.false_key_path,
            password=self.password
        )

        self.assertTrue(false_decrypt_result["success"])

        # 復号結果の検証
        with open(true_output_file, 'r') as f:
            true_decrypted = f.read()

        with open(false_output_file, 'r') as f:
            false_decrypted = f.read()

        # 正しく復号できているか確認
        self.assertEqual(self.test_data_true, true_decrypted)
        self.assertEqual(self.test_data_false, false_decrypted)

    def test_different_crypto_types(self):
        """異なる暗号タイプでのテスト"""
        for crypto_type in ["paillier", "elgamal"]:
            # ファイルパスをクリア
            encrypted_file = os.path.join(self.temp_dir, f"encrypted_{crypto_type}.hcm")
            true_key_path = os.path.join(self.temp_dir, f"true_key_{crypto_type}.key")
            false_key_path = os.path.join(self.temp_dir, f"false_key_{crypto_type}.key")

            # 暗号化の実行
            encrypt_result = encrypt_file(
                input_file=self.test_file_true,
                true_text_file=self.test_file_true,
                false_text_file=self.test_file_false,
                output_file=encrypted_file,
                true_key_file=true_key_path,
                false_key_file=false_key_path,
                password=self.password,
                crypto_type=crypto_type,
                bits=1024 if crypto_type == "paillier" else 512
            )

            self.assertTrue(encrypt_result["success"])

            # true_keyでの復号
            true_output_file = os.path.join(self.temp_dir, f"decrypted_true_{crypto_type}.txt")
            true_decrypt_result = decrypt_file(
                input_file=encrypted_file,
                output_file=true_output_file,
                key_type="true",
                key_file=true_key_path,
                password=self.password
            )

            self.assertTrue(true_decrypt_result["success"])

            # false_keyでの復号
            false_output_file = os.path.join(self.temp_dir, f"decrypted_false_{crypto_type}.txt")
            false_decrypt_result = decrypt_file(
                input_file=encrypted_file,
                output_file=false_output_file,
                key_type="false",
                key_file=false_key_path,
                password=self.password
            )

            self.assertTrue(false_decrypt_result["success"])

            # 復号結果の検証
            with open(true_output_file, 'r') as f:
                true_decrypted = f.read()

            with open(false_output_file, 'r') as f:
                false_decrypted = f.read()

            # 正しく復号できているか確認
            self.assertEqual(self.test_data_true, true_decrypted, f"Failed with {crypto_type}")
            self.assertEqual(self.test_data_false, false_decrypted, f"Failed with {crypto_type}")

    def test_file_sizes(self):
        """様々なファイルサイズでのテスト"""
        sizes = [100, 1000, 10000]  # バイト単位
        results = []

        for size in sizes:
            # テスト用のファイルを作成
            large_true_file = os.path.join(self.temp_dir, f"large_true_{size}.txt")
            large_false_file = os.path.join(self.temp_dir, f"large_false_{size}.txt")

            # ランダムテキストの生成
            true_text = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ') for _ in range(size))
            false_text = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ') for _ in range(size))

            with open(large_true_file, 'w') as f:
                f.write(true_text)

            with open(large_false_file, 'w') as f:
                f.write(false_text)

            # 暗号化ファイルパス
            encrypted_file = os.path.join(self.temp_dir, f"encrypted_size_{size}.hcm")
            true_key_path = os.path.join(self.temp_dir, f"true_key_size_{size}.key")
            false_key_path = os.path.join(self.temp_dir, f"false_key_size_{size}.key")

            # 時間計測開始
            start_time = time.time()

            # 暗号化の実行
            encrypt_result = encrypt_file(
                input_file=large_true_file,
                true_text_file=large_true_file,
                false_text_file=large_false_file,
                output_file=encrypted_file,
                true_key_file=true_key_path,
                false_key_file=false_key_path,
                password=self.password,
                crypto_type="paillier",
                bits=1024
            )

            # 暗号化時間
            encrypt_time = time.time() - start_time

            # 暗号化ファイルサイズ
            encrypted_size = os.path.getsize(encrypted_file)

            # true_keyでの復号
            true_output_file = os.path.join(self.temp_dir, f"decrypted_true_size_{size}.txt")

            # 時間計測開始
            start_time = time.time()

            true_decrypt_result = decrypt_file(
                input_file=encrypted_file,
                output_file=true_output_file,
                key_type="true",
                key_file=true_key_path,
                password=self.password
            )

            # 復号時間
            decrypt_time = time.time() - start_time

            # 復号結果の検証
            with open(true_output_file, 'r') as f:
                true_decrypted = f.read()

            # 結果を記録
            results.append({
                "original_size": size,
                "encrypted_size": encrypted_size,
                "size_ratio": encrypted_size / size,
                "encrypt_time": encrypt_time,
                "decrypt_time": decrypt_time,
                "encryption_speed": size / encrypt_time if encrypt_time > 0 else float('inf'),  # バイト/秒
                "decryption_speed": size / decrypt_time if decrypt_time > 0 else float('inf'),  # バイト/秒
                "success": true_text == true_decrypted
            })

            # 正しく復号できているか確認
            self.assertEqual(true_text, true_decrypted)

        # 結果の可視化
        self.visualize_performance_results(results)

    def test_edge_cases(self):
        """エッジケースのテスト"""
        # 空のファイル
        empty_true_file = os.path.join(self.temp_dir, "empty_true.txt")
        empty_false_file = os.path.join(self.temp_dir, "empty_false.txt")

        with open(empty_true_file, 'w') as f:
            f.write("")

        with open(empty_false_file, 'w') as f:
            f.write("")

        # 暗号化ファイルパス
        encrypted_file = os.path.join(self.temp_dir, "encrypted_empty.hcm")
        true_key_path = os.path.join(self.temp_dir, "true_key_empty.key")
        false_key_path = os.path.join(self.temp_dir, "false_key_empty.key")

        # 空ファイルの暗号化
        encrypt_result = encrypt_file(
            input_file=empty_true_file,
            true_text_file=empty_true_file,
            false_text_file=empty_false_file,
            output_file=encrypted_file,
            true_key_file=true_key_path,
            false_key_file=false_key_path,
            password=self.password,
            crypto_type="paillier",
            bits=1024
        )

        self.assertTrue(encrypt_result["success"])

        # true_keyでの復号
        true_output_file = os.path.join(self.temp_dir, "decrypted_true_empty.txt")
        true_decrypt_result = decrypt_file(
            input_file=encrypted_file,
            output_file=true_output_file,
            key_type="true",
            key_file=true_key_path,
            password=self.password
        )

        self.assertTrue(true_decrypt_result["success"])

        # 復号結果の検証
        with open(true_output_file, 'r') as f:
            true_decrypted = f.read()

        # 正しく復号できているか確認（空ファイル）
        self.assertEqual("", true_decrypted)

        # 特殊文字を含むファイル
        special_true_file = os.path.join(self.temp_dir, "special_true.txt")
        special_false_file = os.path.join(self.temp_dir, "special_false.txt")

        special_chars = "!@#$%^&*()_+{}|:\"<>?[]\\;',./~`\n\t"

        with open(special_true_file, 'w') as f:
            f.write(f"Special characters: {special_chars}")

        with open(special_false_file, 'w') as f:
            f.write(f"Different special chars: {special_chars[::-1]}")

        # 暗号化ファイルパス
        encrypted_file = os.path.join(self.temp_dir, "encrypted_special.hcm")
        true_key_path = os.path.join(self.temp_dir, "true_key_special.key")
        false_key_path = os.path.join(self.temp_dir, "false_key_special.key")

        # 特殊文字ファイルの暗号化
        encrypt_result = encrypt_file(
            input_file=special_true_file,
            true_text_file=special_true_file,
            false_text_file=special_false_file,
            output_file=encrypted_file,
            true_key_file=true_key_path,
            false_key_file=false_key_path,
            password=self.password,
            crypto_type="paillier",
            bits=1024
        )

        self.assertTrue(encrypt_result["success"])

        # true_keyでの復号
        true_output_file = os.path.join(self.temp_dir, "decrypted_true_special.txt")
        true_decrypt_result = decrypt_file(
            input_file=encrypted_file,
            output_file=true_output_file,
            key_type="true",
            key_file=true_key_path,
            password=self.password
        )

        self.assertTrue(true_decrypt_result["success"])

        # 復号結果の検証
        with open(true_output_file, 'r') as f:
            true_decrypted = f.read()

        # 特殊文字を含むファイルが正しく復号できているか確認
        with open(special_true_file, 'r') as f:
            special_true_content = f.read()

        self.assertEqual(special_true_content, true_decrypted)

    def test_error_handling(self):
        """エラー処理のテスト"""
        # 不正なファイルパス
        invalid_file = os.path.join(self.temp_dir, "non_existent_file.txt")

        # 存在しないファイルの暗号化
        with self.assertRaises(Exception):
            encrypt_result = encrypt_file(
                input_file=invalid_file,
                true_text_file=self.test_file_true,
                false_text_file=self.test_file_false,
                output_file=self.encrypted_file,
                true_key_file=self.true_key_path,
                false_key_file=self.false_key_path,
                password=self.password,
                crypto_type="paillier",
                bits=1024
            )

        # 正しい暗号化を実行
        encrypt_result = encrypt_file(
            input_file=self.test_file_true,
            true_text_file=self.test_file_true,
            false_text_file=self.test_file_false,
            output_file=self.encrypted_file,
            true_key_file=self.true_key_path,
            false_key_file=self.false_key_path,
            password=self.password,
            crypto_type="paillier",
            bits=1024
        )

        # 不正なパスワードでの復号
        wrong_output_file = os.path.join(self.temp_dir, "decrypted_wrong.txt")

        with self.assertRaises(Exception):
            decrypt_result = decrypt_file(
                input_file=self.encrypted_file,
                output_file=wrong_output_file,
                key_type="true",
                key_file=self.true_key_path,
                password="wrong_password"
            )

        # 不正な鍵タイプでの復号
        with self.assertRaises(Exception):
            decrypt_result = decrypt_file(
                input_file=self.encrypted_file,
                output_file=wrong_output_file,
                key_type="invalid_type",
                key_file=self.true_key_path,
                password=self.password
            )

    def visualize_performance_results(self, results):
        """パフォーマンステスト結果の可視化"""
        plt.figure(figsize=(15, 10))

        # サイズ比率のプロット
        plt.subplot(2, 2, 1)
        sizes = [r["original_size"] for r in results]
        ratios = [r["size_ratio"] for r in results]
        plt.bar(range(len(sizes)), ratios)
        plt.xlabel('Original Size (bytes)')
        plt.ylabel('Size Ratio (encrypted/original)')
        plt.title('Encryption Size Overhead')
        plt.xticks(range(len(sizes)), sizes)
        plt.grid(True)

        # 暗号化時間のプロット
        plt.subplot(2, 2, 2)
        encrypt_times = [r["encrypt_time"] for r in results]
        plt.bar(range(len(sizes)), encrypt_times)
        plt.xlabel('Original Size (bytes)')
        plt.ylabel('Encryption Time (seconds)')
        plt.title('Encryption Time')
        plt.xticks(range(len(sizes)), sizes)
        plt.grid(True)

        # 復号時間のプロット
        plt.subplot(2, 2, 3)
        decrypt_times = [r["decrypt_time"] for r in results]
        plt.bar(range(len(sizes)), decrypt_times)
        plt.xlabel('Original Size (bytes)')
        plt.ylabel('Decryption Time (seconds)')
        plt.title('Decryption Time')
        plt.xticks(range(len(sizes)), sizes)
        plt.grid(True)

        # 速度のプロット
        plt.subplot(2, 2, 4)
        encrypt_speeds = [r["encryption_speed"] for r in results]
        decrypt_speeds = [r["decryption_speed"] for r in results]

        x = np.arange(len(sizes))
        width = 0.35

        plt.bar(x - width/2, encrypt_speeds, width, label='Encryption Speed')
        plt.bar(x + width/2, decrypt_speeds, width, label='Decryption Speed')

        plt.xlabel('Original Size (bytes)')
        plt.ylabel('Speed (bytes/second)')
        plt.title('Processing Speed')
        plt.xticks(x, sizes)
        plt.legend()
        plt.grid(True)

        plt.tight_layout()

        # 出力ディレクトリの作成
        os.makedirs("test_output", exist_ok=True)

        # 現在のタイムスタンプを取得してファイル名に使用
        timestamp = int(time.time())
        filename = f"test_output/encrypt_decrypt_performance_{timestamp}.png"

        # 画像を保存
        plt.savefig(filename)
        print(f"Performance visualization saved as {filename}")

        # JSONにも保存
        json_filename = f"test_output/encrypt_decrypt_performance_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(results, f, indent=2)

        return filename, json_filename


class TestRealFileEncryptDecrypt(unittest.TestCase):
    """実際のテキストファイルを使用した暗号化・復号テスト"""

    def setUp(self):
        """テスト前の準備"""
        # テスト出力ディレクトリの作成
        os.makedirs("test_output", exist_ok=True)

        # 実際のテキストファイルパス
        self.true_text_file = "common/true-false-text/true.text"
        self.false_text_file = "common/true-false-text/false.text"

        # テスト用一時ディレクトリの作成
        self.temp_dir = tempfile.mkdtemp()

        # テスト用のファイルパス
        self.encrypted_file = os.path.join(self.temp_dir, "encrypted_real.hcm")
        self.true_key_path = os.path.join(self.temp_dir, "true_key_real.key")
        self.false_key_path = os.path.join(self.temp_dir, "false_key_real.key")

        # パスワード
        self.password = "test_real_password_secure_456"

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # テスト用一時ディレクトリの削除
        shutil.rmtree(self.temp_dir)

    def test_real_file_encrypt_decrypt(self):
        """実際のファイルでの暗号化・復号テスト"""
        # 暗号化の実行
        encrypt_result = encrypt_file(
            input_file=self.true_text_file,
            true_text_file=self.true_text_file,
            false_text_file=self.false_text_file,
            output_file=self.encrypted_file,
            true_key_file=self.true_key_path,
            false_key_file=self.false_key_path,
            password=self.password,
            crypto_type="paillier",
            bits=1024
        )

        self.assertTrue(encrypt_result["success"])

        # true_keyでの復号
        true_output_file = os.path.join(self.temp_dir, "decrypted_true_real.txt")
        true_decrypt_result = decrypt_file(
            input_file=self.encrypted_file,
            output_file=true_output_file,
            key_type="true",
            key_file=self.true_key_path,
            password=self.password
        )

        self.assertTrue(true_decrypt_result["success"])

        # false_keyでの復号
        false_output_file = os.path.join(self.temp_dir, "decrypted_false_real.txt")
        false_decrypt_result = decrypt_file(
            input_file=self.encrypted_file,
            output_file=false_output_file,
            key_type="false",
            key_file=self.false_key_path,
            password=self.password
        )

        self.assertTrue(false_decrypt_result["success"])

        # 復号結果の検証
        with open(true_output_file, 'r') as f:
            true_decrypted = f.read()

        with open(false_output_file, 'r') as f:
            false_decrypted = f.read()

        with open(self.true_text_file, 'r') as f:
            original_true = f.read()

        with open(self.false_text_file, 'r') as f:
            original_false = f.read()

        # 正しく復号できているか確認
        self.assertEqual(original_true, true_decrypted)
        self.assertEqual(original_false, false_decrypted)

        # 結果の図式化
        self.visualize_real_file_test_results(
            original_true, original_false,
            true_decrypted, false_decrypted,
            encrypt_result, true_decrypt_result, false_decrypt_result
        )

    def visualize_real_file_test_results(self, original_true, original_false,
                                        true_decrypted, false_decrypted,
                                        encrypt_result, true_decrypt_result, false_decrypt_result):
        """実際のファイルテスト結果の可視化"""
        # テキスト比較レポートの作成
        report = {
            "original_true_length": len(original_true),
            "original_false_length": len(original_false),
            "true_decrypted_length": len(true_decrypted),
            "false_decrypted_length": len(false_decrypted),

            "true_match": original_true == true_decrypted,
            "false_match": original_false == false_decrypted,

            "encryption_time": encrypt_result.get("time", 0),
            "true_decryption_time": true_decrypt_result.get("time", 0),
            "false_decryption_time": false_decrypt_result.get("time", 0),

            "encrypted_file_size": os.path.getsize(self.encrypted_file) if os.path.exists(self.encrypted_file) else 0,
            "true_key_size": os.path.getsize(self.true_key_path) if os.path.exists(self.true_key_path) else 0,
            "false_key_size": os.path.getsize(self.false_key_path) if os.path.exists(self.false_key_path) else 0
        }

        # JSONファイルに保存
        timestamp = int(time.time())
        json_filename = f"test_output/real_file_test_report_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=2)

        # グラフ作成
        plt.figure(figsize=(12, 8))

        # ファイルサイズの比較
        plt.subplot(2, 2, 1)
        sizes = [
            os.path.getsize(self.true_text_file),
            os.path.getsize(self.false_text_file),
            report["encrypted_file_size"],
            report["true_key_size"],
            report["false_key_size"]
        ]
        labels = ['True Text', 'False Text', 'Encrypted', 'True Key', 'False Key']
        plt.bar(range(len(sizes)), sizes)
        plt.xlabel('File Type')
        plt.ylabel('Size (bytes)')
        plt.title('File Size Comparison')
        plt.xticks(range(len(sizes)), labels, rotation=45)
        plt.grid(True)

        # 処理時間の比較
        plt.subplot(2, 2, 2)
        times = [
            report["encryption_time"],
            report["true_decryption_time"],
            report["false_decryption_time"]
        ]
        labels = ['Encryption', 'True Decryption', 'False Decryption']
        plt.bar(range(len(times)), times)
        plt.xlabel('Process')
        plt.ylabel('Time (seconds)')
        plt.title('Processing Time')
        plt.xticks(range(len(times)), labels)
        plt.grid(True)

        # テキスト長の比較
        plt.subplot(2, 2, 3)
        lengths = [
            report["original_true_length"],
            report["true_decrypted_length"],
            report["original_false_length"],
            report["false_decrypted_length"]
        ]
        labels = ['Orig True', 'Decr True', 'Orig False', 'Decr False']
        bars = plt.bar(range(len(lengths)), lengths)

        # 一致するかどうかで色分け
        if report["true_match"]:
            bars[0].set_color('green')
            bars[1].set_color('green')
        else:
            bars[0].set_color('red')
            bars[1].set_color('red')

        if report["false_match"]:
            bars[2].set_color('green')
            bars[3].set_color('green')
        else:
            bars[2].set_color('red')
            bars[3].set_color('red')

        plt.xlabel('Text Type')
        plt.ylabel('Length (chars)')
        plt.title('Text Length Comparison')
        plt.xticks(range(len(lengths)), labels)
        plt.grid(True)

        # オーバーヘッド率
        plt.subplot(2, 2, 4)
        original_size = os.path.getsize(self.true_text_file) + os.path.getsize(self.false_text_file)
        crypto_size = report["encrypted_file_size"] + report["true_key_size"] + report["false_key_size"]
        overhead = (crypto_size / original_size) if original_size > 0 else 0

        plt.text(0.5, 0.5, f"Overhead Ratio: {overhead:.2f}x",
                 horizontalalignment='center',
                 verticalalignment='center',
                 transform=plt.gca().transAxes,
                 fontsize=16)
        plt.title('Storage Overhead')
        plt.axis('off')

        plt.tight_layout()

        # 画像を保存
        filename = f"test_output/real_file_test_results_{timestamp}.png"
        plt.savefig(filename)
        print(f"Real file test results saved as {filename}")

        return filename, json_filename


if __name__ == "__main__":
    # テストの実行
    unittest.main(argv=['first-arg-is-ignored'], exit=False)