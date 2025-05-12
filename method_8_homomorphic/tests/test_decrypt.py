#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の復号機能テスト
"""

import os
import sys
import unittest
import tempfile
import json
import base64
import binascii
from unittest.mock import patch

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.encrypt import encrypt_files, parse_arguments as encrypt_parse_args
from method_8_homomorphic.decrypt import decrypt_file, parse_key
from method_8_homomorphic.key_analyzer import analyze_key_type


class TestDecrypt(unittest.TestCase):
    """準同型暗号マスキング方式の復号機能テスト"""

    def setUp(self):
        """テスト環境のセットアップ"""
        # テスト用の一時ディレクトリを作成
        self.test_dir = tempfile.TemporaryDirectory()
        self.temp_dir = self.test_dir.name

        # テスト用のファイルパス
        self.true_file = os.path.join(self.temp_dir, "true.text")
        self.false_file = os.path.join(self.temp_dir, "false.text")
        self.encrypted_file = os.path.join(self.temp_dir, "encrypted.hmc")
        self.decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")
        self.keys_dir = os.path.join(self.temp_dir, "keys")

        # テスト用のファイルを作成
        with open(self.true_file, "w") as f:
            f.write("これは正規のファイルです。テスト用のデータを含みます。")

        with open(self.false_file, "w") as f:
            f.write("これは非正規のファイルです。偽の鍵で復号されると表示されます。")

        # ディレクトリを作成
        os.makedirs(self.keys_dir, exist_ok=True)

    def tearDown(self):
        """テスト環境のクリーンアップ"""
        # テスト用の一時ディレクトリを削除
        self.test_dir.cleanup()

    def test_parse_key(self):
        """鍵の解析機能のテスト"""
        # 16進数形式
        hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        key = parse_key(hex_key)
        self.assertEqual(len(key), 32)  # KEY_SIZE_BYTES = 32
        self.assertEqual(binascii.hexlify(key).decode(), hex_key)

        # Base64形式
        b64_key = "ABCDEFG123456789="
        try:
            key = parse_key(b64_key)
            self.assertIsInstance(key, bytes)
        except ValueError:
            pass  # Base64のデコードに失敗する場合もOK

        # パスワード形式（16進数やBase64でない場合）
        password = "test_password123"
        key = parse_key(password)
        self.assertEqual(len(key), 32)  # SHA-256の出力は32バイト

    def test_analyze_key_type(self):
        """鍵の種類解析機能のテスト"""
        # 複数のランダム鍵を生成して、解析結果が確実に文字列であることを確認
        for _ in range(10):
            key = os.urandom(32)
            key_type = analyze_key_type(key)
            self.assertIn(key_type, ["true", "false"])
            self.assertIsInstance(key_type, str)

    @patch('sys.stdout')  # 標準出力をモックして表示を抑制
    def test_encrypt_decrypt_flow(self, mock_stdout):
        """暗号化と復号の一連の流れをテスト"""
        # 暗号化用の引数を作成
        encrypt_args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.encrypted_file,
            'algorithm': 'paillier',
            'key': None,
            'password': "test_password",
            'advanced_mask': False,
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': True,
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        # 暗号化実行
        key, metadata = encrypt_files(encrypt_args)

        # キーをファイルに保存
        key_path = os.path.join(self.keys_dir, "test_key.bin")
        with open(key_path, "wb") as f:
            f.write(key)

        # 暗号化ファイルの存在を確認
        self.assertTrue(os.path.exists(self.encrypted_file))

        # 暗号化ファイルの内容を確認
        with open(self.encrypted_file, "r") as f:
            encrypted_data = json.load(f)

        self.assertEqual(encrypted_data["format"], "homomorphic_masked")
        self.assertIn("true_mask", encrypted_data)
        self.assertIn("false_mask", encrypted_data)

        # 鍵の種類を解析
        key_type = analyze_key_type(key)

        # 復号を実行
        success = decrypt_file(
            self.encrypted_file, key, self.decrypted_file, key_type
        )

        # 復号結果を確認
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.decrypted_file))

        # 復号されたファイルの内容を確認
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()

        # キーに応じた内容になっているか確認
        if key_type == "true":
            with open(self.true_file, "r") as f:
                expected_content = f.read()
        else:
            with open(self.false_file, "r") as f:
                expected_content = f.read()

        self.assertEqual(decrypted_content, expected_content)

    @patch('sys.stdout')  # 標準出力をモックして表示を抑制
    def test_decrypt_with_file_key(self, mock_stdout):
        """ファイルから読み込んだ鍵での復号テスト"""
        # 暗号化用の引数を作成
        encrypt_args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.encrypted_file,
            'algorithm': 'paillier',
            'key': None,
            'password': None,
            'advanced_mask': False,
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': True,
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        # 暗号化実行
        key, metadata = encrypt_files(encrypt_args)

        # キーをファイルに保存
        key_path = os.path.join(self.keys_dir, "test_key.bin")
        with open(key_path, "wb") as f:
            f.write(key)

        # 鍵の種類を解析
        key_type = analyze_key_type(key)

        # ファイルから鍵を読み込んで復号
        file_key = parse_key(key_path)
        self.assertEqual(file_key, key)  # ファイルから読み込んだ鍵が正しいか確認

        # 復号を実行
        success = decrypt_file(
            self.encrypted_file, file_key, self.decrypted_file, key_type
        )

        # 復号結果を確認
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.decrypted_file))

    @patch('sys.stdout')  # 標準出力をモックして表示を抑制
    def test_decrypt_with_explicit_key_type(self, mock_stdout):
        """明示的に指定した鍵タイプでの復号テスト"""
        # 暗号化用の引数を作成
        encrypt_args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.encrypted_file,
            'algorithm': 'paillier',
            'key': None,
            'password': None,
            'advanced_mask': False,
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': True,
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        # 暗号化実行
        key, metadata = encrypt_files(encrypt_args)

        # 実際の鍵タイプに関わらず、明示的に "true" を指定
        explicit_key_type = "true"

        # 復号を実行
        success = decrypt_file(
            self.encrypted_file, key, self.decrypted_file, explicit_key_type
        )

        # 復号結果を確認
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.decrypted_file))

        # 復号されたファイルの内容を確認
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()

        # 明示的に指定したキータイプに応じた内容になっているか確認
        with open(self.true_file, "r") as f:
            expected_content = f.read()

        # 実際の鍵タイプに関わらず、明示的に指定したタイプの内容になるはず
        self.assertEqual(decrypted_content, expected_content)

    @patch('sys.stdout')  # 標準出力をモックして表示を抑制
    def test_error_handling(self, mock_stdout):
        """エラー処理のテスト"""
        # 存在しないファイルの復号を試みる
        non_existent_file = os.path.join(self.temp_dir, "non_existent.hmc")
        key = os.urandom(32)

        # 暗号化ファイルが存在しない場合
        success = decrypt_file(
            non_existent_file, key, self.decrypted_file
        )
        self.assertFalse(success)

        # 無効な形式のファイルを作成
        invalid_file = os.path.join(self.temp_dir, "invalid.hmc")
        with open(invalid_file, "w") as f:
            f.write("This is not a valid JSON")

        # 無効な形式のファイルの復号を試みる
        success = decrypt_file(
            invalid_file, key, self.decrypted_file
        )
        self.assertFalse(success)

        # 有効なJSONだがフォーマットが異なるファイルを作成
        wrong_format_file = os.path.join(self.temp_dir, "wrong_format.hmc")
        with open(wrong_format_file, "w") as f:
            json.dump({"format": "wrong_format", "data": "test"}, f)

        # 誤ったフォーマットのファイルの復号を試みる
        success = decrypt_file(
            wrong_format_file, key, self.decrypted_file
        )
        self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()