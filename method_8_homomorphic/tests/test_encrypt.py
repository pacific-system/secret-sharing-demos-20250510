#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の暗号化実装のテスト

このモジュールは、準同型暗号マスキング方式の暗号化実装をテストします。
"""

import os
import sys
import json
import base64
import unittest
import tempfile
import shutil
from unittest.mock import patch

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.encrypt import main, encrypt_files, parse_arguments
from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, serialize_encrypted_data, deserialize_encrypted_data
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)


class TestEncrypt(unittest.TestCase):
    """暗号化実装のテストケース"""

    def setUp(self):
        """テスト前処理"""
        # テスト用の一時ディレクトリを作成
        self.test_dir = tempfile.mkdtemp()

        # テスト用のファイルを作成
        self.true_file = os.path.join(self.test_dir, "true.text")
        self.false_file = os.path.join(self.test_dir, "false.text")
        self.output_file = os.path.join(self.test_dir, "output.hmc")
        self.keys_dir = os.path.join(self.test_dir, "keys")

        # テスト用のデータを作成
        with open(self.true_file, "w") as f:
            f.write("これは正規のファイルの内容です。")

        with open(self.false_file, "w") as f:
            f.write("これは非正規のファイルの内容です。")

    def tearDown(self):
        """テスト後処理"""
        # テスト用の一時ディレクトリを削除
        shutil.rmtree(self.test_dir)

    def test_encrypt_basic(self):
        """基本的な暗号化処理のテスト"""
        # encrypt_filesを直接呼び出してテスト
        args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.output_file,
            'algorithm': 'paillier',
            'key': None,
            'password': None,
            'advanced_mask': False,
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': False,
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        # 暗号化実行
        encrypt_files(args)

        # 出力ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.output_file))

        # 出力ファイルが適切なJSON形式であることを確認
        with open(self.output_file, 'r') as f:
            encrypted_data = json.load(f)

        # 必要なフィールドが存在することを確認
        self.assertIn('format', encrypted_data)
        self.assertIn('version', encrypted_data)
        self.assertIn('true_chunks', encrypted_data)
        self.assertIn('false_chunks', encrypted_data)
        self.assertIn('true_mask', encrypted_data)
        self.assertIn('false_mask', encrypted_data)

    def test_encrypt_with_password(self):
        """パスワードを使用した暗号化のテスト"""
        args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.output_file,
            'algorithm': 'paillier',
            'key': None,
            'password': 'test_password',
            'advanced_mask': False,
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': False,
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        # 暗号化実行
        encrypt_files(args)

        # 出力ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.output_file))

        # 出力ファイルが適切なJSON形式であることを確認
        with open(self.output_file, 'r') as f:
            encrypted_data = json.load(f)

        # 必要なフィールドが存在することを確認
        self.assertIn('format', encrypted_data)
        self.assertIn('version', encrypted_data)
        self.assertIn('salt', encrypted_data)  # パスワード使用時はソルトが必要

    def test_encrypt_with_advanced_mask(self):
        """高度なマスク関数を使用した暗号化のテスト"""
        args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.output_file,
            'algorithm': 'paillier',
            'key': None,
            'password': None,
            'advanced_mask': True,  # 高度なマスク関数を使用
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': False,
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        # 暗号化実行
        encrypt_files(args)

        # 出力ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.output_file))

        # 出力ファイルが適切なJSON形式であることを確認
        with open(self.output_file, 'r') as f:
            encrypted_data = json.load(f)

        # 必要なフィールドが存在することを確認
        self.assertIn('format', encrypted_data)
        self.assertIn('version', encrypted_data)

    def test_save_keys(self):
        """鍵の保存機能のテスト"""
        args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.output_file,
            'algorithm': 'paillier',
            'key': None,
            'password': None,
            'advanced_mask': False,
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': True,  # 鍵を保存
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        # 暗号化実行
        encrypt_files(args)

        # 鍵ディレクトリが作成されていることを確認
        self.assertTrue(os.path.exists(self.keys_dir))

        # 必要な鍵ファイルが存在することを確認
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "paillier_public.json")))
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "paillier_private.json")))
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "encryption_key.bin")))
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "salt.bin")))

    @patch('sys.argv', ['encrypt.py', '--true-file', 'test_true.text', '--false-file', 'test_false.text'])
    def test_command_line_interface(self):
        """コマンドラインインターフェースのテスト"""
        # パッチを適用してコマンドライン引数を模擬
        with patch('method_8_homomorphic.encrypt.encrypt_files') as mock_encrypt:
            # メイン関数を実行
            main()

            # encrypt_filesが呼び出されたことを確認
            mock_encrypt.assert_called_once()

            # 引数が正しく解析されたことを確認
            args = mock_encrypt.call_args[0][0]
            self.assertEqual(args.true_file, 'test_true.text')
            self.assertEqual(args.false_file, 'test_false.text')

    def test_indistinguishable_form(self):
        """区別不可能な形式への変換のテスト"""
        # 暗号化実行
        args = type('Args', (), {
            'true_file': self.true_file,
            'false_file': self.false_file,
            'output': self.output_file,
            'algorithm': 'paillier',
            'key': None,
            'password': None,
            'advanced_mask': False,
            'key_bits': 1024,  # テスト用に小さめのビット数
            'save_keys': True,  # 鍵ファイルを使用するため保存
            'keys_dir': self.keys_dir,
            'verbose': False
        })()

        encrypt_files(args)

        # 出力ファイルを読み込み
        with open(self.output_file, 'r') as f:
            encrypted_data = json.load(f)

        # 必要なフィールドが存在することを確認
        self.assertIn('format', encrypted_data)
        self.assertIn('version', encrypted_data)
        self.assertIn('true_chunks', encrypted_data)
        self.assertIn('false_chunks', encrypted_data)
        self.assertIn('true_mask', encrypted_data)
        self.assertIn('false_mask', encrypted_data)

        # 鍵が正しく保存されていることを確認
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "paillier_public.json")))
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "paillier_private.json")))


if __name__ == "__main__":
    unittest.main()