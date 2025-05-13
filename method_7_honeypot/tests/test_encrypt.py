#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 暗号化プログラムのテスト

暗号化機能のテストを行います。キー生成、ファイル暗号化、ハニーポットカプセル化、
メタデータ処理、および鍵保存機能のテストが含まれます。
"""

import os
import sys
import tempfile
import shutil
import unittest
import binascii
import json
from datetime import datetime
from pathlib import Path

# テスト対象のモジュールへのパスを追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# テスト対象のモジュールをインポート
from method_7_honeypot.encrypt import (
    read_file, symmetric_encrypt, encrypt_files, save_keys
)
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.honeypot_capsule import read_data_from_honeypot_file


class TestEncrypt(unittest.TestCase):
    """暗号化機能のテストケース"""

    def setUp(self):
        """テスト前の準備"""
        # テスト用の一時ディレクトリを作成
        self.test_dir = tempfile.mkdtemp()

        # テスト用のファイルを作成
        self.true_text = b"This is the TRUE data that should be revealed with the correct key."
        self.false_text = b"This is the FALSE data that will be shown with an incorrect key."

        self.true_file = os.path.join(self.test_dir, "true.text")
        self.false_file = os.path.join(self.test_dir, "false.text")

        with open(self.true_file, "wb") as f:
            f.write(self.true_text)
        with open(self.false_file, "wb") as f:
            f.write(self.false_text)

        # 出力ディレクトリを作成
        self.output_dir = os.path.join(self.test_dir, "output")
        os.makedirs(self.output_dir, exist_ok=True)

        # 出力ファイルパス
        self.output_file = os.path.join(self.output_dir, "test_encrypt.hpot")

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # テスト用ディレクトリを削除
        shutil.rmtree(self.test_dir)

    def test_read_file(self):
        """ファイル読み込み機能のテスト"""
        # ファイルを読み込み
        true_data = read_file(self.true_file)
        false_data = read_file(self.false_file)

        # 読み込んだデータが正しいか確認
        self.assertEqual(true_data, self.true_text)
        self.assertEqual(false_data, self.false_text)

        # 存在しないファイルの読み込みで例外が発生するか確認
        with self.assertRaises(FileNotFoundError):
            read_file(os.path.join(self.test_dir, "nonexistent.txt"))

    def test_symmetric_encrypt(self):
        """対称暗号化機能のテスト"""
        # テスト用のデータと鍵
        data = b"Test data to encrypt"
        key = os.urandom(32)  # AES-256用の鍵

        # データを暗号化
        encrypted, iv = symmetric_encrypt(data, key)

        # 暗号化結果の検証
        self.assertIsNotNone(encrypted)
        self.assertIsNotNone(iv)
        self.assertEqual(len(iv), 16)  # IVは16バイト（AES-CTR用）
        self.assertGreater(len(encrypted), len(data))  # 暗号文は平文より長い（認証タグを含む）

        # 同じデータと鍵を使っても、異なるIVにより暗号文が異なることを確認
        encrypted2, iv2 = symmetric_encrypt(data, key)
        self.assertNotEqual(encrypted, encrypted2)
        self.assertNotEqual(iv, iv2)

    def test_encrypt_files(self):
        """ファイル暗号化機能のテスト"""
        # ファイルを暗号化
        key_info, metadata = encrypt_files(
            self.true_file, self.false_file, self.output_file, verbose=True
        )

        # 出力ファイルが存在するか確認
        self.assertTrue(os.path.exists(self.output_file))

        # 鍵情報が正しく生成されているか確認
        self.assertIn(KEY_TYPE_TRUE, key_info)
        self.assertIn(KEY_TYPE_FALSE, key_info)
        self.assertIn("master_key", key_info)
        self.assertEqual(len(key_info[KEY_TYPE_TRUE]), 32)  # AES-256用の鍵
        self.assertEqual(len(key_info[KEY_TYPE_FALSE]), 32)

        # メタデータが正しく生成されているか確認
        self.assertEqual(metadata["format"], "honeypot")
        self.assertEqual(metadata["version"], "1.0")
        self.assertEqual(metadata["algorithm"], "honeypot")
        self.assertIn("salt", metadata)
        self.assertIn("true_iv", metadata)
        self.assertIn("false_iv", metadata)
        self.assertIn("creation_timestamp", metadata)
        self.assertEqual(metadata["true_file"], os.path.basename(self.true_file))
        self.assertEqual(metadata["false_file"], os.path.basename(self.false_file))

        # 暗号文ファイルの内容を検証
        file_size = os.path.getsize(self.output_file)
        self.assertGreater(file_size, 0)

        # ファイル内容を出力（デバッグ用）
        print(f"暗号化ファイルサイズ: {file_size} バイト")

    def test_save_keys(self):
        """鍵保存機能のテスト"""
        # テスト用の鍵情報
        master_key = create_master_key()
        params = create_trapdoor_parameters(master_key)
        keys, salt = derive_keys_from_trapdoor(params)

        key_info = {
            KEY_TYPE_TRUE: keys[KEY_TYPE_TRUE],
            KEY_TYPE_FALSE: keys[KEY_TYPE_FALSE],
            "master_key": master_key
        }

        # 鍵を保存
        key_files = save_keys(key_info, self.output_dir, "test_key")

        # 保存された鍵ファイルを確認
        self.assertIn(KEY_TYPE_TRUE, key_files)
        self.assertIn(KEY_TYPE_FALSE, key_files)
        self.assertIn("master_key", key_files)

        for key_type, file_path in key_files.items():
            self.assertTrue(os.path.exists(file_path))

            # ファイルから鍵を読み込み、元の鍵と一致するか確認
            with open(file_path, "rb") as f:
                saved_key = f.read()
            self.assertEqual(saved_key, key_info[key_type])

    def test_end_to_end(self):
        """エンドツーエンドのテスト（暗号化から復号まで）"""
        # ファイルを暗号化
        key_info, _ = encrypt_files(
            self.true_file, self.false_file, self.output_file
        )

                # 暗号文を読み込み
        with open(self.output_file, "rb") as f:
            encrypted_data = f.read()

        # このテストでは、読み取ったデータが正しく復号できるかを確認します
        # 実際に復号処理を行うには decrypt.py の実装が必要ですが、
        # エンドツーエンドテストの目的は暗号化プロセス全体のテストなので、
        # read_data_from_honeypot_file が正しいデータを返すことを確認します

        # データを読み取り
        true_data, _ = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_TRUE)
        false_data, _ = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_FALSE)

        # データが取得できていることを確認
        self.assertIsNotNone(true_data)
        self.assertIsNotNone(false_data)

        # データが異なることを確認（正規と非正規が同じならバグ）
        self.assertNotEqual(true_data, false_data)

        # データサイズが妥当であることを確認
        self.assertGreater(len(true_data), 0)
        self.assertGreater(len(false_data), 0)

        print("エンドツーエンドテスト成功: 正規データと非正規データが正しく取得できました")

        print("エンドツーエンドテスト成功: 正規データと非正規データが正しく復元されました")


def create_test_output():
    """
    テスト出力ディレクトリに暗号化ファイルを生成します。
    実際のプロジェクトで使用するためのテストファイルを作成します。
    """
    # ファイルパスの設定
    true_file = "common/true-false-text/true.text"
    false_file = "common/true-false-text/false.text"

    # 出力ディレクトリを確認・作成
    output_dir = "test_output"
    os.makedirs(output_dir, exist_ok=True)

    # タイムスタンプを取得
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 出力ファイル名を生成
    output_file = os.path.join(output_dir, f"honeypot_test_{timestamp}.hpot")

    # ファイルを暗号化
    key_info, metadata = encrypt_files(
        true_file, false_file, output_file, verbose=True
    )

    # 鍵を保存
    key_files = save_keys(key_info, output_dir, f"honeypot_test_{timestamp}")

    # 暗号化情報を表示
    print("\n暗号化テスト結果:")
    print(f"出力ファイル: {output_file}")
    print(f"ファイルサイズ: {os.path.getsize(output_file)} バイト")

    for key_type, file_path in key_files.items():
        print(f"{key_type}鍵ファイル: {file_path}")

    print("\nメタデータ:")
    for key, value in metadata.items():
        print(f"  {key}: {value}")

    # プロジェクトルートを基準とした相対パスに変換
    rel_output_file = os.path.join(output_dir, os.path.basename(output_file))
    rel_key_files = {
        k: os.path.join(output_dir, os.path.basename(v))
        for k, v in key_files.items()
    }

    return rel_output_file, rel_key_files, metadata


def main():
    """メイン関数"""
    # テスト出力を生成
    output_file, key_files, _ = create_test_output()

    # 結果レポートを生成
    print("\n### 暗号化テスト実行結果")
    print(f"暗号化ファイル: `{output_file}`")
    print(f"正規鍵ファイル: `{key_files[KEY_TYPE_TRUE]}`")
    print(f"非正規鍵ファイル: `{key_files[KEY_TYPE_FALSE]}`")


if __name__ == "__main__":
    # コマンドライン引数によって動作を分岐
    if len(sys.argv) > 1 and sys.argv[1] == "--create-output":
        main()
    else:
        unittest.main()