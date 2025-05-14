#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 暗号化機能のテスト

暗号化プロセスの正確性とセキュリティを検証します。
"""

import os
import sys
import unittest
import tempfile
import hashlib
from typing import Tuple, Dict, Any

# テスト用にモジュールパスを追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.encrypt import encrypt_files, generate_master_key, process_large_file
from method_10_indeterministic.config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
    MAX_CHUNK_SIZE, FILE_THRESHOLD_SIZE, DEFAULT_CHUNK_COUNT,
    STATE_MATRIX_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION
)

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = "test_output"

class TestEncryption(unittest.TestCase):
    """暗号化機能のテスト"""

    @classmethod
    def setUpClass(cls):
        """テスト前の準備"""
        # テスト出力ディレクトリの作成
        os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

        # テスト用ファイルの存在確認
        assert os.path.exists(TRUE_TEXT_PATH), f"真のテキストファイル {TRUE_TEXT_PATH} が見つかりません"
        assert os.path.exists(FALSE_TEXT_PATH), f"偽のテキストファイル {FALSE_TEXT_PATH} が見つかりません"

        # テストファイルの内容を読み込み
        with open(TRUE_TEXT_PATH, 'rb') as f:
            cls.true_content = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            cls.false_content = f.read()

    def setUp(self):
        """各テスト前の準備"""
        # テスト用の出力ファイル名を生成
        self.output_file = os.path.join(TEST_OUTPUT_DIR, f"test_encrypt_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")

    def test_key_generation(self):
        """鍵生成機能をテスト"""
        # 鍵を生成
        key = generate_master_key()

        # 鍵のサイズを検証
        self.assertEqual(len(key), KEY_SIZE_BYTES, f"鍵のサイズが {KEY_SIZE_BYTES} バイトではありません")

        # 連続して生成した鍵が異なることを確認
        another_key = generate_master_key()
        self.assertNotEqual(key, another_key, "連続して生成された鍵が同一です")

    def test_basic_encryption(self):
        """基本的な暗号化機能をテスト"""
        # 暗号化を実行
        keys, metadata = encrypt_files(
            TRUE_TEXT_PATH,
            FALSE_TEXT_PATH,
            self.output_file,
            verbose=True
        )

        # 出力ファイルが存在するか確認
        self.assertTrue(os.path.exists(self.output_file), "暗号化ファイルが生成されていません")

        # 鍵情報が適切か確認
        self.assertIn("master_key", keys, "鍵情報にマスター鍵が含まれていません")
        self.assertTrue(len(keys["master_key"]) > 0, "マスター鍵が空です")

        # メタデータが適切か確認
        self.assertIn("format", metadata, "メタデータに形式情報が含まれていません")
        self.assertEqual(metadata["format"], OUTPUT_FORMAT, f"メタデータの形式が {OUTPUT_FORMAT} ではありません")
        self.assertIn("timestamp", metadata, "メタデータにタイムスタンプが含まれていません")

        # 出力ファイルのサイズを検証
        file_size = os.path.getsize(self.output_file)
        self.assertTrue(file_size > 0, "暗号化ファイルのサイズがゼロです")

        # 最低限のサイズ（ヘッダー + 最小限のデータ）
        min_expected_size = 8 + 64  # ヘッダー(8バイト) + 最小データ(64バイト)
        self.assertTrue(file_size >= min_expected_size, f"暗号化ファイルのサイズが小さすぎます: {file_size} < {min_expected_size}")

    def test_large_file_handling(self):
        """大きなファイルの分割処理をテスト"""
        # 一時的な大きなファイルを作成
        with tempfile.NamedTemporaryFile(delete=False) as temp_true:
            # FILE_THRESHOLD_SIZE より大きなファイルを作成
            min_size = FILE_THRESHOLD_SIZE + 1024
            # 元のファイルの内容を繰り返して大きなファイルを作成
            while temp_true.tell() < min_size:
                temp_true.write(self.true_content)
            temp_true_path = temp_true.name

        with tempfile.NamedTemporaryFile(delete=False) as temp_false:
            # 同様に偽のファイルも作成
            while temp_false.tell() < min_size:
                temp_false.write(self.false_content)
            temp_false_path = temp_false.name

        try:
            # 大きなファイルの処理を実行
            output_file = os.path.join(TEST_OUTPUT_DIR, f"test_large_encrypt_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")
            keys, metadata = process_large_file(
                temp_true_path,
                temp_false_path,
                output_file,
                max_chunk_size=MAX_CHUNK_SIZE // 10,  # より小さなチャンクサイズでテスト
                verbose=True
            )

            # マニフェストファイルが作成されたか確認
            manifest_path = f"{output_file}.manifest"
            self.assertTrue(os.path.exists(manifest_path), "チャンクマニフェストファイルが作成されていません")

            # 鍵情報が適切か確認
            self.assertIn("master_key", keys, "鍵情報にマスター鍵が含まれていません")

            # メタデータが適切か確認
            self.assertIn("format", metadata, "メタデータに形式情報が含まれていません")
            self.assertEqual(metadata["format"], "indeterministic_chunks", "メタデータの形式が indeterministic_chunks ではありません")
            self.assertIn("chunks", metadata, "メタデータにチャンク情報が含まれていません")

            # チャンクファイルが存在するか確認
            chunk_count = metadata["chunks"]
            self.assertTrue(chunk_count > 0, "チャンク数がゼロです")

            for i in range(chunk_count):
                chunk_path = f"{output_file}.{i:03d}"
                self.assertTrue(os.path.exists(chunk_path), f"チャンクファイル {chunk_path} が存在しません")

        finally:
            # 一時ファイルを削除
            os.unlink(temp_true_path)
            os.unlink(temp_false_path)

    def test_security_properties(self):
        """暗号化のセキュリティ特性をテスト"""
        # 同じ入力に対して異なる暗号文が生成されることを確認
        output_file1 = os.path.join(TEST_OUTPUT_DIR, f"test_security1_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")
        output_file2 = os.path.join(TEST_OUTPUT_DIR, f"test_security2_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")

        # 同じ入力で2回暗号化
        keys1, _ = encrypt_files(TRUE_TEXT_PATH, FALSE_TEXT_PATH, output_file1)
        keys2, _ = encrypt_files(TRUE_TEXT_PATH, FALSE_TEXT_PATH, output_file2)

        # 鍵が異なることを確認
        self.assertNotEqual(keys1["master_key"], keys2["master_key"], "異なる実行で同じ鍵が生成されました")

        # 出力ファイルの内容を比較
        with open(output_file1, 'rb') as f1, open(output_file2, 'rb') as f2:
            content1 = f1.read()
            content2 = f2.read()

        # ヘッダー以外の部分が異なることを確認
        # (ヘッダーは同じでも良いが、暗号文部分は異なるべき)
        if len(content1) >= 8 and len(content2) >= 8:
            # ヘッダー (最初の8バイト) は同じかもしれない
            header1 = content1[:8]
            header2 = content2[:8]
            self.assertEqual(header1, header2, "ヘッダーが一致していません")

            # 残りの部分（暗号文）は異なるべき
            if len(content1) > 8 and len(content2) > 8:
                # 少なくとも一部のバイトは異なるはず
                different_bytes = sum(1 for a, b in zip(content1[8:], content2[8:]) if a != b)
                total_compared = min(len(content1), len(content2)) - 8

                # 少なくとも10%のバイトは異なるべき
                min_different = max(1, total_compared // 10)
                self.assertTrue(different_bytes >= min_different,
                               f"暗号文の差異が少なすぎます: {different_bytes}/{total_compared} < {min_different}")

    def tearDown(self):
        """各テスト後のクリーンアップ"""
        # テスト生成ファイルの削除は行わない
        # タイムスタンプ付きでエビデンスとして保存
        pass

if __name__ == "__main__":
    unittest.main()
