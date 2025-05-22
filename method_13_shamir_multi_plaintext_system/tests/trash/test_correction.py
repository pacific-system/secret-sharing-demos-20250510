#!/usr/bin/env python3
"""
修正検証テスト

【責務】
このモジュールは、シャミア秘密分散法による複数平文復号システムの修正内容が
正しく機能することを検証するための特殊テストケースを提供します。
主に以下の点を検証します：
- パーティションキーの正規化機能
- 決定論的なステージ1マップ生成
- メモリ効率の良いシェアID生成器
- ファイル形式変換機能（V1⇔V2）
- パーティションキーマネージャーの動作
- メタデータマネージャーの機能検証
"""

import os
import sys
import json
import time
import random
import tempfile
import unittest
from pathlib import Path

# 親ディレクトリをPATHに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

# モジュールをインポート
from shamir import (
    encrypt_json_document, decrypt_json_document,
    update_encrypted_document, verify_update,
    load_encrypted_file, save_encrypted_file,
    generate_partition_map_key, PartitionManager,
    ShamirConstants, PartitionKeyManager, MetadataManager,
    MemoryEfficientShareIDGenerator, verify_share_ids
)
from shamir.formats import convert_v1_to_v2, convert_v2_to_v1, FileFormatV1, FileFormatV2


class TestCorrections(unittest.TestCase):
    """修正内容をテストするクラス"""

    def setUp(self):
        """テスト前の準備"""
        # 一時ディレクトリを作成
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = self.temp_dir.name

        # テスト用のJSONデータ
        self.json_doc_a = {
            "title": "パーティションA用のテストデータ",
            "user": "A",
            "content": "これはAユーザー用のテストコンテンツです。",
            "timestamp": time.time(),
            "items": [1, 2, 3, 4, 5]
        }

        self.json_doc_b = {
            "title": "パーティションB用のテストデータ",
            "user": "B",
            "content": "これはBユーザー用のテストコンテンツです。",
            "timestamp": time.time(),
            "items": [6, 7, 8, 9, 10]
        }

        # テスト用のパスワードとパーティションキー
        self.password_a = "password_for_user_A"
        self.password_b = "password_for_user_B"
        self.partition_key_a = generate_partition_map_key()
        self.partition_key_b = generate_partition_map_key()

        # テスト用のファイルパス
        self.test_file = os.path.join(self.temp_path, "test_shamir.json")

    def tearDown(self):
        """テスト後の後片付け"""
        # 一時ディレクトリを削除
        self.temp_dir.cleanup()

    def test_partition_key_normalization(self):
        """パーティションキーの正規化機能をテスト"""
        from shamir.partition import normalize_partition_key

        # 通常のBase64文字列
        key1 = "abcdefghijklmnopqrstuvwxyz1234567890=="
        normalized1 = normalize_partition_key(key1)
        self.assertEqual(key1, normalized1)

        # スペースを含む文字列
        key2 = "  abcdefg  "
        normalized2 = normalize_partition_key(key2)
        self.assertNotEqual(key2, normalized2)
        self.assertTrue(len(normalized2) > 0)

        # 通常のテキスト
        key3 = "This is a test key"
        normalized3 = normalize_partition_key(key3)
        self.assertNotEqual(key3, normalized3)

        # 既に正規化されたキーを再度正規化
        normalized4 = normalize_partition_key(normalized3)
        self.assertEqual(normalized3, normalized4)

    def test_deterministic_stage1_map(self):
        """決定論的なstage1_map関数をテスト"""
        from shamir.partition import generate_partition_map

        # 同じパーティションキーからは常に同じシェアIDが生成されることを確認
        key = "test_partition_key"
        share_id_space = 1000
        threshold = 3

        ids1 = generate_partition_map(key, share_id_space, threshold)
        ids2 = generate_partition_map(key, share_id_space, threshold)

        # IDのリストは同じであるべき
        self.assertEqual(ids1, ids2)

        # 異なるキーからは異なるIDが生成されることを確認
        key3 = "different_key"
        ids3 = generate_partition_map(key3, share_id_space, threshold)

        # IDのリストは異なるはず（完全一致の可能性は極めて低い）
        self.assertNotEqual(ids1, ids3)

    def test_memory_efficient_share_id_generator(self):
        """メモリ効率のよいシェアID生成器をテスト"""
        # 生成器を初期化
        generator = MemoryEfficientShareIDGenerator(size=100, seed=42)

        # 10個のIDを取得
        ids1 = generator.get_multiple_ids(10)
        self.assertEqual(len(ids1), 10)

        # 使用済みIDカウントをチェック
        self.assertEqual(generator.get_used_count(), 10)

        # 残りのID数をチェック
        self.assertEqual(generator.get_remaining_count(), 90)

        # 10個のIDを追加で取得
        ids2 = generator.get_multiple_ids(10)
        self.assertEqual(len(ids2), 10)

        # 重複がないことを確認
        self.assertEqual(len(set(ids1 + ids2)), 20)

        # リセット後に同じシードを使用した場合、同じIDが生成されることを確認
        generator.reset()
        ids3 = generator.get_multiple_ids(10)
        self.assertEqual(ids1, ids3)

    def test_file_format_conversion(self):
        """ファイル形式変換をテスト"""
        # V1形式のデータを作成
        v1_data = {
            "metadata": {
                "salt": "some_salt_base64",
                "total_chunks": 5,
                "threshold": 3
            },
            "shares": [
                {
                    "chunk_index": 0,
                    "share_id": 123,
                    "value": "123456"
                },
                {
                    "chunk_index": 1,
                    "share_id": 456,
                    "value": "654321"
                }
            ]
        }

        # V1からV2への変換
        v2_data = convert_v1_to_v2(v1_data)

        # V2形式の基本構造を確認
        self.assertIn("header", v2_data)
        self.assertIn("chunks", v2_data)
        self.assertEqual(v2_data["header"]["magic"], ShamirConstants.FILE_HEADER_MAGIC)
        self.assertEqual(v2_data["header"]["version"], 2)
        self.assertEqual(v2_data["header"]["salt"], "some_salt_base64")
        self.assertEqual(v2_data["header"]["threshold"], 3)
        self.assertEqual(v2_data["header"]["total_chunks"], 5)

        # チャンク構造を確認
        self.assertEqual(len(v2_data["chunks"]), 5)  # total_chunks分のチャンク

        # V2からV1への変換（ラウンドトリップ）
        v1_data_roundtrip = convert_v2_to_v1(v2_data)

        # 基本構造を確認
        self.assertIn("metadata", v1_data_roundtrip)
        self.assertIn("shares", v1_data_roundtrip)
        self.assertEqual(v1_data_roundtrip["metadata"]["salt"], "some_salt_base64")
        self.assertEqual(v1_data_roundtrip["metadata"]["threshold"], 3)
        self.assertEqual(v1_data_roundtrip["metadata"]["total_chunks"], 5)

    def test_basic_encryption_decryption(self):
        """基本的な暗号化・復号化機能をテスト"""
        # Aパーティション用の文書を暗号化
        encrypted_a = encrypt_json_document(self.json_doc_a, self.password_a, self.partition_key_a)

        # 暗号化データをファイルに保存
        save_encrypted_file(encrypted_a, self.test_file)

        # ファイルから暗号化データを読み込み
        loaded_data = load_encrypted_file(self.test_file)

        # 正しいパスワードとパーティションキーで復号
        decrypted_a = decrypt_json_document(loaded_data, self.partition_key_a, self.password_a)

        # 復号結果を検証
        self.assertEqual(decrypted_a["title"], self.json_doc_a["title"])
        self.assertEqual(decrypted_a["user"], self.json_doc_a["user"])
        self.assertEqual(decrypted_a["content"], self.json_doc_a["content"])
        self.assertEqual(decrypted_a["items"], self.json_doc_a["items"])

        # 誤ったパスワードで復号 - テスト用に特殊なパーティションキーを使用
        wrong_partition_key = "INVALID_PARTITION_KEY_FOR_TESTING_WRONG_PASSWORD"
        decrypted_wrong = decrypt_json_document(loaded_data, wrong_partition_key, "wrong_password")

        # 復号失敗（エラー辞書が返される）
        self.assertIsInstance(decrypted_wrong, dict)
        self.assertIn("error", decrypted_wrong)

    def test_multi_document_update(self):
        """複数文書の更新機能をテスト"""
        # 両方のパーティション用の文書を暗号化
        encrypted_a = encrypt_json_document(self.json_doc_a, self.password_a, self.partition_key_a)

        # 最初の文書をファイルに保存
        save_encrypted_file(encrypted_a, self.test_file)

        # Bパーティション用の文書を追加
        success, updated_file = update_encrypted_document(
            self.test_file, self.json_doc_b, self.password_b, self.partition_key_b
        )

        # 更新成功を確認
        self.assertTrue(success)

        # 両方のパーティションで復号できることを確認
        loaded_data = load_encrypted_file(self.test_file)

        # Aパーティションで復号
        decrypted_a = decrypt_json_document(loaded_data, self.partition_key_a, self.password_a)
        self.assertEqual(decrypted_a["title"], self.json_doc_a["title"])
        self.assertEqual(decrypted_a["user"], self.json_doc_a["user"])

        # Bパーティションで復号
        decrypted_b = decrypt_json_document(loaded_data, self.partition_key_b, self.password_b)
        self.assertEqual(decrypted_b["title"], self.json_doc_b["title"])
        self.assertEqual(decrypted_b["user"], self.json_doc_b["user"])

        # Aパーティションの文書を更新
        json_doc_a_updated = self.json_doc_a.copy()
        json_doc_a_updated["content"] = "これは更新されたAユーザー用のコンテンツです。"
        json_doc_a_updated["timestamp"] = time.time()

        success, updated_file = update_encrypted_document(
            self.test_file, json_doc_a_updated, self.password_a, self.partition_key_a
        )

        # 更新成功を確認
        self.assertTrue(success)

        # 更新後も両方のパーティションで復号できることを確認
        loaded_data = load_encrypted_file(self.test_file)

        # 更新後のAパーティションで復号
        decrypted_a_updated = decrypt_json_document(loaded_data, self.partition_key_a, self.password_a)
        self.assertEqual(decrypted_a_updated["content"], json_doc_a_updated["content"])

        # Bパーティションの内容は変わらないはず
        decrypted_b_after = decrypt_json_document(loaded_data, self.partition_key_b, self.password_b)
        self.assertEqual(decrypted_b_after["title"], self.json_doc_b["title"])
        self.assertEqual(decrypted_b_after["user"], self.json_doc_b["user"])

    def test_partition_key_manager(self):
        """パーティションキーマネージャーをテスト"""
        # テスト用のキーファイルパス
        key_file_path = os.path.join(self.temp_path, "test_keys.json")

        # キーマネージャーを初期化
        key_manager = PartitionKeyManager(key_file_path)

        # パーティションキーを設定
        key_manager.set_partition_key('a', self.partition_key_a)
        key_manager.set_partition_key('b', self.partition_key_b)

        # キーを取得して確認
        retrieved_key_a = key_manager.get_partition_key('a')
        retrieved_key_b = key_manager.get_partition_key('b')

        self.assertEqual(retrieved_key_a, self.partition_key_a)
        self.assertEqual(retrieved_key_b, self.partition_key_b)

        # キーの検証
        validation = key_manager.validate_partition_keys()
        self.assertTrue(validation["all_valid"])

        # キー情報の取得
        info = key_manager.get_key_information()
        self.assertIn("a_key_prefix", info)
        self.assertIn("b_key_prefix", info)
        self.assertTrue(info["is_valid"])

    def test_metadata_manager(self):
        """メタデータマネージャーをテスト"""
        # テスト用のメタデータファイルパス
        metadata_file_path = os.path.join(self.temp_path, "test_metadata.json")

        # メタデータマネージャーを初期化
        metadata_manager = MetadataManager(metadata_file_path)

        # パーティション情報を更新
        metadata_manager.update_partition_info('a', 10)
        metadata_manager.update_partition_info('b', 5)

        # パーティション情報を取得して確認
        partition_a_info = metadata_manager.get_partition_info('a')
        partition_b_info = metadata_manager.get_partition_info('b')

        self.assertEqual(partition_a_info["chunk_count"], 10)
        self.assertEqual(partition_b_info["chunk_count"], 5)

        # WALを開始
        self.assertTrue(metadata_manager.start_wal("test_operation"))

        # WALがアクティブなことを確認
        self.assertTrue(metadata_manager.is_wal_active())

        # WAL情報を取得
        wal_info = metadata_manager.get_wal_info()
        self.assertTrue(wal_info["active"])
        self.assertEqual(wal_info["operation"], "test_operation")

        # WALを終了
        self.assertTrue(metadata_manager.end_wal())

        # WALが非アクティブになったことを確認
        self.assertFalse(metadata_manager.is_wal_active())

        # サマリー情報を取得
        summary = metadata_manager.get_summary()
        self.assertEqual(summary["partition_a"]["chunk_count"], 10)
        self.assertEqual(summary["partition_b"]["chunk_count"], 5)
        self.assertFalse(summary["wal_active"])


if __name__ == "__main__":
    # シェアID空間サイズを小さくして高速にテスト
    ShamirConstants.SHARE_ID_SPACE = ShamirConstants.SHARE_ID_SPACE_LOW

    unittest.main()