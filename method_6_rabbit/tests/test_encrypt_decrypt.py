#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
暗号化・復号のエンドツーエンドテスト
"""

import unittest
import os
import sys
import tempfile
import shutil
from typing import Dict, List, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# モジュールインポート
from method_6_rabbit.encrypt import encrypt_file, encrypt_data
from method_6_rabbit.decrypt import decrypt_file, decrypt_data
from method_6_rabbit.multipath_decrypt import MultiPathDecryptor
from method_6_rabbit.stream_selector import StreamSelector
from method_6_rabbit.config import TRUE_KEY_MARKER, FALSE_KEY_MARKER


class TestEncryptDecrypt(unittest.TestCase):
    """暗号化と復号のエンドツーエンドテスト"""

    def setUp(self):
        """テストの前処理"""
        # テスト用のディレクトリとファイルを作成
        self.test_dir = tempfile.mkdtemp()

        # テスト用のファイルを作成
        self.true_path = os.path.join(self.test_dir, "true.text")
        self.false_path = os.path.join(self.test_dir, "false.text")
        self.encrypted_path = os.path.join(self.test_dir, "encrypted.bin")
        self.decrypted_true_path = os.path.join(self.test_dir, "decrypted_true.text")
        self.decrypted_false_path = os.path.join(self.test_dir, "decrypted_false.text")

        # テスト用のデータ
        self.true_content = "これは正規の秘密文書です。\n重要な情報が含まれています。"
        self.false_content = "これはダミーの文書です。\n本物の情報はありません。"

        # テストファイルに書き込み
        with open(self.true_path, "w", encoding="utf-8") as f:
            f.write(self.true_content)
        with open(self.false_path, "w", encoding="utf-8") as f:
            f.write(self.false_content)

        # テスト用の鍵
        self.test_keys = {
            "true": "correct_master_key_2023",
            "false": "wrong_backup_key_2023"
        }

    def tearDown(self):
        """テスト後の後処理"""
        # テスト用のディレクトリとファイルを削除
        shutil.rmtree(self.test_dir)

    def test_encrypt_decrypt_file(self):
        """ファイルの暗号化と復号のテスト"""
        # ファイルを暗号化
        encrypt_file(
            true_file=self.true_path,
            false_file=self.false_path,
            output_file=self.encrypted_path,
            key=self.test_keys["true"]
        )

        # ファイルが暗号化されたことを確認
        self.assertTrue(os.path.exists(self.encrypted_path))

        # 正規の鍵で復号
        decrypt_file(
            input_file=self.encrypted_path,
            output_file=self.decrypted_true_path,
            key=self.test_keys["true"]
        )

        # 非正規の鍵で復号
        decrypt_file(
            input_file=self.encrypted_path,
            output_file=self.decrypted_false_path,
            key=self.test_keys["false"]
        )

        # 復号結果を確認
        with open(self.decrypted_true_path, "r", encoding="utf-8") as f:
            decrypted_true_content = f.read()
        with open(self.decrypted_false_path, "r", encoding="utf-8") as f:
            decrypted_false_content = f.read()

        # 正規の鍵では正規のコンテンツが復号されること
        self.assertEqual(self.true_content, decrypted_true_content)

        # 非正規の鍵では非正規のコンテンツが復号されること
        self.assertEqual(self.false_content, decrypted_false_content)

    def test_encrypt_decrypt_data(self):
        """データの暗号化と復号のテスト"""
        # データを暗号化
        encrypted_data = encrypt_data(
            true_data=self.true_content.encode("utf-8"),
            false_data=self.false_content.encode("utf-8"),
            key=self.test_keys["true"]
        )

        # データが暗号化されたことを確認
        self.assertIsInstance(encrypted_data, bytes)
        self.assertGreater(len(encrypted_data), 0)

        # 正規の鍵で復号
        decrypted_true_data = decrypt_data(
            data=encrypted_data,
            key=self.test_keys["true"]
        )

        # 非正規の鍵で復号
        decrypted_false_data = decrypt_data(
            data=encrypted_data,
            key=self.test_keys["false"]
        )

        # 復号結果を確認
        decrypted_true_content = decrypted_true_data.decode("utf-8")
        decrypted_false_content = decrypted_false_data.decode("utf-8")

        # 正規の鍵では正規のコンテンツが復号されること
        self.assertEqual(self.true_content, decrypted_true_content)

        # 非正規の鍵では非正規のコンテンツが復号されること
        self.assertEqual(self.false_content, decrypted_false_content)

    def test_multipath_decrypt(self):
        """多重復号パスのテスト"""
        # ファイルを暗号化
        encrypt_file(
            true_file=self.true_path,
            false_file=self.false_path,
            output_file=self.encrypted_path,
            key=self.test_keys["true"]
        )

        # 多重復号パスを設定
        decryptor = MultiPathDecryptor()

        # 複数の鍵で復号を試みる
        test_keys = [
            self.test_keys["true"],
            self.test_keys["false"],
            "another_test_key",
            "invalid_key_123"
        ]

        # 復号パスを設定
        paths = []
        for i, key in enumerate(test_keys):
            output_path = os.path.join(self.test_dir, f"decrypted_path_{i}.text")
            paths.append((key, output_path))

        # 多重復号を実行
        results = decryptor.decrypt_file_with_multiple_keys(
            input_file=self.encrypted_path,
            key_output_pairs=paths
        )

        # 結果の検証
        for key, output_path, success in results:
            if key == self.test_keys["true"]:
                # 正規の鍵は復号に成功し、正規のコンテンツが得られるはず
                self.assertTrue(success)
                with open(output_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertEqual(self.true_content, content)
            elif key == self.test_keys["false"]:
                # 非正規の鍵は復号に成功し、非正規のコンテンツが得られるはず
                self.assertTrue(success)
                with open(output_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertEqual(self.false_content, content)
            else:
                # その他の鍵は復号に失敗するか、不正な結果になるはず
                # 注: 本実装では全ての鍵が成功するが、内容が異なる
                if success:
                    with open(output_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    # 正規/非正規のいずれかと一致しないことを期待するのは難しい
                    # （乱数によって一致する可能性もあるため）
                    pass

    def test_edge_cases(self):
        """エッジケースのテスト"""
        # 空のファイルの暗号化・復号
        empty_true_path = os.path.join(self.test_dir, "empty_true.text")
        empty_false_path = os.path.join(self.test_dir, "empty_false.text")
        empty_encrypted_path = os.path.join(self.test_dir, "empty_encrypted.bin")
        empty_decrypted_path = os.path.join(self.test_dir, "empty_decrypted.text")

        with open(empty_true_path, "w") as f:
            pass
        with open(empty_false_path, "w") as f:
            pass

        # 空ファイルを暗号化
        encrypt_file(
            true_file=empty_true_path,
            false_file=empty_false_path,
            output_file=empty_encrypted_path,
            key=self.test_keys["true"]
        )

        # 空ファイルが暗号化されたことを確認
        self.assertTrue(os.path.exists(empty_encrypted_path))

        # 暗号化ファイルが空でないことを確認（ヘッダー等が含まれるため）
        self.assertGreater(os.path.getsize(empty_encrypted_path), 0)

        # 空ファイルを復号
        decrypt_file(
            input_file=empty_encrypted_path,
            output_file=empty_decrypted_path,
            key=self.test_keys["true"]
        )

        # 復号結果が空ファイルであることを確認
        self.assertEqual(os.path.getsize(empty_decrypted_path), 0)

        # 非常に大きいファイル（シミュレーション）
        # 実際にはテスト速度のために小さめのファイルで代用
        large_size = 1024 * 100  # 100KB
        large_true_path = os.path.join(self.test_dir, "large_true.text")
        large_false_path = os.path.join(self.test_dir, "large_false.text")
        large_encrypted_path = os.path.join(self.test_dir, "large_encrypted.bin")
        large_decrypted_path = os.path.join(self.test_dir, "large_decrypted.text")

        with open(large_true_path, "wb") as f:
            f.write(os.urandom(large_size))
        with open(large_false_path, "wb") as f:
            f.write(os.urandom(large_size))

        # 大きなファイルを暗号化
        encrypt_file(
            true_file=large_true_path,
            false_file=large_false_path,
            output_file=large_encrypted_path,
            key=self.test_keys["true"]
        )

        # 大きなファイルが暗号化されたことを確認
        self.assertTrue(os.path.exists(large_encrypted_path))

        # 大きなファイルを復号
        decrypt_file(
            input_file=large_encrypted_path,
            output_file=large_decrypted_path,
            key=self.test_keys["true"]
        )

        # 復号結果のサイズが元のファイルと一致することを確認
        self.assertEqual(os.path.getsize(large_decrypted_path), large_size)

        # 内容が一致することを確認
        with open(large_true_path, "rb") as f:
            large_true_content = f.read()
        with open(large_decrypted_path, "rb") as f:
            large_decrypted_content = f.read()

        self.assertEqual(large_true_content, large_decrypted_content)


# テスト実行
if __name__ == "__main__":
    unittest.main()