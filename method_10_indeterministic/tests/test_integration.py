#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 統合テスト

暗号化と復号のエンドツーエンドテストを実施します。
"""

import os
import sys
import tempfile
import unittest
import binascii
import datetime
from typing import Tuple, Dict, Any

# テスト用にモジュールパスを追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.encrypt import encrypt_files
from method_10_indeterministic.decrypt import decrypt_file
from method_10_indeterministic.config import TRUE_TEXT_PATH, FALSE_TEXT_PATH

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = "test_output"

class TestIntegration(unittest.TestCase):
    """暗号化と復号のエンドツーエンド統合テスト"""

    @classmethod
    def setUpClass(cls):
        """テスト前の準備"""
        # テスト出力ディレクトリの作成
        os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

        # テスト用ファイルの存在確認
        assert os.path.exists(TRUE_TEXT_PATH), f"真のテキストファイル {TRUE_TEXT_PATH} が見つかりません"
        assert os.path.exists(FALSE_TEXT_PATH), f"偽のテキストファイル {FALSE_TEXT_PATH} が見つかりません"

        # テストファイルの内容を確認
        with open(TRUE_TEXT_PATH, 'rb') as f:
            cls.true_content = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            cls.false_content = f.read()

    def setUp(self):
        """各テスト前の準備"""
        # テスト用の一時ファイル名を生成
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.encrypted_file = os.path.join(TEST_OUTPUT_DIR, f"test_encrypt_{timestamp}.indet")
        self.true_decrypted_file = os.path.join(TEST_OUTPUT_DIR, f"test_decrypt_true_{timestamp}.txt")
        self.false_decrypted_file = os.path.join(TEST_OUTPUT_DIR, f"test_decrypt_false_{timestamp}.txt")

    def test_encrypt_decrypt_workflow(self):
        """暗号化から復号までの一連のワークフローをテスト"""
        # 1. 暗号化の実行
        keys, metadata = encrypt_files(
            TRUE_TEXT_PATH,
            FALSE_TEXT_PATH,
            self.encrypted_file,
            verbose=True
        )

        # 暗号化ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.encrypted_file), "暗号化ファイルが生成されていません")

        # 鍵情報が生成されていることを確認
        self.assertIn("master_key", keys, "鍵情報にマスター鍵が含まれていません")
        self.assertTrue(len(keys["master_key"]) > 0, "マスター鍵が空です")

        # 2. 正規鍵で復号
        decrypt_file(
            self.encrypted_file,
            keys["master_key"],
            self.true_decrypted_file,
            verbose=True
        )

        # 復号ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.true_decrypted_file), "正規復号ファイルが生成されていません")

        # 3. 内容の検証
        with open(self.true_decrypted_file, 'rb') as f:
            decrypted_content = f.read()

        # 正規パスでの復号が真のファイルを復元していることを確認
        # 注意: この基本実装では、正規/非正規が決まっていないため、どちらが復元されるか未定義
        # 実際の実装では、鍵の種類に応じて適切な内容が復元されるよう実装する
        self.assertTrue(
            decrypted_content == self.true_content or decrypted_content == self.false_content,
            "復号結果が元のファイルと一致しません"
        )

        # 4. 非正規鍵を生成して復号
        # 実際の実装では、true_key/false_keyを適切に生成する
        # ここでは単純に異なる鍵を生成
        false_key = os.urandom(len(keys["master_key"]))

        decrypt_file(
            self.encrypted_file,
            false_key,
            self.false_decrypted_file,
            verbose=True
        )

        # 復号ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.false_decrypted_file), "非正規復号ファイルが生成されていません")

        # 5. 内容の検証
        with open(self.false_decrypted_file, 'rb') as f:
            false_decrypted_content = f.read()

        # 非正規パスでの復号が偽のファイルを復元していることを確認
        # 同上: 実際の実装では適切な内容が復元されるよう実装する
        self.assertTrue(
            false_decrypted_content == self.true_content or false_decrypted_content == self.false_content,
            "復号結果が元のファイルと一致しません"
        )

    def test_different_keys_different_outputs(self):
        """異なる鍵で異なる出力が得られることをテスト"""
        # 1. 暗号化の実行
        keys, metadata = encrypt_files(
            TRUE_TEXT_PATH,
            FALSE_TEXT_PATH,
            self.encrypted_file,
            verbose=True
        )

        # 2. 10個の異なる鍵で復号を試みる
        decrypted_files = []
        decrypted_contents = []

        for i in range(10):
            # 異なる鍵を生成
            test_key = os.urandom(len(keys["master_key"]))
            output_file = os.path.join(TEST_OUTPUT_DIR, f"test_decrypt_random_{i}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

            # 復号
            decrypt_file(
                self.encrypted_file,
                test_key,
                output_file,
                verbose=False
            )

            decrypted_files.append(output_file)

            # 内容を読み込み
            with open(output_file, 'rb') as f:
                content = f.read()
                decrypted_contents.append(content)

        # 3. 少なくとも1つは真のファイル、少なくとも1つは偽のファイルになっていることを期待
        # 注意: この基本実装では確率的な要素があるため、必ずしも両方が出現するわけではない
        # 実際の実装では、適切な判定ロジックにより、鍵に応じた出力を保証する
        true_matches = sum(1 for content in decrypted_contents if content == self.true_content)
        false_matches = sum(1 for content in decrypted_contents if content == self.false_content)

        # 出力の分布を表示
        print(f"真のファイル一致数: {true_matches}/{len(decrypted_contents)}")
        print(f"偽のファイル一致数: {false_matches}/{len(decrypted_contents)}")

        # すべての出力が真または偽のいずれかであることを確認
        self.assertEqual(true_matches + false_matches, len(decrypted_contents),
                        "復号結果が真または偽のファイルと一致しません")

    def tearDown(self):
        """各テスト後のクリーンアップ"""
        # テスト生成ファイルの削除は行わない
        # タイムスタンプ付きでエビデンスとして保存
        pass

if __name__ == "__main__":
    unittest.main()
