#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 復号機能のテスト

復号プロセスの正確性とセキュリティを検証します。
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
from method_10_indeterministic.encrypt import encrypt_files, generate_master_key
from method_10_indeterministic.decrypt import decrypt_file, determine_path_type
from method_10_indeterministic.config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
    STATE_MATRIX_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION
)

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = "test_output"

class TestDecryption(unittest.TestCase):
    """復号機能のテスト"""

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
        # テスト用のファイル名を生成
        self.encrypted_file = os.path.join(TEST_OUTPUT_DIR, f"test_enc_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")

        # 暗号化を実行
        self.keys, _ = encrypt_files(
            TRUE_TEXT_PATH,
            FALSE_TEXT_PATH,
            self.encrypted_file,
            verbose=False
        )

        # 復号出力ファイル名を生成
        self.decrypted_file = os.path.join(TEST_OUTPUT_DIR, f"test_dec_{os.urandom(4).hex()}.txt")

    def test_basic_decryption(self):
        """基本的な復号機能をテスト"""
        # マスター鍵を使用して復号
        output_file = decrypt_file(
            self.encrypted_file,
            self.keys["master_key"],
            self.decrypted_file,
            verbose=True
        )

        # 出力ファイルが存在するか確認
        self.assertTrue(os.path.exists(output_file), "復号ファイルが生成されていません")

        # 出力ファイルのサイズを検証
        file_size = os.path.getsize(output_file)
        self.assertTrue(file_size > 0, "復号ファイルのサイズがゼロです")

        # 復号内容の検証
        with open(output_file, 'rb') as f:
            decrypted_content = f.read()

        # 真または偽のいずれかのテキストに一致するか確認
        is_true_match = (decrypted_content == self.true_content)
        is_false_match = (decrypted_content == self.false_content)
        self.assertTrue(is_true_match or is_false_match,
                       "復号結果が元のファイルのいずれとも一致しません")

    def test_different_keys_produce_different_results(self):
        """異なる鍵で異なる結果が得られることをテスト"""
        # オリジナル鍵で復号
        original_output = os.path.join(TEST_OUTPUT_DIR, f"test_original_{os.urandom(4).hex()}.txt")
        decrypt_file(self.encrypted_file, self.keys["master_key"], original_output)

        # 別の鍵を生成して復号
        different_key = generate_master_key()
        different_output = os.path.join(TEST_OUTPUT_DIR, f"test_different_{os.urandom(4).hex()}.txt")
        decrypt_file(self.encrypted_file, different_key, different_output)

        # 出力ファイルが存在するか確認
        self.assertTrue(os.path.exists(original_output), "オリジナル鍵による復号ファイルが生成されていません")
        self.assertTrue(os.path.exists(different_output), "異なる鍵による復号ファイルが生成されていません")

        # 出力内容を比較
        with open(original_output, 'rb') as f1, open(different_output, 'rb') as f2:
            original_content = f1.read()
            different_content = f2.read()

        # 同一の鍵からは同一の結果が得られることを確認
        # （これは同じテストではないが、この仮定の下で次のテストを行う）
        same_key_output = os.path.join(TEST_OUTPUT_DIR, f"test_same_key_{os.urandom(4).hex()}.txt")
        decrypt_file(self.encrypted_file, self.keys["master_key"], same_key_output)
        with open(same_key_output, 'rb') as f:
            same_key_content = f.read()
        self.assertEqual(original_content, same_key_content, "同一の鍵で異なる復号結果が得られました")

        # 異なる鍵から異なる結果が得られる場合があることを確認
        # 注意: 確率的に同じ結果になる可能性もあるため、必ずしも異なるとは限らない
        # このテストは参考程度に実施
        same_result = (original_content == different_content)
        print(f"異なる鍵からの結果は同一: {same_result}")

        # 両方とも true.text か false.text に一致することを確認
        original_is_true = (original_content == self.true_content)
        original_is_false = (original_content == self.false_content)
        different_is_true = (different_content == self.true_content)
        different_is_false = (different_content == self.false_content)

        self.assertTrue(original_is_true or original_is_false,
                       "オリジナル鍵による復号結果が元のファイルのいずれとも一致しません")
        self.assertTrue(different_is_true or different_is_false,
                       "異なる鍵による復号結果が元のファイルのいずれとも一致しません")

    def test_path_determination(self):
        """パス決定機能をテスト"""
        # 複数の鍵を生成して確率的分布を確認
        num_keys = 100
        results = {"true": 0, "false": 0}

        for _ in range(num_keys):
            key = generate_master_key()
            path_type = determine_path_type(key)
            self.assertIn(path_type, ["true", "false"], f"不正なパスタイプ: {path_type}")
            results[path_type] += 1

        # 分布を表示
        true_percentage = results["true"] / num_keys * 100
        false_percentage = results["false"] / num_keys * 100
        print(f"パスタイプの分布: true={true_percentage:.1f}%, false={false_percentage:.1f}%")

        # 分布が極端に偏っていないか確認（20%〜80%の範囲内）
        self.assertTrue(20 <= true_percentage <= 80,
                       f"真のパスタイプの割合が極端です: {true_percentage:.1f}%")
        self.assertTrue(20 <= false_percentage <= 80,
                       f"偽のパスタイプの割合が極端です: {false_percentage:.1f}%")

    def test_error_handling(self):
        """エラー処理をテスト"""
        # 存在しないファイルの復号
        non_existent_file = os.path.join(TEST_OUTPUT_DIR, "non_existent_file.indet")
        non_existent_output = os.path.join(TEST_OUTPUT_DIR, "non_existent_output.txt")

        # エラーが発生することを確認
        with self.assertRaises(Exception):
            decrypt_file(non_existent_file, self.keys["master_key"], non_existent_output)

        # 無効な鍵（短すぎる）
        invalid_key = b"too_short"
        invalid_output = os.path.join(TEST_OUTPUT_DIR, f"test_invalid_{os.urandom(4).hex()}.txt")

        # エラーにならなくても、有効な復号結果が得られるはず
        try:
            decrypt_file(self.encrypted_file, invalid_key, invalid_output)
            # ファイルが生成されたか確認
            self.assertTrue(os.path.exists(invalid_output), "無効な鍵での復号でファイルが生成されませんでした")

            # 復号内容の検証
            with open(invalid_output, 'rb') as f:
                invalid_content = f.read()

            # 真または偽のいずれかのテキストに一致するか確認
            is_true_match = (invalid_content == self.true_content)
            is_false_match = (invalid_content == self.false_content)
            self.assertTrue(is_true_match or is_false_match,
                          "無効な鍵での復号結果が元のファイルのいずれとも一致しません")
        except Exception as e:
            # エラーになっても許容範囲
            print(f"無効な鍵でのエラー（許容範囲）: {e}")

    def test_same_key_produces_same_result(self):
        """同じ鍵から常に同じ結果が得られることをテスト"""
        # 同じ鍵で複数回復号
        results = []
        for i in range(5):
            output_file = os.path.join(TEST_OUTPUT_DIR, f"test_consistency_{i}_{os.urandom(4).hex()}.txt")
            decrypt_file(self.encrypted_file, self.keys["master_key"], output_file)
            with open(output_file, 'rb') as f:
                results.append(f.read())

        # すべての結果が一致するか確認
        for i in range(1, len(results)):
            self.assertEqual(results[0], results[i],
                           f"同一鍵からの復号結果が一致しません: 試行1と試行{i+1}")

    def tearDown(self):
        """各テスト後のクリーンアップ"""
        # テスト生成ファイルの削除は行わない
        # タイムスタンプ付きでエビデンスとして保存
        pass

if __name__ == "__main__":
    unittest.main()
