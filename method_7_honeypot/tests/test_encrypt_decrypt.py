#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 暗号化・復号のテスト

暗号化と復号の基本機能をテストし、正規鍵と非正規鍵での
復号結果が期待通りであることを確認します。
"""

import os
import sys
import unittest
import tempfile
import shutil
import binascii
import time
from pathlib import Path
from datetime import datetime

# テスト対象のモジュール
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.encrypt import encrypt_files
from method_7_honeypot.decrypt import decrypt_file
from method_7_honeypot.config import TRUE_TEXT_PATH, FALSE_TEXT_PATH


class TestEncryptDecrypt(unittest.TestCase):
    """
    暗号化と復号の機能テスト
    """

    def setUp(self):
        """
        テスト用のデータとディレクトリを設定
        """
        # テスト用の一時ディレクトリを作成
        self.test_dir = tempfile.mkdtemp()

        # テスト用のデータファイルを作成
        self.true_data = "これは正規の平文です。正しい鍵で読み取られるべきデータです。".encode('utf-8')
        self.false_data = "これは非正規の平文です。不正な鍵で読み取られるデータです。".encode('utf-8')

        self.true_file = os.path.join(self.test_dir, 'true_test.txt')
        self.false_file = os.path.join(self.test_dir, 'false_test.txt')

        with open(self.true_file, 'wb') as f:
            f.write(self.true_data)

        with open(self.false_file, 'wb') as f:
            f.write(self.false_data)

        # 出力ファイルのパス
        self.output_file = os.path.join(self.test_dir, 'encrypted.hpot')
        self.decrypted_true_file = os.path.join(self.test_dir, 'decrypted_true.txt')
        self.decrypted_false_file = os.path.join(self.test_dir, 'decrypted_false.txt')

        # テスト用の鍵を生成
        self.keys = {}

    def tearDown(self):
        """
        テスト後のクリーンアップ
        """
        # テスト用の一時ディレクトリを削除
        shutil.rmtree(self.test_dir)

    def test_encrypt_decrypt_basic(self):
        """
        基本的な暗号化と復号のテスト
        """
        print("\n=== 基本的な暗号化と復号のテスト ===")

        # ファイルの暗号化
        key_info, metadata = encrypt_files(
            self.true_file, self.false_file, self.output_file
        )

        # 鍵情報の保存
        self.keys = key_info

        # 暗号化ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.output_file))

        print(f"暗号化ファイル: {self.output_file}")
        print(f"正規鍵: {binascii.hexlify(key_info[KEY_TYPE_TRUE]).decode()}")
        print(f"非正規鍵: {binascii.hexlify(key_info[KEY_TYPE_FALSE]).decode()}")

        # 正規鍵での復号
        print("\n正規鍵での復号:")
        decrypt_file(
            self.output_file, key_info[KEY_TYPE_TRUE], self.decrypted_true_file
        )

        # 非正規鍵での復号
        print("\n非正規鍵での復号:")
        decrypt_file(
            self.output_file, key_info[KEY_TYPE_FALSE], self.decrypted_false_file
        )

        # 復号されたファイルが存在することを確認
        self.assertTrue(os.path.exists(self.decrypted_true_file))
        self.assertTrue(os.path.exists(self.decrypted_false_file))

        # 復号結果を確認
        with open(self.decrypted_true_file, 'rb') as f:
            decrypted_true_data = f.read()

        with open(self.decrypted_false_file, 'rb') as f:
            decrypted_false_data = f.read()

        # 正規鍵での復号結果が正規データと一致するか確認
        self.assertEqual(decrypted_true_data, self.true_data)

        # 非正規鍵での復号結果が非正規データと一致するか確認
        self.assertEqual(decrypted_false_data, self.false_data)

        print("復号結果:")
        print(f"正規データ: {decrypted_true_data.decode('utf-8')}")
        print(f"非正規データ: {decrypted_false_data.decode('utf-8')}")

    def test_timing_attacks(self):
        """
        タイミング攻撃耐性のテスト
        """
        print("\n=== タイミング攻撃耐性のテスト ===")

        # ファイルの暗号化
        key_info, metadata = encrypt_files(
            self.true_file, self.false_file, self.output_file
        )

        # 鍵情報の保存
        self.keys = key_info

        # 正規鍵での復号時間を測定
        start_time = time.time()
        decrypt_file(
            self.output_file, key_info[KEY_TYPE_TRUE], self.decrypted_true_file
        )
        true_decrypt_time = time.time() - start_time

        # 非正規鍵での復号時間を測定
        start_time = time.time()
        decrypt_file(
            self.output_file, key_info[KEY_TYPE_FALSE], self.decrypted_false_file
        )
        false_decrypt_time = time.time() - start_time

        # 時間差を確認
        time_diff = abs(true_decrypt_time - false_decrypt_time)
        print(f"正規鍵の復号時間: {true_decrypt_time:.6f}秒")
        print(f"非正規鍵の復号時間: {false_decrypt_time:.6f}秒")
        print(f"時間差: {time_diff:.6f}秒")

        # 時間差が十分に小さいことを確認（タイミング攻撃耐性）
        # 注: 現実的なノイズを考慮して、小さな差は許容する
        self.assertLess(time_diff, 0.1, "タイミング攻撃に対して脆弱である可能性があります")

        if time_diff < 0.02:
            print("タイミング攻撃耐性: 優良（時間差が非常に小さい）")
        elif time_diff < 0.05:
            print("タイミング攻撃耐性: 良好（時間差が小さい）")
        else:
            print("タイミング攻撃耐性: 要改善（時間差が大きめ）")

    def test_invalid_keys(self):
        """
        不正な鍵でのエラー処理のテスト
        """
        print("\n=== 不正な鍵でのエラー処理のテスト ===")

        # ファイルの暗号化
        key_info, metadata = encrypt_files(
            self.true_file, self.false_file, self.output_file
        )

        # 不正な鍵を生成
        invalid_key = os.urandom(len(key_info[KEY_TYPE_TRUE]))
        print(f"不正な鍵: {binascii.hexlify(invalid_key).decode()}")

        # 不正な鍵での復号でエラーが発生することを確認
        with self.assertRaises(Exception):
            decrypt_file(
                self.output_file, invalid_key, os.path.join(self.test_dir, 'invalid.txt')
            )

        print("不正な鍵での復号: 期待通りにエラーが発生しました")

    def test_real_files(self):
        """
        実際のtrue.textとfalse.textを使用した暗号化と復号のテスト
        """
        print("\n=== 実際のファイルを使用した暗号化と復号のテスト ===")

        # 実際のファイルが存在するか確認
        if not os.path.exists(TRUE_TEXT_PATH) or not os.path.exists(FALSE_TEXT_PATH):
            print(f"警告: 実際のファイルが見つかりません。テストをスキップします。")
            print(f"True file path: {TRUE_TEXT_PATH}")
            print(f"False file path: {FALSE_TEXT_PATH}")
            return

        # ファイルの暗号化
        output_file = os.path.join(self.test_dir, 'real_encrypted.hpot')
        key_info, metadata = encrypt_files(
            TRUE_TEXT_PATH, FALSE_TEXT_PATH, output_file
        )

        # 暗号化ファイルが存在することを確認
        self.assertTrue(os.path.exists(output_file))

        # 正規鍵での復号
        true_output = os.path.join(self.test_dir, 'real_true.txt')
        decrypt_file(output_file, key_info[KEY_TYPE_TRUE], true_output)

        # 非正規鍵での復号
        false_output = os.path.join(self.test_dir, 'real_false.txt')
        decrypt_file(output_file, key_info[KEY_TYPE_FALSE], false_output)

        # 復号されたファイルが存在することを確認
        self.assertTrue(os.path.exists(true_output))
        self.assertTrue(os.path.exists(false_output))

        # 復号結果を確認
        with open(true_output, 'rb') as f:
            true_data = f.read()

        with open(false_output, 'rb') as f:
            false_data = f.read()

        # 元のファイルの内容を読み込み
        with open(TRUE_TEXT_PATH, 'rb') as f:
            original_true_data = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            original_false_data = f.read()

        # 復号結果が元のファイルと一致するか確認
        self.assertEqual(true_data, original_true_data)
        self.assertEqual(false_data, original_false_data)

        print("実際のファイルでのテスト: 成功")

    def test_performance(self):
        """
        パフォーマンステスト
        """
        print("\n=== パフォーマンステスト ===")

        # 大きなデータを生成
        large_true_data = os.urandom(1024 * 1024)  # 1 MB
        large_false_data = os.urandom(1024 * 1024)  # 1 MB

        # テストファイルに書き込み
        large_true_file = os.path.join(self.test_dir, 'large_true.bin')
        large_false_file = os.path.join(self.test_dir, 'large_false.bin')

        with open(large_true_file, 'wb') as f:
            f.write(large_true_data)

        with open(large_false_file, 'wb') as f:
            f.write(large_false_data)

        # 暗号化の時間を測定
        large_output = os.path.join(self.test_dir, 'large_encrypted.hpot')

        start_time = time.time()
        key_info, metadata = encrypt_files(
            large_true_file, large_false_file, large_output
        )
        encrypt_time = time.time() - start_time

        print(f"1MBファイルの暗号化時間: {encrypt_time:.2f}秒")

        # 復号の時間を測定
        large_true_output = os.path.join(self.test_dir, 'large_true_out.bin')
        large_false_output = os.path.join(self.test_dir, 'large_false_out.bin')

        start_time = time.time()
        decrypt_file(large_output, key_info[KEY_TYPE_TRUE], large_true_output)
        true_decrypt_time = time.time() - start_time

        start_time = time.time()
        decrypt_file(large_output, key_info[KEY_TYPE_FALSE], large_false_output)
        false_decrypt_time = time.time() - start_time

        print(f"1MBファイルの正規鍵復号時間: {true_decrypt_time:.2f}秒")
        print(f"1MBファイルの非正規鍵復号時間: {false_decrypt_time:.2f}秒")

        # 結果が一致するか確認
        with open(large_true_output, 'rb') as f:
            decrypted_true_data = f.read()

        with open(large_false_output, 'rb') as f:
            decrypted_false_data = f.read()

        self.assertEqual(decrypted_true_data, large_true_data)
        self.assertEqual(decrypted_false_data, large_false_data)


def run_tests():
    """
    全テストを実行
    """
    # テスト出力ディレクトリの作成
    os.makedirs('test_output', exist_ok=True)

    # 現在の時刻を取得
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ログファイルを設定
    log_file = os.path.join('test_output', f'encrypt_decrypt_test_{timestamp}.log')

    # 標準出力を記録
    with open(log_file, 'w') as f:
        # 元の標準出力を保存
        original_stdout = sys.stdout

        try:
            # 標準出力をファイルにリダイレクト
            sys.stdout = f

            print(f"=== 暗号学的ハニーポット方式 - 暗号化・復号テスト ===")
            print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Python バージョン: {sys.version}")
            print(f"テスト開始...\n")

            # テストの実行
            unittest.main(argv=['first-arg-is-ignored'], exit=False)

            print(f"\nテスト完了。")

        finally:
            # 標準出力を元に戻す
            sys.stdout = original_stdout

    print(f"テスト結果がログファイルに保存されました: {log_file}")
    return log_file


if __name__ == '__main__':
    log_file = run_tests()

    # テスト結果の概要を表示
    with open(log_file, 'r') as f:
        for line in f:
            if 'Ran' in line or 'OK' in line or 'FAILED' in line or 'Test completed' in line:
                print(line.strip())
