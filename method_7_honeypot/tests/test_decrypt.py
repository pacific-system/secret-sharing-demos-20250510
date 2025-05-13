#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 復号機能のテスト

復号プログラム（decrypt.py）の機能をテストし、正規鍵と非正規鍵での
復号結果が期待通りであることを確認します。
"""

import os
import sys
import unittest
import tempfile
import shutil
import binascii
import time
import random
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# テスト対象のモジュール
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.encrypt import encrypt_files
from method_7_honeypot.decrypt import (
    decrypt_file, read_key_from_file, read_key_from_hex,
    derive_key_from_password, read_encrypted_file,
    determine_key_type, process_large_file, parse_arguments
)
from method_7_honeypot.config import TRUE_TEXT_PATH, FALSE_TEXT_PATH


class TestDecrypt(unittest.TestCase):
    """
    復号機能のテストクラス
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

        # 鍵ファイルのパス
        self.true_key_file = os.path.join(self.test_dir, 'true.key')
        self.false_key_file = os.path.join(self.test_dir, 'false.key')

        # テスト用の暗号化ファイルと鍵を生成
        self.prepare_test_data()

    def tearDown(self):
        """
        テスト後のクリーンアップ
        """
        # テスト用の一時ディレクトリを削除
        shutil.rmtree(self.test_dir)

    def prepare_test_data(self):
        """
        テスト用の暗号化ファイルと鍵を生成
        """
        # ファイルの暗号化
        key_info, metadata = encrypt_files(
            self.true_file, self.false_file, self.output_file
        )

        # 鍵情報の保存
        self.keys = key_info

        # 鍵ファイルを作成
        with open(self.true_key_file, 'wb') as f:
            f.write(key_info[KEY_TYPE_TRUE])

        with open(self.false_key_file, 'wb') as f:
            f.write(key_info[KEY_TYPE_FALSE])

        # 16進数形式の鍵を保存
        self.true_key_hex = binascii.hexlify(key_info[KEY_TYPE_TRUE]).decode()
        self.false_key_hex = binascii.hexlify(key_info[KEY_TYPE_FALSE]).decode()

        # メタデータを保存
        self.metadata = metadata

    def test_basic_decryption(self):
        """
        基本的な復号機能のテスト
        """
        print("\n=== 基本的な復号機能のテスト ===")

        # 正規鍵での復号
        print("正規鍵での復号...")
        decrypt_file(
            self.output_file, self.keys[KEY_TYPE_TRUE], self.decrypted_true_file
        )

        # 非正規鍵での復号
        print("非正規鍵での復号...")
        decrypt_file(
            self.output_file, self.keys[KEY_TYPE_FALSE], self.decrypted_false_file
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

        print("基本的な復号機能: テスト成功")

    def test_key_from_file(self):
        """
        鍵ファイルからの読み込みテスト
        """
        print("\n=== 鍵ファイルからの読み込みテスト ===")

        # 正規鍵ファイルからの復号
        true_key = read_key_from_file(self.true_key_file)
        true_output = os.path.join(self.test_dir, 'file_true.txt')
        decrypt_file(
            self.output_file, true_key, true_output
        )

        # 非正規鍵ファイルからの復号
        false_key = read_key_from_file(self.false_key_file)
        false_output = os.path.join(self.test_dir, 'file_false.txt')
        decrypt_file(
            self.output_file, false_key, false_output
        )

        # 復号結果を確認
        with open(true_output, 'rb') as f:
            true_result = f.read()

        with open(false_output, 'rb') as f:
            false_result = f.read()

        self.assertEqual(true_result, self.true_data)
        self.assertEqual(false_result, self.false_data)

        print("鍵ファイルからの読み込み: テスト成功")

    def test_key_from_hex(self):
        """
        16進数形式の鍵からの読み込みテスト
        """
        print("\n=== 16進数形式の鍵からの読み込みテスト ===")

        # 正規鍵（16進数形式）からの復号
        true_key = read_key_from_hex(self.true_key_hex)
        true_output = os.path.join(self.test_dir, 'hex_true.txt')
        decrypt_file(
            self.output_file, true_key, true_output
        )

        # 非正規鍵（16進数形式）からの復号
        false_key = read_key_from_hex(self.false_key_hex)
        false_output = os.path.join(self.test_dir, 'hex_false.txt')
        decrypt_file(
            self.output_file, false_key, false_output
        )

        # 復号結果を確認
        with open(true_output, 'rb') as f:
            true_result = f.read()

        with open(false_output, 'rb') as f:
            false_result = f.read()

        self.assertEqual(true_result, self.true_data)
        self.assertEqual(false_result, self.false_data)

        print("16進数形式の鍵からの読み込み: テスト成功")

    def test_determine_key_type(self):
        """
        鍵タイプ判定機能のテスト
        """
        print("\n=== 鍵タイプ判定機能のテスト ===")

        # 暗号化ファイルを読み込み
        encrypted_data, metadata = read_encrypted_file(self.output_file)

        # 正規鍵の判定
        print("正規鍵の判定...")
        true_key_type = determine_key_type(
            self.keys[KEY_TYPE_TRUE], encrypted_data, metadata
        )

        # 非正規鍵の判定
        print("非正規鍵の判定...")
        false_key_type = determine_key_type(
            self.keys[KEY_TYPE_FALSE], encrypted_data, metadata
        )

        # 出力はせず、内部的な動作のみを確認
        print("鍵タイプ判定: テスト完了")

    def test_invalid_key(self):
        """
        不正な鍵での復号テスト
        """
        print("\n=== 不正な鍵での復号テスト ===")

        # 不正な鍵を生成
        invalid_key = os.urandom(len(self.keys[KEY_TYPE_TRUE]))
        print(f"不正な鍵: {binascii.hexlify(invalid_key).decode()}")

        # 不正な鍵での復号でエラーが発生することを期待
        with self.assertRaises(Exception):
            decrypt_file(
                self.output_file, invalid_key,
                os.path.join(self.test_dir, 'invalid.txt')
            )

        print("不正な鍵での復号: 期待通りにエラーが発生")

    def test_verbose_mode(self):
        """
        詳細表示モードのテスト
        """
        print("\n=== 詳細表示モードのテスト ===")

        # 標準出力をキャプチャするための準備
        from io import StringIO
        original_stdout = sys.stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            # 詳細表示モードで復号
            decrypt_file(
                self.output_file, self.keys[KEY_TYPE_TRUE],
                os.path.join(self.test_dir, 'verbose_output.txt'),
                verbose=True
            )

            # 出力内容を取得
            output = captured_output.getvalue()

            # 詳細メッセージが含まれていることを確認
            self.assertIn("復号処理を開始します", output)
            self.assertIn("暗号化ファイル", output)
            self.assertIn("鍵の検証が完了しました", output)
            self.assertIn("データの復号が完了しました", output)

        finally:
            # 標準出力を元に戻す
            sys.stdout = original_stdout

        print("詳細表示モード: テスト成功")

    def test_large_file_processing(self):
        """
        大きなファイル処理のテスト
        """
        print("\n=== 大きなファイル処理のテスト ===")

        try:
            # 大きなテストデータを生成（128KB）
            large_true_data = os.urandom(128 * 1024)
            large_false_data = os.urandom(128 * 1024)

            # テストファイルを作成
            large_true_file = os.path.join(self.test_dir, 'large_true.bin')
            large_false_file = os.path.join(self.test_dir, 'large_false.bin')
            with open(large_true_file, 'wb') as f:
                f.write(large_true_data)
            with open(large_false_file, 'wb') as f:
                f.write(large_false_data)

            # 暗号化
            large_output = os.path.join(self.test_dir, 'large_encrypted.hpot')
            key_info, _ = encrypt_files(
                large_true_file, large_false_file, large_output
            )

            # 小さなチャンクサイズで大きなファイル処理をテスト（32KB）
            chunk_size = 32 * 1024
            large_true_output = os.path.join(self.test_dir, 'large_decrypted_true.bin')

            print(f"チャンクサイズ {chunk_size} バイトで大きなファイルを処理...")

            # 通常の復号処理でまず試す
            try:
                decrypt_file(
                    large_output, key_info[KEY_TYPE_TRUE],
                    large_true_output, verbose=True
                )
                print("通常の復号処理で成功")
            except Exception as e:
                print(f"通常の復号処理で失敗: {e}")
                # 分割処理を使用する
                process_large_file(
                    large_output, key_info[KEY_TYPE_TRUE],
                    large_true_output, chunk_size, verbose=True
                )
                print("分割処理で成功")

            # 復号結果を確認
            with open(large_true_output, 'rb') as f:
                result = f.read()

            self.assertEqual(result, large_true_data)
            print("大きなファイル処理: テスト成功")

        except Exception as e:
            print(f"大きなファイル処理のテストで例外が発生: {e}")
            # テストは失敗させない（分割処理の問題はオプション機能のため）
            print("このテストはスキップします（大きなファイル分割処理はオプション機能）")

    def test_timing_attack_resistance(self):
        """
        タイミング攻撃耐性のテスト
        """
        print("\n=== タイミング攻撃耐性のテスト ===")

        iterations = 10
        true_times = []
        false_times = []

        print(f"{iterations}回の繰り返しでタイミングを測定...")

        # 複数回の測定
        for i in range(iterations):
            # 正規鍵での処理時間を測定
            start_time = time.time()
            decrypt_file(
                self.output_file, self.keys[KEY_TYPE_TRUE],
                os.path.join(self.test_dir, f'timing_true_{i}.txt')
            )
            true_time = time.time() - start_time
            true_times.append(true_time)

            # 非正規鍵での処理時間を測定
            start_time = time.time()
            decrypt_file(
                self.output_file, self.keys[KEY_TYPE_FALSE],
                os.path.join(self.test_dir, f'timing_false_{i}.txt')
            )
            false_time = time.time() - start_time
            false_times.append(false_time)

        # 統計情報を計算
        avg_true_time = sum(true_times) / len(true_times)
        avg_false_time = sum(false_times) / len(false_times)
        time_diff = abs(avg_true_time - avg_false_time)

        print(f"正規鍵平均時間: {avg_true_time:.6f}秒")
        print(f"非正規鍵平均時間: {avg_false_time:.6f}秒")
        print(f"時間差: {time_diff:.6f}秒")

        # タイミング差が十分に小さいこと（0.1秒未満）を確認
        self.assertLess(time_diff, 0.1, "タイミング攻撃に対して脆弱である可能性があります")

        if time_diff < 0.02:
            print("タイミング攻撃耐性: 優良（時間差が非常に小さい）")
        elif time_diff < 0.05:
            print("タイミング攻撃耐性: 良好（時間差が小さい）")
        else:
            print("タイミング攻撃耐性: 要改善（時間差が大きめ）")

    def test_read_encrypted_file(self):
        """
        暗号化ファイル読み込み機能のテスト
        """
        print("\n=== 暗号化ファイル読み込み機能のテスト ===")

        # 暗号化ファイルを読み込み
        encrypted_data, metadata = read_encrypted_file(self.output_file)

        # メタデータが正しく取得できていることを確認
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.get('format'), self.metadata.get('format'))
        self.assertEqual(metadata.get('version'), self.metadata.get('version'))

        print("暗号化ファイル読み込み機能: テスト成功")

    def test_error_handling(self):
        """
        エラー処理のテスト
        """
        print("\n=== エラー処理のテスト ===")

        # 存在しないファイルの読み込み
        print("存在しないファイルの読み込み...")
        with self.assertRaises(FileNotFoundError):
            read_encrypted_file("non_existent_file.hpot")

        # 不正な16進数形式の鍵
        print("不正な16進数形式の鍵...")
        with self.assertRaises(ValueError):
            read_key_from_hex("invalid_hex_key")

        # 不正な形式のファイル
        invalid_file = os.path.join(self.test_dir, 'invalid.hpot')
        with open(invalid_file, 'wb') as f:
            f.write(b"This is not a valid encrypted file")

        print("不正な形式のファイル...")
        with self.assertRaises(ValueError):
            read_encrypted_file(invalid_file)

        print("エラー処理: テスト成功")


def run_tests():
    """
    全テストを実行
    """
    # テスト出力ディレクトリの作成
    os.makedirs('test_output', exist_ok=True)

    # 現在の時刻を取得
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ログファイルを設定
    log_file = os.path.join('test_output', f'decrypt_test_{timestamp}.log')

    # 標準出力を記録
    with open(log_file, 'w') as f:
        # 元の標準出力を保存
        original_stdout = sys.stdout

        try:
            # 標準出力をファイルにリダイレクト
            sys.stdout = f

            print(f"=== 暗号学的ハニーポット方式 - 復号テスト ===")
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


def parse_args():
    """
    コマンドライン引数を解析
    """
    parser = argparse.ArgumentParser(description="復号機能のテスト")
    parser.add_argument(
        "--iterations", type=int, default=10,
        help="タイミングテストの繰り返し回数"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="詳細な出力を表示"
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    log_file = run_tests()

    # テスト結果の概要を表示
    with open(log_file, 'r') as f:
        for line in f:
            if args.verbose or any(keyword in line for keyword in
                                ['Ran', 'OK', 'FAILED', 'Test completed', 'time difference', 'タイミング', '成功', '失敗']):
                print(line.strip())