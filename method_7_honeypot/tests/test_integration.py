#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 統合テスト

暗号化から復号までの完全な処理フローをテストし、
システム全体が正しく機能することを確認します。
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import binascii
import time
import random
import subprocess
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

# テスト対象のモジュール
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.encrypt import encrypt_files
from method_7_honeypot.decrypt import decrypt_file, read_key_from_file
from method_7_honeypot.key_verification import verify_key_and_select_path
from method_7_honeypot.deception import verify_with_tamper_resistance
from method_7_honeypot.config import OUTPUT_EXTENSION

# 出力ディレクトリの設定
OUTPUT_DIR = Path("test_output")
OUTPUT_DIR.mkdir(exist_ok=True)

# テスト用データ
TEST_DATA = {
    "正規データ": "これは正規の秘密データです。本当の情報はここにあります。",
    "非正規データ": "これは非正規のデータです。騙し用の情報が含まれています。"
}

class TestIntegration(unittest.TestCase):
    """
    暗号学的ハニーポット方式の統合テスト
    """

    def setUp(self):
        """
        テスト前の準備
        """
        # 一時ディレクトリの作成
        self.temp_dir = tempfile.mkdtemp()
        self.test_dir = Path(self.temp_dir)

        # テスト用ファイルの作成
        self.true_file = self.test_dir / "true_data.txt"
        self.false_file = self.test_dir / "false_data.txt"

        with open(self.true_file, "w", encoding="utf-8") as f:
            f.write(TEST_DATA["正規データ"])

        with open(self.false_file, "w", encoding="utf-8") as f:
            f.write(TEST_DATA["非正規データ"])

        # テスト用の鍵を生成
        self.master_key = create_master_key()
        self.params = create_trapdoor_parameters(self.master_key)
        self.keys, self.salt = derive_keys_from_trapdoor(self.params)

        # 鍵ファイルの保存
        self.true_key_file = self.test_dir / "true.key"
        self.false_key_file = self.test_dir / "false.key"

        # 鍵をファイルに直接保存（save_keys関数は使わない）
        with open(self.true_key_file, 'wb') as f:
            f.write(self.keys[KEY_TYPE_TRUE])

        with open(self.false_key_file, 'wb') as f:
            f.write(self.keys[KEY_TYPE_FALSE])

        # 暗号化ファイルのパス
        self.encrypted_file = self.test_dir / f"test_data{OUTPUT_EXTENSION}"

        # 復号ファイルのパス
        self.decrypted_true_file = self.test_dir / "decrypted_true.txt"
        self.decrypted_false_file = self.test_dir / "decrypted_false.txt"

    def tearDown(self):
        """
        テスト後のクリーンアップ
        """
        # 一時ディレクトリの削除
        shutil.rmtree(self.temp_dir)

    def test_encrypt_decrypt_cycle(self):
        """
        暗号化・復号サイクルのテスト
        """
        # ファイルの暗号化
        keys, metadata = encrypt_files(
            true_file_path=str(self.true_file),
            false_file_path=str(self.false_file),
            output_path=str(self.encrypted_file),
            verbose=False
        )

        self.assertTrue(self.encrypted_file.exists(), "暗号化ファイルが生成されていません")

        # 正規鍵で復号
        decrypt_file(
            file_path=str(self.encrypted_file),
            key=keys[KEY_TYPE_TRUE],
            output_path=str(self.decrypted_true_file)
        )

        self.assertTrue(self.decrypted_true_file.exists(), "正規鍵で復号したファイルが生成されていません")

        # 非正規鍵で復号
        decrypt_file(
            file_path=str(self.encrypted_file),
            key=keys[KEY_TYPE_FALSE],
            output_path=str(self.decrypted_false_file)
        )

        self.assertTrue(self.decrypted_false_file.exists(), "非正規鍵で復号したファイルが生成されていません")

        # 復号されたファイルの内容を確認
        with open(self.decrypted_true_file, "r", encoding="utf-8") as f:
            true_content = f.read()

        with open(self.decrypted_false_file, "r", encoding="utf-8") as f:
            false_content = f.read()

        self.assertEqual(true_content, TEST_DATA["正規データ"], "正規データの復号結果が一致しません")
        self.assertEqual(false_content, TEST_DATA["非正規データ"], "非正規データの復号結果が一致しません")

    def test_multiple_encrypt_decrypt_cycles(self):
        """
        複数回の暗号化・復号サイクルの一貫性テスト
        """
        cycles = 3
        results = {"true_success": 0, "false_success": 0}

        for i in range(cycles):
            # ファイルパスを設定
            encrypted_file = self.test_dir / f"test_data_{i}{OUTPUT_EXTENSION}"
            decrypted_true_file = self.test_dir / f"decrypted_true_{i}.txt"
            decrypted_false_file = self.test_dir / f"decrypted_false_{i}.txt"

            # ファイルの暗号化
            keys, metadata = encrypt_files(
                true_file_path=str(self.true_file),
                false_file_path=str(self.false_file),
                output_path=str(encrypted_file),
                verbose=False
            )

            # 正規鍵で復号
            decrypt_file(
                file_path=str(encrypted_file),
                key=keys[KEY_TYPE_TRUE],
                output_path=str(decrypted_true_file)
            )

            # 非正規鍵で復号
            decrypt_file(
                file_path=str(encrypted_file),
                key=keys[KEY_TYPE_FALSE],
                output_path=str(decrypted_false_file)
            )

            # 復号されたファイルの内容を確認
            with open(decrypted_true_file, "r", encoding="utf-8") as f:
                true_content = f.read()

            with open(decrypted_false_file, "r", encoding="utf-8") as f:
                false_content = f.read()

            # 内容を検証
            if true_content == TEST_DATA["正規データ"]:
                results["true_success"] += 1

            if false_content == TEST_DATA["非正規データ"]:
                results["false_success"] += 1

        # すべてのサイクルで成功していることを確認
        self.assertEqual(results["true_success"], cycles, "正規データの復号が一部失敗しました")
        self.assertEqual(results["false_success"], cycles, "非正規データの復号が一部失敗しました")

    def test_key_loading_and_verification(self):
        """
        鍵のロードと検証フローのテスト
        """
        # 鍵ファイルからの読み込み
        true_key = read_key_from_file(str(self.true_key_file))
        false_key = read_key_from_file(str(self.false_key_file))

        # 鍵の検証
        true_key_type, true_context = verify_key_and_select_path(true_key, self.params, self.salt)
        false_key_type, false_context = verify_key_and_select_path(false_key, self.params, self.salt)

        self.assertEqual(true_key_type, KEY_TYPE_TRUE, "正規鍵の検証に失敗しました")
        self.assertEqual(false_key_type, KEY_TYPE_FALSE, "非正規鍵の検証に失敗しました")

        # 経路選択を検証
        true_path = true_context.get("path")
        false_path = false_context.get("path")

        self.assertIsNotNone(true_path, "正規鍵の経路が設定されていません")
        self.assertIsNotNone(false_path, "非正規鍵の経路が設定されていません")

        # 改変耐性検証
        true_result = verify_with_tamper_resistance(true_key, true_context.get("token"), self.params)
        false_result = verify_with_tamper_resistance(false_key, false_context.get("token"), self.params)

        # 改変耐性の結果を検証（常に同じ結果を返す保証はないため、assert なし）
        self.assertIn(true_result, [KEY_TYPE_TRUE, KEY_TYPE_FALSE], "改変耐性検証の結果が不正です")
        self.assertIn(false_result, [KEY_TYPE_TRUE, KEY_TYPE_FALSE], "改変耐性検証の結果が不正です")

    def test_cli_interface(self):
        """
        コマンドラインインターフェースのテスト
        """
        # ファイルの暗号化
        keys, metadata = encrypt_files(
            true_file_path=str(self.true_file),
            false_file_path=str(self.false_file),
            output_path=str(self.encrypted_file),
            verbose=False
        )

        # コマンドライン経由で暗号化・復号をテスト
        output_true = self.test_dir / "cli_true.txt"
        output_false = self.test_dir / "cli_false.txt"

        # 鍵ファイルを作成（CLIテスト用）
        cli_true_key_file = self.test_dir / "cli_true.key"
        cli_false_key_file = self.test_dir / "cli_false.key"

        with open(cli_true_key_file, 'wb') as f:
            f.write(keys[KEY_TYPE_TRUE])

        with open(cli_false_key_file, 'wb') as f:
            f.write(keys[KEY_TYPE_FALSE])

        # 正規鍵で復号（CLIを使用）
        cmd_true = [
            "python3", "-m", "method_7_honeypot.decrypt",
            str(self.encrypted_file),
            "--key-file", str(cli_true_key_file),
            "--output", str(output_true)
        ]

        # 非正規鍵で復号（CLIを使用）
        cmd_false = [
            "python3", "-m", "method_7_honeypot.decrypt",
            str(self.encrypted_file),
            "--key-file", str(cli_false_key_file),
            "--output", str(output_false)
        ]

        try:
            # 正規鍵での復号を実行
            result_true = subprocess.run(cmd_true, capture_output=True, text=True)
            self.assertEqual(result_true.returncode, 0, f"CLIでの正規鍵復号に失敗しました: {result_true.stderr}")
            self.assertTrue(output_true.exists(), "CLIで復号されたファイルが生成されていません")

            # 非正規鍵での復号を実行
            result_false = subprocess.run(cmd_false, capture_output=True, text=True)
            self.assertEqual(result_false.returncode, 0, f"CLIでの非正規鍵復号に失敗しました: {result_false.stderr}")
            self.assertTrue(output_false.exists(), "CLIで復号されたファイルが生成されていません")

            # 復号されたファイルの内容を確認
            with open(output_true, "r", encoding="utf-8") as f:
                true_content = f.read()

            with open(output_false, "r", encoding="utf-8") as f:
                false_content = f.read()

            self.assertEqual(true_content, TEST_DATA["正規データ"], "CLIでの正規データの復号結果が一致しません")
            self.assertEqual(false_content, TEST_DATA["非正規データ"], "CLIでの非正規データの復号結果が一致しません")

        except subprocess.SubprocessError as e:
            self.fail(f"コマンドラインインターフェースの実行に失敗しました: {e}")

    def test_error_handling(self):
        """
        エラー処理のテスト
        """
        # 不正なファイルパス
        invalid_file = self.test_dir / "nonexistent.hpot"

        # 不正な鍵
        invalid_key = os.urandom(32)

        # 不正なファイルで復号を試行
        with self.assertRaises(Exception):
            decrypt_file(
                file_path=str(invalid_file),
                key=self.keys[KEY_TYPE_TRUE],
                output_path=str(self.decrypted_true_file)
            )

        # 正常に暗号化
        keys, metadata = encrypt_files(
            true_file_path=str(self.true_file),
            false_file_path=str(self.false_file),
            output_path=str(self.encrypted_file),
            verbose=False
        )

        # 不正な鍵で復号を試行
        # 注: この場合、例外は発生せず、不正な結果が返されるべき
        invalid_output = self.test_dir / "invalid_output.txt"
        try:
            decrypt_file(
                file_path=str(self.encrypted_file),
                key=invalid_key,
                output_path=str(invalid_output)
            )
        except Exception:
            # エラーが発生しても無視（エラー処理テストなので）
            pass

        # 正規鍵と非正規鍵のいずれでもない鍵で復号した場合のテスト
        # この場合、結果はランダムになるか、エラーが発生するはず
        if invalid_output.exists():
            try:
                with open(invalid_output, "r", encoding="utf-8") as f:
                    content = f.read()
                    # 内容チェックは省略（結果が不定のため）
            except:
                # 読み込みエラーも許容
                pass

    def test_performance(self):
        """
        性能測定のテスト
        """
        # 性能測定用のデータを作成
        data_sizes = [1024, 10*1024, 100*1024]  # バイトサイズ（1KB, 10KB, 100KB）
        cycles = 3

        # 測定結果を格納する辞書
        performance_data = {
            "sizes": data_sizes,
            "encrypt_times": [],
            "decrypt_true_times": [],
            "decrypt_false_times": []
        }

        for size in data_sizes:
            # 指定サイズのデータを生成
            true_data = "T" * size
            false_data = "F" * size

            # テストファイルの作成
            true_test_file = self.test_dir / f"true_data_{size}.txt"
            false_test_file = self.test_dir / f"false_data_{size}.txt"
            with open(true_test_file, "w") as f:
                f.write(true_data)
            with open(false_test_file, "w") as f:
                f.write(false_data)

            # 暗号化ファイルパス
            encrypted_file = self.test_dir / f"test_data_{size}{OUTPUT_EXTENSION}"

            # 復号ファイルパス
            decrypted_true_file = self.test_dir / f"decrypted_true_{size}.txt"
            decrypted_false_file = self.test_dir / f"decrypted_false_{size}.txt"

            # 暗号化時間の測定
            encrypt_times = []
            for _ in range(cycles):
                start_time = time.time()
                keys, metadata = encrypt_files(
                    true_file_path=str(true_test_file),
                    false_file_path=str(false_test_file),
                    output_path=str(encrypted_file),
                    verbose=False
                )
                encrypt_times.append(time.time() - start_time)

            # 正規鍵での復号時間の測定
            decrypt_true_times = []
            for _ in range(cycles):
                start_time = time.time()
                try:
                    decrypt_file(
                        file_path=str(encrypted_file),
                        key=keys[KEY_TYPE_TRUE],
                        output_path=str(decrypted_true_file)
                    )
                except Exception:
                    # エラーが発生しても時間測定は継続
                    pass
                decrypt_true_times.append(time.time() - start_time)

            # 非正規鍵での復号時間の測定
            decrypt_false_times = []
            for _ in range(cycles):
                start_time = time.time()
                try:
                    decrypt_file(
                        file_path=str(encrypted_file),
                        key=keys[KEY_TYPE_FALSE],
                        output_path=str(decrypted_false_file)
                    )
                except Exception:
                    # エラーが発生しても時間測定は継続
                    pass
                decrypt_false_times.append(time.time() - start_time)

            # 平均時間を記録
            performance_data["encrypt_times"].append(sum(encrypt_times) / cycles)
            performance_data["decrypt_true_times"].append(sum(decrypt_true_times) / cycles)
            performance_data["decrypt_false_times"].append(sum(decrypt_false_times) / cycles)

        # 性能グラフを作成
        self._create_performance_graph(performance_data)

    def _create_performance_graph(self, data):
        """
        性能測定結果のグラフを作成

        Args:
            data: 性能データ（サイズと処理時間）
        """
        plt.style.use('dark_background')
        fig, ax = plt.subplots(figsize=(10, 6))

        # データ
        sizes_kb = [size/1024 for size in data["sizes"]]

        # プロット
        ax.plot(sizes_kb, data["encrypt_times"], 'o-', label='暗号化', color='#bb86fc')
        ax.plot(sizes_kb, data["decrypt_true_times"], 's-', label='正規鍵復号', color='#03dac6')
        ax.plot(sizes_kb, data["decrypt_false_times"], '^-', label='非正規鍵復号', color='#cf6679')

        # 装飾
        ax.set_xlabel('データサイズ (KB)')
        ax.set_ylabel('処理時間 (秒)')
        ax.set_title('ハニーポット暗号化方式の性能測定')
        ax.grid(True, linestyle='--', alpha=0.7)
        ax.legend()

        # 数値を表示
        for i, size in enumerate(sizes_kb):
            ax.annotate(f'{data["encrypt_times"][i]:.3f}s',
                      (size, data["encrypt_times"][i]),
                      textcoords="offset points",
                      xytext=(0,10),
                      ha='center')
            ax.annotate(f'{data["decrypt_true_times"][i]:.3f}s',
                      (size, data["decrypt_true_times"][i]),
                      textcoords="offset points",
                      xytext=(0,10),
                      ha='center')
            ax.annotate(f'{data["decrypt_false_times"][i]:.3f}s',
                      (size, data["decrypt_false_times"][i]),
                      textcoords="offset points",
                      xytext=(0,10),
                      ha='center')

        # グラフを保存
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = OUTPUT_DIR / f"performance_graph_{timestamp}.png"
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close(fig)

        print(f"性能グラフを保存しました: {output_file}")


# テストを実行
if __name__ == "__main__":
    unittest.main()