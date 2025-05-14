#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - テストスイート実行スクリプト

すべてのテストを実行し、結果を集約して表示します。
また、テスト実行のタイミング情報や成功/失敗の統計情報も提供します。
"""

import os
import sys
import time
import unittest
import importlib
import subprocess
import traceback
import argparse
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# matplotlib設定
plt.style.use('dark_background')

# 実行するテストモジュールのリスト
TEST_MODULES = [
    'method_7_honeypot.tests.test_trapdoor',
    'method_7_honeypot.tests.test_key_verification',
    'method_7_honeypot.tests.test_encrypt_decrypt',
    'method_7_honeypot.tests.test_tamper_resistance',
    'method_7_honeypot.tests.test_capsule',
    'method_7_honeypot.tests.test_integration'
]

# 出力ディレクトリの設定
OUTPUT_DIR = Path("test_output")
OUTPUT_DIR.mkdir(exist_ok=True)

# テスト結果の集計用クラス
class TestResults:
    """テスト結果を集計するクラス"""

    def __init__(self):
        self.modules = []
        self.total_tests = 0
        self.successes = 0
        self.failures = 0
        self.errors = 0
        self.skipped = 0
        self.total_time = 0
        self.module_times = {}
        self.module_results = {}

    def add_result(self, module_name, result, time_taken):
        """テスト結果を追加"""
        self.modules.append(module_name)
        self.total_tests += result.testsRun
        self.failures += len(result.failures)
        self.errors += len(result.errors)
        self.skipped += len(result.skipped)
        self.successes += result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
        self.total_time += time_taken
        self.module_times[module_name] = time_taken
        self.module_results[module_name] = {
            'tests': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'skipped': len(result.skipped),
            'success': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
        }

    def is_successful(self):
        """すべてのテストが成功したかどうか"""
        return self.failures == 0 and self.errors == 0

    def create_time_graph(self):
        """実行時間グラフを作成"""
        plt.figure(figsize=(10, 6))

        # データ準備
        modules = list(self.module_times.keys())
        times = list(self.module_times.values())

        # モジュール名を短くする
        short_names = [m.split('.')[-1] for m in modules]

        # グラフ作成
        plt.barh(short_names, times, color='#bb86fc')
        plt.xlabel('実行時間 (秒)')
        plt.ylabel('テストモジュール')
        plt.title('テストモジュール別実行時間')
        plt.grid(axis='x', linestyle='--', alpha=0.7)

        # 値を表示
        for i, v in enumerate(times):
            plt.text(v + 0.1, i, f"{v:.2f}s", va='center')

        # ファイル保存
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = OUTPUT_DIR / f"test_time_graph_{timestamp}.png"
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()

        return output_file

    def create_result_graph(self):
        """テスト結果グラフを作成"""
        plt.figure(figsize=(8, 8))

        # データ準備
        labels = ['成功', '失敗', 'エラー', 'スキップ']
        sizes = [self.successes, self.failures, self.errors, self.skipped]
        colors = ['#03dac6', '#cf6679', '#ff7597', '#ffb74d']

        # 0のカテゴリを省く
        filtered_labels = []
        filtered_sizes = []
        filtered_colors = []
        for i, size in enumerate(sizes):
            if size > 0:
                filtered_labels.append(labels[i])
                filtered_sizes.append(size)
                filtered_colors.append(colors[i])

        # グラフ作成
        if filtered_sizes:  # データがある場合のみ
            plt.pie(filtered_sizes, labels=filtered_labels, colors=filtered_colors,
                   autopct='%1.1f%%', startangle=90, shadow=True)
            plt.axis('equal')
            plt.title('テスト結果の内訳')

            # ファイル保存
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = OUTPUT_DIR / f"test_result_graph_{timestamp}.png"
            plt.tight_layout()
            plt.savefig(output_file)
            plt.close()

            return output_file

        return None


def run_test_module(module_name):
    """指定されたテストモジュールを実行"""
    print(f"モジュール {module_name} のテスト実行中...")
    try:
        # モジュールをインポート
        module = importlib.import_module(module_name)

        # テスト実行
        start_time = time.time()
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        time_taken = time.time() - start_time

        print(f"テスト実行完了: {result.testsRun}テスト, "
              f"成功: {result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)}, "
              f"失敗: {len(result.failures)}, エラー: {len(result.errors)}, "
              f"スキップ: {len(result.skipped)}, 時間: {time_taken:.2f}秒")

        return result, time_taken

    except Exception as e:
        print(f"モジュール {module_name} のテスト実行中にエラーが発生しました:")
        traceback.print_exc()

        # ダミーの結果を返す
        result = unittest.TestResult()
        result.testsRun = 0
        result.errors = [(None, traceback.format_exc())]
        return result, 0


def discover_and_run_tests():
    """テストを自動検出して実行"""
    test_results = TestResults()

    print("=== 暗号学的ハニーポット方式 - テストスイート ===")
    print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python バージョン: {sys.version}")
    print(f"実行モジュール: {len(TEST_MODULES)}")
    print()

    for module_name in TEST_MODULES:
        result, time_taken = run_test_module(module_name)
        test_results.add_result(module_name, result, time_taken)
        print()  # 空行を挿入

    print("===== テスト実行サマリー =====")
    print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"テストモジュール数: {len(test_results.modules)}")
    print(f"成功: {test_results.successes}")
    print(f"失敗: {test_results.failures}")
    print(f"エラー: {test_results.errors}")
    print(f"スキップ: {test_results.skipped}")
    print(f"総実行時間: {test_results.total_time:.2f}秒")

    # グラフ作成
    time_graph = test_results.create_time_graph()
    result_graph = test_results.create_result_graph()

    print(f"\n実行時間グラフ: {time_graph}")
    if result_graph:
        print(f"結果グラフ: {result_graph}")

    return test_results.is_successful()


def run_all_tests_with_discover():
    """テストの検出とテストスイートの実行"""
    print("テストを検出しています...")

    # テストを検出し実行
    loader = unittest.TestLoader()
    start_dir = 'method_7_honeypot/tests'
    suite = loader.discover(start_dir, pattern='test_*.py')

    # テスト結果の保存先
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = OUTPUT_DIR / f"test_results_{timestamp}.log"

    # テストを実行
    with open(log_file, 'w') as f:
        # 元の標準出力を保存
        original_stdout = sys.stdout
        original_stderr = sys.stderr

        try:
            # 標準出力をファイルにリダイレクト
            sys.stdout = f
            sys.stderr = f

            print(f"=== 暗号学的ハニーポット方式 - テストスイート ===")
            print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Python バージョン: {sys.version}")
            print(f"テスト開始...\n")

            start_time = time.time()
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            end_time = time.time()

            print(f"\n===== テスト実行サマリー =====")
            print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"テスト数: {result.testsRun}")
            print(f"成功: {result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)}")
            print(f"失敗: {len(result.failures)}")
            print(f"エラー: {len(result.errors)}")
            print(f"スキップ: {len(result.skipped)}")
            print(f"総実行時間: {end_time - start_time:.2f}秒")

        finally:
            # 標準出力を元に戻す
            sys.stdout = original_stdout
            sys.stderr = original_stderr

    print(f"テスト結果がログファイルに保存されました: {log_file}")

    # 結果の概要を表示
    with open(log_file, 'r') as f:
        for line in f:
            if 'サマリー' in line or 'テスト数:' in line or '成功:' in line or '失敗:' in line or 'エラー:' in line:
                print(line.strip())

    # 成功したかどうかを返す
    return len(result.failures) == 0 and len(result.errors) == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='暗号学的ハニーポット方式のテストを実行します。')
    parser.add_argument('--discover', action='store_true', help='テストを自動検出して実行します')
    parser.add_argument('--modules', action='store_true', help='個別のモジュールテストを実行します（デフォルト）')

    args = parser.parse_args()

    if args.discover:
        success = run_all_tests_with_discover()
    else:
        success = discover_and_run_tests()

    # 終了コードを設定
    sys.exit(0 if success else 1)