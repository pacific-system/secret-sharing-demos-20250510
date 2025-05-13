#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式のテスト実行スクリプト

このスクリプトは、準同型暗号マスキング方式の各種テストを実行し、
結果をレポート形式で出力します。また、パフォーマンス計測機能も含みます。
"""

import os
import sys
import time
import json
import unittest
import argparse
import logging
import datetime
import importlib
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any, List, Tuple, Union, Optional

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# ユーティリティモジュールのインポート
from method_8_homomorphic.debug_utils import CryptoDebugger

# ロガーの設定
logger = logging.getLogger("homomorphic_test_runner")
logger.setLevel(logging.INFO)

# 出力ディレクトリの作成
os.makedirs("test_output", exist_ok=True)

# ファイルハンドラーの追加
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join("test_output", f"test_run_{timestamp}.log")
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# コンソールハンドラーの追加
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# フォーマッターの設定
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# ハンドラーをロガーに追加
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class TestRunner:
    """テスト実行クラス"""

    def __init__(self, test_modules: List[str], debug_mode: bool = False,
                 performance_mode: bool = False, report_file: Optional[str] = None):
        """
        テスト実行クラスの初期化

        Args:
            test_modules: テストモジュールのリスト
            debug_mode: デバッグモードフラグ
            performance_mode: パフォーマンス測定モードフラグ
            report_file: レポート出力ファイルパス（デフォルトはタイムスタンプ付きの名前）
        """
        self.test_modules = test_modules
        self.debug_mode = debug_mode
        self.performance_mode = performance_mode

        if report_file:
            self.report_file = report_file
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.report_file = os.path.join("test_output", f"test_report_{timestamp}.json")

        self.results = {
            "start_time": None,
            "end_time": None,
            "total_elapsed": None,
            "test_modules": {},
            "performance": {},
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "skipped": 0
            }
        }

        self.debugger = CryptoDebugger(debug_level="DEBUG" if debug_mode else "INFO")

    def import_test_module(self, module_name: str) -> unittest.TestSuite:
        """
        テストモジュールのインポートとテストスイートの取得

        Args:
            module_name: テストモジュール名

        Returns:
            テストスイート
        """
        try:
            # モジュールのインポート
            module = importlib.import_module(module_name)

            # ロガーの設定
            module_logger = logging.getLogger(module_name)
            module_logger.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)
            module_logger.addHandler(file_handler)

            # テストローダーの作成
            loader = unittest.TestLoader()

            # モジュールからテストスイートをロード
            suite = loader.loadTestsFromModule(module)

            logger.info(f"Imported test module: {module_name} ({suite.countTestCases()} tests)")
            return suite

        except ImportError as e:
            logger.error(f"Failed to import test module {module_name}: {str(e)}")
            return unittest.TestSuite()  # 空のテストスイート

    def run_tests(self) -> Dict[str, Any]:
        """
        テストの実行

        Returns:
            テスト結果
        """
        self.results["start_time"] = time.time()

        logger.info(f"Starting test run with {len(self.test_modules)} modules")
        logger.info(f"Debug mode: {self.debug_mode}")
        logger.info(f"Performance mode: {self.performance_mode}")

        # 全テストモジュールの結果を格納
        for module_name in self.test_modules:
            logger.info(f"Running tests from module: {module_name}")

            # デバッグチェックポイント
            self.debugger.checkpoint(f"Starting module {module_name}")

            # モジュールのインポートとテストスイートの取得
            suite = self.import_test_module(module_name)

            # テスト実行用のランナーを作成
            runner = unittest.TextTestRunner(verbosity=2)

            # パフォーマンスモードの場合は時間を計測
            if self.performance_mode:
                module_start_time = time.time()

                # テストの実行
                result = runner.run(suite)

                module_end_time = time.time()
                module_elapsed = module_end_time - module_start_time

                # パフォーマンス情報の記録
                self.results["performance"][module_name] = {
                    "execution_time": module_elapsed,
                    "tests_per_second": suite.countTestCases() / module_elapsed if module_elapsed > 0 else float('inf')
                }
            else:
                # 通常モードでのテスト実行
                result = runner.run(suite)

            # テスト結果の記録
            self.results["test_modules"][module_name] = {
                "tests": suite.countTestCases(),
                "passed": suite.countTestCases() - len(result.failures) - len(result.errors) - len(result.skipped),
                "failed": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "failures": [{"test": str(test), "message": err} for test, err in result.failures],
                "errors_list": [{"test": str(test), "message": err} for test, err in result.errors]
            }

            # サマリー統計の更新
            self.results["summary"]["total_tests"] += suite.countTestCases()
            self.results["summary"]["passed"] += (suite.countTestCases() - len(result.failures) - len(result.errors) - len(result.skipped))
            self.results["summary"]["failed"] += len(result.failures)
            self.results["summary"]["errors"] += len(result.errors)
            self.results["summary"]["skipped"] += len(result.skipped)

            # デバッグチェックポイント
            self.debugger.checkpoint(f"Completed module {module_name}")

        self.results["end_time"] = time.time()
        self.results["total_elapsed"] = self.results["end_time"] - self.results["start_time"]

        # 成功率の計算
        total_tests = self.results["summary"]["total_tests"]
        passed_tests = self.results["summary"]["passed"]

        if total_tests > 0:
            self.results["summary"]["success_rate"] = passed_tests / total_tests * 100
        else:
            self.results["summary"]["success_rate"] = 0

        logger.info(f"Test run completed in {self.results['total_elapsed']:.2f} seconds")
        logger.info(f"Summary: {passed_tests}/{total_tests} tests passed "
                   f"({self.results['summary']['success_rate']:.2f}%)")

        # 結果をファイルに保存
        self.save_results()

        # テスト結果の可視化
        self.visualize_results()

        return self.results

    def save_results(self) -> str:
        """
        テスト結果をJSONファイルに保存

        Returns:
            保存したファイルのパス
        """
        # JSONシリアライズ可能な形式に変換
        serializable_results = {
            "start_time": self.results["start_time"],
            "end_time": self.results["end_time"],
            "total_elapsed": self.results["total_elapsed"],
            "test_modules": self.results["test_modules"],
            "performance": self.results["performance"],
            "summary": self.results["summary"],
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "environment": {
                "python_version": sys.version,
                "platform": sys.platform
            }
        }

        # JSONファイルへの書き込み
        with open(self.report_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)

        logger.info(f"Test results saved to {self.report_file}")
        return self.report_file

    def visualize_results(self) -> str:
        """
        テスト結果の可視化

        Returns:
            生成された画像ファイルのパス
        """
        # 出力ファイルパスの設定
        output_file = self.report_file.replace('.json', '.png')

        plt.figure(figsize=(15, 10))

        # モジュールごとのテスト結果
        plt.subplot(2, 2, 1)
        modules = list(self.results["test_modules"].keys())
        passed = [self.results["test_modules"][m]["passed"] for m in modules]
        failed = [self.results["test_modules"][m]["failed"] for m in modules]
        errors = [self.results["test_modules"][m]["errors"] for m in modules]
        skipped = [self.results["test_modules"][m]["skipped"] for m in modules]

        # モジュール名が長い場合は省略
        short_modules = [m[-20:] if len(m) > 20 else m for m in modules]

        # 横棒グラフで表示
        y_pos = range(len(modules))
        width = 0.65

        plt.barh(y_pos, passed, width, label='Passed', color='green')
        plt.barh(y_pos, failed, width, left=passed, label='Failed', color='red')
        plt.barh(y_pos, errors, width, left=[p+f for p, f in zip(passed, failed)], label='Errors', color='orange')
        plt.barh(y_pos, skipped, width, left=[p+f+e for p, f, e in zip(passed, failed, errors)], label='Skipped', color='gray')

        plt.yticks(y_pos, short_modules)
        plt.xlabel('Test Count')
        plt.title('Test Results by Module')
        plt.legend(loc='upper right')
        plt.grid(True, axis='x')

        # パフォーマンス結果（パフォーマンスモードの場合のみ）
        if self.performance_mode and self.results["performance"]:
            plt.subplot(2, 2, 2)

            # 実行時間
            execution_times = [self.results["performance"][m]["execution_time"] for m in modules]

            plt.barh(y_pos, execution_times)
            plt.yticks(y_pos, short_modules)
            plt.xlabel('Execution Time (seconds)')
            plt.title('Performance by Module')
            plt.grid(True, axis='x')
        else:
            # パフォーマンスデータがない場合は成功率を表示
            plt.subplot(2, 2, 2)

            total_by_module = [self.results["test_modules"][m]["tests"] for m in modules]
            passed_by_module = [self.results["test_modules"][m]["passed"] for m in modules]

            success_rates = [p/t*100 if t > 0 else 0 for p, t in zip(passed_by_module, total_by_module)]

            # 各バーの色を成功率に応じて設定
            colors = ['red' if r < 60 else 'orange' if r < 90 else 'green' for r in success_rates]

            plt.barh(y_pos, success_rates, color=colors)
            plt.yticks(y_pos, short_modules)
            plt.xlabel('Success Rate (%)')
            plt.title('Success Rate by Module')
            plt.xlim(0, 100)
            plt.grid(True, axis='x')

        # 概要パイチャート
        plt.subplot(2, 2, 3)
        summary = self.results["summary"]
        labels = ['Passed', 'Failed', 'Errors', 'Skipped']
        sizes = [summary["passed"], summary["failed"], summary["errors"], summary["skipped"]]
        colors = ['green', 'red', 'orange', 'gray']

        # サイズが0の項目を除外
        non_zero_labels = [l for l, s in zip(labels, sizes) if s > 0]
        non_zero_sizes = [s for s in sizes if s > 0]
        non_zero_colors = [c for c, s in zip(colors, sizes) if s > 0]

        if non_zero_sizes:
            plt.pie(non_zero_sizes, labels=non_zero_labels, colors=non_zero_colors, autopct='%1.1f%%',
                    startangle=90, shadow=True)
        else:
            plt.text(0.5, 0.5, "No tests were run",
                     horizontalalignment='center',
                     verticalalignment='center',
                     transform=plt.gca().transAxes)

        plt.axis('equal')
        plt.title('Test Result Summary')

        # 実行時間と統計情報
        plt.subplot(2, 2, 4)
        plt.axis('off')

        # 実行時間と統計情報のテキスト
        elapsed = self.results["total_elapsed"]
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)

        time_str = f"Total time: {int(hours)}h {int(minutes)}m {seconds:.2f}s"
        stat_str = f"Total tests: {summary['total_tests']}\n" \
                  f"Passed: {summary['passed']}\n" \
                  f"Failed: {summary['failed']}\n" \
                  f"Errors: {summary['errors']}\n" \
                  f"Skipped: {summary['skipped']}\n" \
                  f"Success rate: {summary['success_rate']:.2f}%"

        # タイムスタンプと環境情報
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        env_str = f"Python: {sys.version.split()[0]}\n" \
                 f"Platform: {sys.platform}"

        plt.text(0.05, 0.95, time_str, fontsize=12, verticalalignment='top')
        plt.text(0.05, 0.85, stat_str, fontsize=12, verticalalignment='top')
        plt.text(0.05, 0.35, f"Generated: {ts}", fontsize=10, verticalalignment='top')
        plt.text(0.05, 0.25, env_str, fontsize=10, verticalalignment='top')

        plt.tight_layout()
        plt.savefig(output_file)

        logger.info(f"Test results visualization saved to {output_file}")
        return output_file


def discover_test_modules() -> List[str]:
    """
    テストモジュールを自動検出

    Returns:
        検出されたテストモジュールのリスト
    """
    import glob

    # カレントディレクトリのパスを取得
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # テストファイルのパターンにマッチするファイルを検索
    test_files = glob.glob(os.path.join(current_dir, "test_*.py"))

    # ファイルパスからモジュール名に変換
    modules = []
    for file_path in test_files:
        # ファイル名を取得
        file_name = os.path.basename(file_path)

        # 拡張子を除去
        module_name = os.path.splitext(file_name)[0]

        # メソッド8の完全修飾名
        full_module_name = f"method_8_homomorphic.tests.{module_name}"

        modules.append(full_module_name)

    return sorted(modules)


def main():
    """メイン関数"""
    # コマンドライン引数のパース
    parser = argparse.ArgumentParser(description="準同型暗号マスキング方式のテスト実行スクリプト")

    parser.add_argument("-m", "--modules", nargs="+",
                       help="実行するテストモジュールのリスト（指定しない場合は自動検出）")
    parser.add_argument("-d", "--debug", action="store_true",
                       help="デバッグモード（詳細なログ出力）")
    parser.add_argument("-p", "--performance", action="store_true",
                       help="パフォーマンス測定モード")
    parser.add_argument("-o", "--output",
                       help="レポート出力ファイルパス")
    parser.add_argument("-a", "--all", action="store_true",
                       help="全てのテストを実行（デフォルト）")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="詳細な出力")

    args = parser.parse_args()

    # ログレベルの設定
    if args.verbose:
        console_handler.setLevel(logging.DEBUG)

    # テストモジュールの決定
    if args.modules:
        # コマンドライン引数で指定されたモジュール
        test_modules = [f"method_8_homomorphic.tests.{m}"
                       if not m.startswith("method_8_homomorphic.") else m
                       for m in args.modules]
    else:
        # 自動検出
        test_modules = discover_test_modules()

    logger.info(f"Discovered {len(test_modules)} test modules")

    # テストランナーの作成と実行
    runner = TestRunner(
        test_modules=test_modules,
        debug_mode=args.debug,
        performance_mode=args.performance,
        report_file=args.output
    )

    results = runner.run_tests()

    # 終了コードの設定（失敗があれば1、なければ0）
    if results["summary"]["failed"] > 0 or results["summary"]["errors"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()