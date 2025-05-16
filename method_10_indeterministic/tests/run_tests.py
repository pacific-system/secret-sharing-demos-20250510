"""
不確定性転写暗号化方式の全テスト実行

すべてのテストモジュールを実行し、結果を集計して表示します。
"""

import os
import sys
import time
import datetime
import matplotlib
matplotlib.use('Agg')  # GUIを使用せずに保存
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Any

# プロジェクトルートをインポートパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
method_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(method_dir)
sys.path.insert(0, project_root)

# テストモジュールをインポート
from method_10_indeterministic.tests.test_utils import TestResult, get_timestamp_str, TEST_OUTPUT_DIR
from method_10_indeterministic.tests.test_state_matrix import test_state_matrix_generation
from method_10_indeterministic.tests.test_probability_engine import test_probability_engine
from method_10_indeterministic.tests.test_integration import IntegrationTests
from method_10_indeterministic.tests.test_state_capsule import test_state_capsule_basic
from method_10_indeterministic.tests.test_runner import run_all_tests as run_capsule_tests

# 出力ディレクトリを確保
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

# ANSIカラーコード（ターミナル出力の色付け）
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_section_header(title):
    """セクションヘッダーを表示"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD} {title} {Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")


def print_result(test_name, passed, total, details=""):
    """テスト結果を色付きで表示"""
    if passed == total:
        color = Colors.GREEN
        status = "成功"
    elif passed > 0:
        color = Colors.YELLOW
        status = "一部成功"
    else:
        color = Colors.RED
        status = "失敗"

    print(f"{color}[{status}]{Colors.ENDC} {test_name}: {passed}/{total} ({(passed/total*100):.1f}%)")
    if details:
        print(f"  {details}")


def run_all_tests():
    """全テストを実行"""
    start_time = time.time()
    timestamp = get_timestamp_str()

    # 結果保存用の辞書
    all_results = {}

    print_section_header("不確定性転写暗号化方式 全テスト実行")
    print(f"開始時刻: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. 状態マトリス生成機構のテスト
    print_section_header("1. 状態マトリクス生成機構のテスト")
    matrix_results = test_state_matrix_generation()
    all_results['state_matrix'] = matrix_results
    print_result("状態マトリクステスト", matrix_results.passed, matrix_results.total)

    # 2. 確率的実行エンジンのテスト
    print_section_header("2. 確率的実行エンジンのテスト")
    engine_results = test_probability_engine()
    all_results['probability_engine'] = engine_results
    print_result("確率的実行エンジンテスト", engine_results.passed, engine_results.total)

    # 3. 統合テスト
    print_section_header("3. 統合テスト")
    integration_results = TestResult()

    # 統合テストはunittestで実装されているため、特別な処理
    import unittest
    test_suite = unittest.TestLoader().loadTestsFromTestCase(IntegrationTests)
    test_runner = unittest.TextTestRunner(verbosity=2)
    test_result = test_runner.run(test_suite)

    integration_results.total = test_result.testsRun
    integration_results.passed = test_result.testsRun - len(test_result.failures) - len(test_result.errors)
    integration_results.failed = len(test_result.failures) + len(test_result.errors)

    all_results['integration'] = integration_results
    print_result("統合テスト", integration_results.passed, integration_results.total)

    # 4. 状態カプセルテスト
    print_section_header("4. 状態カプセルテスト")
    print("状態カプセルテストを実行中...")
    capsule_success = run_capsule_tests()
    capsule_results = TestResult()
    capsule_results.total = 1
    capsule_results.passed = 1 if capsule_success else 0
    capsule_results.failed = 0 if capsule_success else 1

    all_results['capsule'] = capsule_results
    print_result("状態カプセルテスト", capsule_results.passed, capsule_results.total)

    # 総合結果の計算
    total_tests = sum(r.total for r in all_results.values())
    total_passed = sum(r.passed for r in all_results.values())
    total_failed = sum(r.failed for r in all_results.values())

    end_time = time.time()
    duration = end_time - start_time

    # 全体の結果表示
    print_section_header("テスト実行サマリー")
    print(f"総テスト数: {total_tests}")
    print(f"成功: {Colors.GREEN}{total_passed}{Colors.ENDC}")
    print(f"失敗: {Colors.RED if total_failed > 0 else Colors.GREEN}{total_failed}{Colors.ENDC}")
    print(f"成功率: {Colors.GREEN if total_failed == 0 else Colors.YELLOW}{(total_passed/total_tests*100):.1f}%{Colors.ENDC}")
    print(f"実行時間: {duration:.2f}秒")

    # 結果の可視化
    visualize_test_results(all_results, timestamp, duration)

    return total_failed == 0


def visualize_test_results(all_results, timestamp, duration):
    """テスト結果を可視化してファイルに保存"""
    output_file = os.path.join(TEST_OUTPUT_DIR, f"all_tests_summary_{timestamp}.png")

    plt.figure(figsize=(15, 10))

    # 全体の成功/失敗の円グラフ
    plt.subplot(2, 2, 1)
    total_passed = sum(r.passed for r in all_results.values())
    total_failed = sum(r.failed for r in all_results.values())

    labels = ['成功', '失敗']
    sizes = [total_passed, total_failed]
    colors = ['#4CAF50', '#F44336'] if total_failed == 0 else ['#FFEB3B', '#F44336']
    explode = (0.1, 0) if total_failed == 0 else (0, 0.1)

    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=90)
    plt.axis('equal')
    plt.title('全テスト結果概要')

    # 各モジュールの成功率の棒グラフ
    plt.subplot(2, 2, 2)
    modules = list(all_results.keys())
    success_rates = [(r.passed / r.total * 100) for r in all_results.values()]
    colors = [
        '#4CAF50' if rate == 100 else '#FFEB3B' if rate >= 80 else '#F44336'
        for rate in success_rates
    ]

    y_pos = np.arange(len(modules))
    plt.barh(y_pos, success_rates, color=colors)
    plt.yticks(y_pos, [m.replace('_', ' ').title() for m in modules])
    plt.xlabel('成功率 (%)')
    plt.title('モジュール別テスト成功率')
    plt.xlim(0, 105)  # 余白を含めて100%を超えるように

    # 各モジュールの成功/失敗の詳細積み上げ棒グラフ
    plt.subplot(2, 2, 3)
    passed_counts = [r.passed for r in all_results.values()]
    failed_counts = [r.failed for r in all_results.values()]

    plt.bar(modules, passed_counts, label='成功', color='#4CAF50')
    plt.bar(modules, failed_counts, bottom=passed_counts, label='失敗', color='#F44336')
    plt.ylabel('テスト数')
    plt.title('モジュール別テスト詳細')
    plt.xticks(rotation=45, ha='right')
    plt.legend()

    # テスト実行時間の表示
    plt.subplot(2, 2, 4)
    plt.axis('off')
    execution_info = (
        f"実行時刻: {timestamp}\n"
        f"実行時間: {duration:.2f}秒\n\n"
        f"総テスト数: {sum(r.total for r in all_results.values())}\n"
        f"総成功数: {total_passed}\n"
        f"総失敗数: {total_failed}\n"
        f"総成功率: {(total_passed / (total_passed + total_failed) * 100):.1f}%\n\n"
    )

    for module, result in all_results.items():
        module_name = module.replace('_', ' ').title()
        success_rate = (result.passed / result.total * 100) if result.total > 0 else 0
        execution_info += f"{module_name}: {result.passed}/{result.total} ({success_rate:.1f}%)\n"

    plt.text(0.5, 0.5, execution_info, ha='center', va='center', fontsize=12)

    # 全体のタイトル
    plt.suptitle('不確定性転写暗号化方式 - 全テスト実行結果', fontsize=16)

    # 保存
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(output_file)
    print(f"テスト結果の可視化を保存しました: {output_file}")

    # 結果ファイルパスを返す
    return output_file


if __name__ == "__main__":
    # 全テストを実行
    success = run_all_tests()

    # 終了ステータスを設定
    sys.exit(0 if success else 1)