#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - テスト実行スクリプト

すべてのテストを一括実行し、結果を出力します。
"""

import os
import sys
import time
import unittest
import datetime
import importlib
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Tuple

# テスト用にモジュールパスを追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = "test_output"

def discover_tests() -> List[str]:
    """
    テストファイルを検出

    Returns:
        検出されたテストモジュール名のリスト
    """
    test_dir = os.path.dirname(os.path.abspath(__file__))
    test_files = []

    for file in os.listdir(test_dir):
        if file.startswith("test_") and file.endswith(".py"):
            module_name = file[:-3]  # .pyを削除
            test_files.append(module_name)

    return sorted(test_files)

def run_test_module(module_name: str) -> Tuple[Dict[str, Any], Dict[str, float]]:
    """
    指定されたテストモジュールを実行

    Args:
        module_name: テストモジュール名

    Returns:
        (result, timings): テスト結果と実行時間
    """
    print(f"\n実行: {module_name}")
    print("-" * 80)

    try:
        # モジュールをインポート
        module = importlib.import_module(f"method_10_indeterministic.tests.{module_name}")

        # テストスイートを作成
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)

        # テスト結果を保存するオブジェクト
        test_result = unittest.TestResult()

        # 各テストの実行時間を記録
        timings = {}

        # 各テストケースを実行
        for test_case in unittest.defaultTestLoader.getTestCaseNames(module.TestCase):
            test_method = getattr(module.TestCase(test_case), test_case)

            # 開始時間
            start_time = time.time()

            # テスト実行
            test = module.TestCase(test_case)
            test.run(test_result)

            # 終了時間と所要時間
            end_time = time.time()
            elapsed = end_time - start_time

            # 時間を記録
            timings[test_case] = elapsed

            # 結果を表示
            status = "成功" if not (test_case in [f.id().split(".")[-1] for f in test_result.failures + test_result.errors]) else "失敗"
            print(f"  {test_case}: {status} ({elapsed:.2f}秒)")

        # 最終結果を表示
        print(f"\n結果: {test_result.testsRun}件実行, {len(test_result.failures)}件失敗, {len(test_result.errors)}件エラー")

        # 詳細なエラー情報を表示
        if test_result.failures or test_result.errors:
            print("\n失敗したテスト:")
            for failure in test_result.failures:
                print(f"\n{failure[0]}")
                print(failure[1])

            print("\nエラーが発生したテスト:")
            for error in test_result.errors:
                print(f"\n{error[0]}")
                print(error[1])

        return {"module": module_name, "result": test_result, "success": len(test_result.failures) == 0 and len(test_result.errors) == 0}, timings

    except Exception as e:
        print(f"エラー: モジュール {module_name} の実行中に問題が発生しました: {e}")
        import traceback
        traceback.print_exc()
        return {"module": module_name, "result": None, "success": False, "error": str(e)}, {}

def generate_test_report(results: List[Dict[str, Any]], timings_list: List[Dict[str, float]]):
    """
    テスト結果レポートを生成

    Args:
        results: テスト結果のリスト
        timings_list: テスト実行時間のリスト
    """
    # テスト結果の集計
    total_tests = sum(len(list(r["result"].failures) + list(r["result"].errors) + list(r["result"].successes)) if r["result"] else 0 for r in results)
    successful_tests = sum(r["success"] for r in results)
    failed_modules = [r["module"] for r in results if not r["success"]]

    # 出力ディレクトリの作成
    os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

    # タイムスタンプ
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # テスト結果グラフの生成
    plt.figure(figsize=(10, 6))
    modules = [r["module"].replace("test_", "") for r in results]
    success_status = [1 if r["success"] else 0 for r in results]

    plt.bar(modules, success_status, color=['green' if s else 'red' for s in success_status])
    plt.ylim(0, 1.2)
    plt.title('テスト結果')
    plt.xlabel('テストモジュール')
    plt.ylabel('成功 (1) / 失敗 (0)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # グラフを保存
    result_graph_path = os.path.join(TEST_OUTPUT_DIR, f"test_result_graph_{timestamp}.png")
    plt.savefig(result_graph_path)
    plt.close()

    # 実行時間グラフの生成
    plt.figure(figsize=(12, 8))

    # 各モジュールの実行時間を集計
    module_times = {}
    for i, timings in enumerate(timings_list):
        module_name = results[i]["module"].replace("test_", "")
        module_times[module_name] = sum(timings.values())

    # モジュール別の実行時間グラフ
    plt.subplot(2, 1, 1)
    modules = list(module_times.keys())
    times = list(module_times.values())

    plt.bar(modules, times, color='skyblue')
    plt.title('モジュール別実行時間')
    plt.xlabel('テストモジュール')
    plt.ylabel('実行時間 (秒)')
    plt.xticks(rotation=45, ha='right')

    # 詳細なテストケース実行時間グラフ
    plt.subplot(2, 1, 2)

    # 全テストケースとその実行時間をフラットリストに変換
    test_names = []
    test_times = []
    test_modules = []

    for i, timings in enumerate(timings_list):
        module_name = results[i]["module"].replace("test_", "")
        for test_name, test_time in timings.items():
            test_names.append(f"{module_name}.{test_name}")
            test_times.append(test_time)
            test_modules.append(module_name)

    # テストケース名でソート
    sorted_indices = np.argsort(test_names)
    test_names = [test_names[i] for i in sorted_indices]
    test_times = [test_times[i] for i in sorted_indices]
    test_modules = [test_modules[i] for i in sorted_indices]

    # モジュールごとに色分け
    unique_modules = sorted(set(test_modules))
    colors = plt.cm.tab10(np.linspace(0, 1, len(unique_modules)))
    color_map = {module: colors[i] for i, module in enumerate(unique_modules)}
    bar_colors = [color_map[module] for module in test_modules]

    plt.bar(range(len(test_names)), test_times, color=bar_colors)
    plt.title('テストケース別実行時間')
    plt.xlabel('テストケース')
    plt.ylabel('実行時間 (秒)')
    plt.xticks(range(len(test_names)), test_names, rotation=90)

    # 凡例を追加
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=color_map[module], label=module) for module in unique_modules]
    plt.legend(handles=legend_elements, loc='upper right')

    plt.tight_layout()

    # グラフを保存
    time_graph_path = os.path.join(TEST_OUTPUT_DIR, f"test_time_graph_{timestamp}.png")
    plt.savefig(time_graph_path)
    plt.close()

    # パフォーマンスグラフ（実行時間の分布）
    plt.figure(figsize=(10, 6))

    # 実行時間でソート
    sorted_indices = np.argsort(test_times)[::-1]  # 降順
    sorted_names = [test_names[i] for i in sorted_indices]
    sorted_times = [test_times[i] for i in sorted_indices]
    sorted_colors = [bar_colors[i] for i in sorted_indices]

    plt.bar(range(len(sorted_names)), sorted_times, color=sorted_colors)
    plt.title('テストパフォーマンス（実行時間順）')
    plt.xlabel('テストケース')
    plt.ylabel('実行時間 (秒)')
    plt.xticks(range(len(sorted_names)), sorted_names, rotation=90)
    plt.legend(handles=legend_elements, loc='upper right')
    plt.tight_layout()

    # グラフを保存
    performance_graph_path = os.path.join(TEST_OUTPUT_DIR, f"performance_graph_{timestamp}.png")
    plt.savefig(performance_graph_path)
    plt.close()

    # テスト結果レポートを生成
    report_path = os.path.join(TEST_OUTPUT_DIR, f"test_results_{timestamp}.log")
    with open(report_path, 'w') as f:
        f.write(f"# 不確定性転写暗号化方式テスト結果\n\n")
        f.write(f"実行日時: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write(f"## サマリー\n\n")
        f.write(f"- テストモジュール: {len(results)}個\n")
        f.write(f"- 成功: {successful_tests}個\n")
        f.write(f"- 失敗: {len(failed_modules)}個\n\n")

        if failed_modules:
            f.write(f"### 失敗したモジュール\n\n")
            for module in failed_modules:
                f.write(f"- {module}\n")
            f.write("\n")

        f.write(f"## 詳細結果\n\n")
        for i, result in enumerate(results):
            module_name = result["module"]
            module_result = result["result"]
            success = result["success"]

            f.write(f"### {module_name}\n\n")
            f.write(f"状態: {'成功' if success else '失敗'}\n")

            if "error" in result:
                f.write(f"エラー: {result['error']}\n\n")
                continue

            if module_result:
                f.write(f"テスト数: {module_result.testsRun}\n")
                f.write(f"失敗: {len(module_result.failures)}\n")
                f.write(f"エラー: {len(module_result.errors)}\n\n")

                if module_result.failures:
                    f.write("#### 失敗\n\n")
                    for failure in module_result.failures:
                        f.write(f"- {failure[0]}\n")
                        f.write(f"```\n{failure[1]}\n```\n\n")

                if module_result.errors:
                    f.write("#### エラー\n\n")
                    for error in module_result.errors:
                        f.write(f"- {error[0]}\n")
                        f.write(f"```\n{error[1]}\n```\n\n")

            f.write("\n")

        f.write(f"## 実行時間\n\n")
        f.write("### モジュール別実行時間\n\n")
        for module, time_value in module_times.items():
            f.write(f"- {module}: {time_value:.2f}秒\n")

        f.write("\n### テストケース別実行時間\n\n")
        for i, (name, t) in enumerate(zip(sorted_names, sorted_times)):
            f.write(f"- {name}: {t:.2f}秒\n")

        f.write("\n## グラフ\n\n")
        f.write(f"![テスト結果]({os.path.basename(result_graph_path)})\n\n")
        f.write(f"![実行時間]({os.path.basename(time_graph_path)})\n\n")
        f.write(f"![パフォーマンス]({os.path.basename(performance_graph_path)})\n\n")

    print(f"\nレポートを生成しました: {report_path}")
    print(f"テスト結果グラフ: {result_graph_path}")
    print(f"実行時間グラフ: {time_graph_path}")
    print(f"パフォーマンスグラフ: {performance_graph_path}")

    return report_path, result_graph_path, time_graph_path, performance_graph_path

def main():
    """
    メイン実行関数
    """
    print("不確定性転写暗号化方式テストを開始します...")

    # テストモジュールを検出
    test_modules = discover_tests()
    print(f"検出されたテストモジュール: {len(test_modules)}個")
    for module in test_modules:
        print(f"  - {module}")

    # 各テストモジュールを実行
    results = []
    timings_list = []

    for module in test_modules:
        result, timings = run_test_module(module)
        results.append(result)
        timings_list.append(timings)

    # 結果レポートを生成
    if results:
        generate_test_report(results, timings_list)

    # 全体の成功・失敗を判定
    success = all(r["success"] for r in results)

    print("\nテスト実行完了")
    print(f"結果: {'成功' if success else '失敗'}")

    # 終了コードを返す（成功:0, 失敗:1）
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
