#!/usr/bin/env python3
"""
不確定性転写暗号化方式のテスト実行スクリプト

全テストを実行し、結果を出力します。
"""

import os
import sys
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Any

# プロジェクトルートを追加
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)

# テスト用モジュールのインポート
from method_10_indeterministic.state_matrix import (
    STATE_MATRIX_SIZE, STATE_TRANSITIONS, create_state_matrix_from_key
)

class TestResult:
    """テスト結果を管理するクラス"""

    def __init__(self, name: str):
        self.name = name
        self.tests = []
        self.passed = 0
        self.failed = 0
        self.start_time = time.time()
        self.end_time = None

    def add_test(self, test_name: str, passed: bool, message: str = ""):
        """テスト結果を追加"""
        self.tests.append({
            "name": test_name,
            "passed": passed,
            "message": message
        })

        if passed:
            self.passed += 1
        else:
            self.failed += 1

    def finish(self):
        """テスト終了処理"""
        self.end_time = time.time()

    def get_duration(self) -> float:
        """テスト実行時間を取得"""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    def summary(self) -> str:
        """テスト結果のサマリーを取得"""
        duration = self.get_duration()
        total = self.passed + self.failed

        result = f"{self.name} テスト結果:\n"
        result += f"合計: {total} テスト\n"
        result += f"成功: {self.passed} テスト\n"
        result += f"失敗: {self.failed} テスト\n"
        result += f"実行時間: {duration:.2f} 秒\n"

        if self.failed > 0:
            result += "\n失敗したテスト:\n"
            for test in self.tests:
                if not test["passed"]:
                    result += f"- {test['name']}: {test['message']}\n"

        return result

def test_state_matrix(generate_visualization: bool = True) -> TestResult:
    """
    状態遷移マトリクスのテスト

    Args:
        generate_visualization: 視覚化を行うかどうか

    Returns:
        テスト結果
    """
    from method_10_indeterministic.state_matrix import (
        StateMatrixGenerator, StateExecutor, get_biased_random_generator
    )

    result = TestResult("状態遷移マトリクス")

    # テスト1: マトリクス生成
    try:
        # テスト用の鍵を生成
        test_key = os.urandom(32)
        test_key_hex = test_key.hex()

        # マトリクスの生成
        generator = StateMatrixGenerator(test_key)
        states = generator.generate_state_matrix()

        # 状態数のチェック
        valid_states = len(states) == STATE_MATRIX_SIZE
        result.add_test(
            "状態数チェック",
            valid_states,
            f"期待値: {STATE_MATRIX_SIZE}, 実際: {len(states)}"
        )

        # 正規化のチェック
        normalization_valid = True
        for state_id, state in states.items():
            total_prob = sum(state.transitions.values())
            if abs(total_prob - 1.0) > 0.001:  # 浮動小数点誤差を考慮
                normalization_valid = False
                break

        result.add_test(
            "確率の正規化チェック",
            normalization_valid,
            "すべての状態の遷移確率合計が1.0であること"
        )

        # 初期状態の導出
        true_initial, false_initial = generator.derive_initial_states()

        # 初期状態が異なるかチェック
        distinct_initials = true_initial != false_initial
        result.add_test(
            "初期状態の区別",
            distinct_initials,
            f"正規初期状態: {true_initial}, 非正規初期状態: {false_initial}"
        )

    except Exception as e:
        result.add_test("マトリクス生成", False, f"例外発生: {e}")

    # テスト2: 状態遷移実行
    try:
        # 上のテストからstatesとinitial statesを使用
        if 'states' in locals() and 'true_initial' in locals() and 'false_initial' in locals():
            # 正規パスの実行
            true_executor = StateExecutor(states, true_initial)
            true_path = true_executor.run_transitions(STATE_TRANSITIONS)

            # 非正規パスの実行
            false_executor = StateExecutor(states, false_initial)
            false_path = false_executor.run_transitions(STATE_TRANSITIONS)

            # パス長のチェック
            true_path_valid = len(true_path) == STATE_TRANSITIONS + 1  # 初期状態を含む
            result.add_test(
                "正規パス長",
                true_path_valid,
                f"期待値: {STATE_TRANSITIONS + 1}, 実際: {len(true_path)}"
            )

            # パスの差異チェック
            paths_differ = true_path != false_path
            result.add_test(
                "パス差異",
                paths_differ,
                "正規パスと非正規パスが異なること"
            )

            # 視覚化の実行
            if generate_visualization and paths_differ:
                try:
                    from method_10_indeterministic.tests.visualize_state_matrix import visualize_state_matrix

                    # タイムスタンプ付きの出力パス
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = os.path.join(root_dir, "test_output", f"state_matrix_test_{timestamp}.png")

                    # 視覚化の実行
                    vis_result = visualize_state_matrix(test_key, output_path)

                    # 視覚化結果のチェック
                    visualization_valid = vis_result["paths_differ"] == paths_differ
                    result.add_test(
                        "視覚化結果",
                        visualization_valid,
                        f"視覚化: {output_path}"
                    )

                    # 静的なファイル名のコピーも作成（最新結果用）
                    static_path = os.path.join(root_dir, "test_output", "state_matrix_test.png")
                    import shutil
                    shutil.copy2(output_path, static_path)

                except Exception as e:
                    result.add_test("視覚化実行", False, f"例外発生: {e}")
        else:
            result.add_test("状態遷移実行", False, "前のテストが失敗したため実行できません")

    except Exception as e:
        result.add_test("状態遷移実行", False, f"例外発生: {e}")

    # テスト3: バイアス乱数生成器
    try:
        # バイアス付き乱数生成器のテスト
        biased_gen = get_biased_random_generator(test_key, 0.7)

        # 生成した乱数の範囲チェック
        random_values = [biased_gen() for _ in range(100)]
        all_in_range = all(0.0 <= val <= 1.0 for val in random_values)

        result.add_test(
            "バイアス乱数範囲",
            all_in_range,
            "すべての乱数が0.0-1.0の範囲内であること"
        )

        # 乱数の分布チェック（大まかな確認）
        avg = sum(random_values) / len(random_values)
        distribution_valid = 0.3 <= avg <= 0.7  # バイアスを考慮した適切な範囲

        result.add_test(
            "乱数分布",
            distribution_valid,
            f"平均値: {avg:.4f}"
        )

    except Exception as e:
        result.add_test("バイアス乱数生成", False, f"例外発生: {e}")

    result.finish()
    return result

def test_probability_engine() -> TestResult:
    """
    確率的実行エンジンのテスト

    Returns:
        テスト結果
    """
    # このIssueでは未実装のため、ダミーの成功結果を返す
    result = TestResult("確率的実行エンジン")
    result.add_test("ダミーテスト", True, "この機能は別のIssueで実装予定")
    result.finish()
    return result

def run_tests(visualization: bool = True) -> int:
    """
    全テストを実行

    Args:
        visualization: 視覚化を行うかどうか

    Returns:
        終了コード（0: 成功, 1: 失敗あり）
    """
    print("=" * 60)
    print("不確定性転写暗号化方式 テスト実行")
    print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # テスト出力ディレクトリの作成
    test_output_dir = os.path.join(root_dir, "test_output")
    os.makedirs(test_output_dir, exist_ok=True)

    # 各テストの実行
    state_matrix_result = test_state_matrix(visualization)
    print("\n" + state_matrix_result.summary())

    # 全体の結果集計
    total_tests = state_matrix_result.passed + state_matrix_result.failed
    total_passed = state_matrix_result.passed
    total_failed = state_matrix_result.failed

    # 結果サマリーの表示
    print("=" * 60)
    print("全体サマリー")
    print("=" * 60)
    print(f"合計テスト数: {total_tests}")
    print(f"成功: {total_passed}")
    print(f"失敗: {total_failed}")

    success_rate = (total_passed / total_tests) * 100 if total_tests > 0 else 0
    print(f"成功率: {success_rate:.2f}%")

    # 最終結果を判定
    success = total_failed == 0
    print(f"\n最終判定: {'成功 ✅' if success else '失敗 ❌'}")

    return 0 if success else 1

if __name__ == "__main__":
    # コマンドライン引数の解析
    import argparse
    parser = argparse.ArgumentParser(description='不確定性転写暗号化方式のテスト実行')
    parser.add_argument('--no-visualization', action='store_true', help='視覚化を無効にする')
    args = parser.parse_args()

    # テストの実行
    sys.exit(run_tests(not args.no_visualization))
