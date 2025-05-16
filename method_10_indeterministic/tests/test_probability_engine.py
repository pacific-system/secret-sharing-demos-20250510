"""
確率的実行エンジンのテスト
"""

import os
import sys
import unittest
import random
import time
import hashlib
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Any

# プロジェクトルートを追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.probability_engine import (
    ProbabilityController, ExecutionPathManager, ProbabilisticExecutionEngine,
    TRUE_PATH, FALSE_PATH, create_engine_from_key, obfuscate_execution_path,
    generate_anti_analysis_noise
)
from method_10_indeterministic.state_matrix import create_state_matrix_from_key
from method_10_indeterministic.tests.test_utils import (
    generate_random_key, TestResult, get_timestamp_str, TEST_OUTPUT_DIR
)
from method_10_indeterministic.config import STATE_TRANSITIONS


def test_probability_engine():
    """確率的実行エンジンのテスト"""
    results = TestResult()

    # テスト1: エンジン作成と基本動作
    try:
        key = generate_random_key()

        # 正規パスエンジン作成
        true_engine = create_engine_from_key(key, TRUE_PATH)

        # 非正規パスエンジン作成
        false_engine = create_engine_from_key(key, FALSE_PATH)

        # 初期状態が適切に設定されているか検証
        is_valid_true_init = true_engine.path_manager.current_state_id == true_engine.true_initial
        is_valid_false_init = false_engine.path_manager.current_state_id == false_engine.false_initial

        results.add_result(
            "正規パスエンジン初期状態検証",
            is_valid_true_init,
            f"初期状態: {true_engine.path_manager.current_state_id}"
        )

        results.add_result(
            "非正規パスエンジン初期状態検証",
            is_valid_false_init,
            f"初期状態: {false_engine.path_manager.current_state_id}"
        )

    except Exception as e:
        results.add_result("エンジン作成テスト", False, f"例外発生: {str(e)}")

    # テスト2: エンジン実行と収束性
    try:
        key = generate_random_key()

        # 複数回実行して最終状態を収集
        true_finals = []
        false_finals = []

        for i in range(5):
            true_engine = create_engine_from_key(key, TRUE_PATH)
            true_path = true_engine.run_execution()
            true_finals.append(true_path[-1])

            false_engine = create_engine_from_key(key, FALSE_PATH)
            false_path = false_engine.run_execution()
            false_finals.append(false_path[-1])

        # 正規パスの収束性（同じ鍵では最終状態が類似する傾向になるか）
        true_converges = len(set(true_finals)) < 3  # 5回中3種類未満なら収束傾向あり

        # 非正規パスの収束性
        false_converges = len(set(false_finals)) < 3

        # 正規/非正規パスの差異（両者の最終状態が明確に異なるか）
        paths_differ = len(set(true_finals) & set(false_finals)) == 0  # 共通要素がない

        results.add_result(
            "正規パス収束性",
            true_converges,
            f"最終状態集合: {set(true_finals)}"
        )

        results.add_result(
            "非正規パス収束性",
            false_converges,
            f"最終状態集合: {set(false_finals)}"
        )

        results.add_result(
            "正規/非正規パス差異",
            paths_differ,
            f"正規最終状態: {set(true_finals)}, 非正規最終状態: {set(false_finals)}"
        )

    except Exception as e:
        results.add_result("エンジン収束性テスト", False, f"例外発生: {str(e)}")

    # テスト3: 実行パスの非決定性
    try:
        key = generate_random_key()

        # 同じパラメータで複数回実行し、パスの詳細が毎回変化することを確認
        path_histories = []

        for i in range(3):
            engine = create_engine_from_key(key, TRUE_PATH)
            engine.run_execution()
            path_histories.append(tuple(engine.path_manager.path_history))

        # 各実行パスが異なることを確認
        all_same = len(path_histories) > 1 and all(path == path_histories[0] for path in path_histories)
        all_different = len(set(path_histories)) == len(path_histories)

        results.add_result(
            "実行パスの非決定性",
            not all_same,
            "同じパラメータでも異なる実行パスになること"
        )

        results.add_result(
            "実行パスの十分な変動性",
            all_different,
            "各実行で完全に異なるパスが生成されること"
        )

    except Exception as e:
        results.add_result("実行パス非決定性テスト", False, f"例外発生: {str(e)}")

    # テスト4: 難読化機能
    try:
        key = generate_random_key()
        engine = create_engine_from_key(key, TRUE_PATH)

        # 元のパス履歴を保存
        original_state = engine.path_manager.current_state_id
        original_history = engine.path_manager.path_history.copy()

        # 難読化を実行
        obfuscate_execution_path(engine)

        # 状態が保存されているか確認
        state_preserved = engine.path_manager.current_state_id == original_state
        history_preserved = engine.path_manager.path_history == original_history

        results.add_result(
            "難読化後の状態保存",
            state_preserved,
            "難読化後も元の状態が保持されること"
        )

        results.add_result(
            "難読化後の履歴保存",
            history_preserved,
            "難読化後も元の履歴が保持されること"
        )

    except Exception as e:
        results.add_result("難読化機能テスト", False, f"例外発生: {str(e)}")

    # テスト5: 解析対策ノイズ生成
    try:
        key = generate_random_key()

        # TRUE/FALSE パスでのノイズを生成
        true_noise = generate_anti_analysis_noise(key, TRUE_PATH)
        false_noise = generate_anti_analysis_noise(key, FALSE_PATH)

        # 同じ長さになっているか
        same_length = len(true_noise) == len(false_noise)

        # 内容が異なるか
        different_content = true_noise != false_noise

        # エントロピーを測定（どれだけランダムか）
        def calculate_entropy(data):
            counts = {}
            for byte in data:
                counts[byte] = counts.get(byte, 0) + 1
            entropy = 0
            for count in counts.values():
                prob = count / len(data)
                entropy -= prob * np.log2(prob)
            return entropy

        true_entropy = calculate_entropy(true_noise)
        false_entropy = calculate_entropy(false_noise)

        # 十分なエントロピーがあるか検証（8ビットデータの理論上最大値は8）
        high_entropy = true_entropy > 7.0 and false_entropy > 7.0

        results.add_result(
            "ノイズのエントロピー",
            high_entropy,
            f"TRUEエントロピー: {true_entropy:.4f}, FALSEエントロピー: {false_entropy:.4f}"
        )

        results.add_result(
            "ノイズの差異",
            different_content,
            "TRUE/FALSEパスで異なるノイズが生成されること"
        )

    except Exception as e:
        results.add_result("解析対策ノイズテスト", False, f"例外発生: {str(e)}")

    # 結果の可視化
    try:
        visualize_test_results(results)
    except Exception as e:
        print(f"結果の可視化に失敗しました: {e}")

    return results


def visualize_test_results(results):
    """テスト結果を可視化"""
    # タイムスタンプを取得
    timestamp = get_timestamp_str()

    # 出力ファイル名
    output_file = os.path.join(TEST_OUTPUT_DIR, f"probability_engine_test_{timestamp}.png")

    # テスト結果の可視化
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 7))

    # 左側: 成功/失敗の円グラフ
    labels = ['成功', '失敗']
    sizes = [results.passed, results.failed]
    colors = ['#4CAF50', '#F44336'] if results.failed == 0 else ['#FFEB3B', '#F44336']
    explode = (0.1, 0) if results.failed == 0 else (0, 0.1)

    ax1.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=90)
    ax1.axis('equal')
    ax1.set_title('テスト結果概要')

    # 右側: 各テストの成功/失敗の棒グラフ
    test_names = [r['name'] if len(r['name']) < 25 else r['name'][:22] + '...' for r in results.results]
    test_results = [1 if r['passed'] else 0 for r in results.results]

    y_pos = np.arange(len(test_names))
    colors = ['#4CAF50' if res else '#F44336' for res in test_results]

    ax2.barh(y_pos, test_results, align='center', color=colors)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(test_names)
    ax2.invert_yaxis()  # 最初のテストを上に表示
    ax2.set_xlabel('結果 (1=成功, 0=失敗)')
    ax2.set_title('各テストの結果')

    # タイトルと情報
    plt.suptitle(f'不確定性転写暗号化方式 - 確率的実行エンジンテスト結果', fontsize=16)
    plt.figtext(0.5, 0.01, f'全テスト: {results.total}, 成功: {results.passed}, 失敗: {results.failed}, ' +
                f'成功率: {(results.passed/results.total*100):.1f}% (実行日時: {timestamp})',
                ha='center', fontsize=10)

    # 保存
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(output_file)
    print(f"テスト結果の可視化を保存しました: {output_file}")

    # ファイルの絶対パスを返す
    return os.path.abspath(output_file)


if __name__ == "__main__":
    print("=== 確率的実行エンジンのテスト ===")
    results = test_probability_engine()
    results.print_summary()

    # 終了コードを設定（テスト失敗なら1、成功なら0）
    sys.exit(0 if results.all_passed() else 1)
