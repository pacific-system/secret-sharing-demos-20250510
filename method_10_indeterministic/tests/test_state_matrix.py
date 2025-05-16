"""
状態遷移マトリクス生成機構のテスト
"""

import os
import sys
import time
import matplotlib
matplotlib.use('Agg')  # GUIを使用せずに保存
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Tuple, Optional, Any

# プロジェクトルートを追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.state_matrix import (
    State, StateMatrixGenerator, StateExecutor,
    create_state_matrix_from_key, get_biased_random_generator
)
from method_10_indeterministic.config import STATE_MATRIX_SIZE, STATE_TRANSITIONS
from method_10_indeterministic.tests.test_utils import (
    generate_random_key, TestResult, get_timestamp_str, TEST_OUTPUT_DIR
)


def test_state_matrix_generation():
    """状態マトリクス生成機能のテスト"""
    results = TestResult()

    # テスト1: 基本的な状態マトリクス生成
    try:
        key = generate_random_key()
        generator = StateMatrixGenerator(key)
        states = generator.generate_state_matrix()

        # 生成された状態の数を検証
        is_correct_size = len(states) == STATE_MATRIX_SIZE
        results.add_result(
            "状態マトリクスのサイズ検証",
            is_correct_size,
            f"期待値: {STATE_MATRIX_SIZE}, 実際: {len(states)}"
        )

        # 各状態の遷移確率の合計が1になっているか検証
        probabilities_valid = True
        for state_id, state in states.items():
            total_prob = sum(state.transitions.values())
            if abs(total_prob - 1.0) > 0.001:  # 浮動小数点誤差を考慮
                probabilities_valid = False
                break

        results.add_result(
            "遷移確率の正規化検証",
            probabilities_valid,
            "すべての状態の遷移確率合計が1.0であること"
        )

        # 異なる鍵で生成した場合、異なる状態マトリクスになるか検証
        key2 = generate_random_key()
        generator2 = StateMatrixGenerator(key2)
        states2 = generator2.generate_state_matrix()

        # 少なくとも一部の状態が異なるか検証
        is_different = False
        for state_id in states:
            if state_id in states2:
                for next_id in states[state_id].transitions:
                    if next_id in states2[state_id].transitions:
                        if abs(states[state_id].transitions[next_id] - states2[state_id].transitions[next_id]) > 0.001:
                            is_different = True
                            break
            if is_different:
                break

        results.add_result(
            "異なる鍵での状態マトリクス差異検証",
            is_different,
            "異なる鍵で生成した状態マトリクスが異なること"
        )

    except Exception as e:
        results.add_result("状態マトリクス生成基本テスト", False, f"例外発生: {str(e)}")

    # テスト2: 初期状態生成
    try:
        key = generate_random_key()
        generator = StateMatrixGenerator(key)
        states = generator.generate_state_matrix()
        true_initial, false_initial = generator.derive_initial_states()

        # 初期状態が有効範囲内か検証
        is_valid_true = 0 <= true_initial < STATE_MATRIX_SIZE
        is_valid_false = 0 <= false_initial < STATE_MATRIX_SIZE

        results.add_result(
            "正規パス初期状態の有効性",
            is_valid_true,
            f"初期状態: {true_initial}"
        )

        results.add_result(
            "非正規パス初期状態の有効性",
            is_valid_false,
            f"初期状態: {false_initial}"
        )

        # 正規パスと非正規パスの初期状態が異なるか検証
        is_different = true_initial != false_initial
        results.add_result(
            "初期状態の差異",
            is_different,
            f"正規: {true_initial}, 非正規: {false_initial}"
        )

    except Exception as e:
        results.add_result("初期状態生成テスト", False, f"例外発生: {str(e)}")

    # テスト3: 状態実行機能
    try:
        key = generate_random_key()
        states, true_initial, false_initial = create_state_matrix_from_key(key)

        # 正規パスの実行
        true_executor = StateExecutor(states, true_initial)
        true_path = true_executor.run_transitions(STATE_TRANSITIONS)

        # 非正規パスの実行
        false_executor = StateExecutor(states, false_initial)
        false_path = false_executor.run_transitions(STATE_TRANSITIONS)

        # パスが正しい長さになっているか検証
        is_correct_true_len = len(true_path) == STATE_TRANSITIONS + 1  # 初期状態を含む
        is_correct_false_len = len(false_path) == STATE_TRANSITIONS + 1

        results.add_result(
            "正規パス長の検証",
            is_correct_true_len,
            f"期待値: {STATE_TRANSITIONS+1}, 実際: {len(true_path)}"
        )

        results.add_result(
            "非正規パス長の検証",
            is_correct_false_len,
            f"期待値: {STATE_TRANSITIONS+1}, 実際: {len(false_path)}"
        )

        # 正規パスと非正規パスが異なる遷移をするか検証
        is_different_path = true_path != false_path
        results.add_result(
            "パス差異の検証",
            is_different_path,
            "正規パスと非正規パスが異なること"
        )

    except Exception as e:
        results.add_result("状態実行テスト", False, f"例外発生: {str(e)}")

    # テスト4: バイアス付き乱数生成器
    try:
        key = generate_random_key()
        bias_factor = 0.7
        biased_gen = get_biased_random_generator(key, bias_factor)

        # 乱数を生成
        random_values = [biased_gen() for _ in range(100)]

        # 分布の検証（0.0-1.0の範囲にあるか）
        all_in_range = all(0.0 <= val <= 1.0 for val in random_values)

        results.add_result(
            "バイアス付き乱数の範囲検証",
            all_in_range,
            "すべての乱数が0.0から1.0の範囲内にあること"
        )

        # バイアスの効果が見られるか検証（完全なランダムより偏りがあるべき）
        avg_value = sum(random_values) / len(random_values)
        has_bias = abs(avg_value - 0.5) > 0.05  # 平均値が0.5から5%以上離れているか

        results.add_result(
            "バイアス効果の検証",
            has_bias,
            f"平均値: {avg_value:.4f} (バイアスにより0.5からの偏りが期待される)"
        )

        # 異なる鍵では異なる結果が得られるか検証
        key2 = generate_random_key()
        biased_gen2 = get_biased_random_generator(key2, bias_factor)
        random_values2 = [biased_gen2() for _ in range(100)]
        avg_value2 = sum(random_values2) / len(random_values2)
        is_different_bias = abs(avg_value - avg_value2) > 0.05

        results.add_result(
            "異なる鍵でのバイアス差異",
            is_different_bias,
            f"鍵1の平均: {avg_value:.4f}, 鍵2の平均: {avg_value2:.4f}"
        )

    except Exception as e:
        results.add_result("バイアス付き乱数生成器テスト", False, f"例外発生: {str(e)}")

    # 結果の可視化
    try:
        visualize_state_matrix_test(results, key, true_path, false_path, random_values)
    except Exception as e:
        print(f"可視化中にエラーが発生しました: {e}")

    return results


def visualize_state_matrix_test(results, key, true_path, false_path, random_values):
    """状態マトリクステストの結果を可視化"""
    timestamp = get_timestamp_str()
    output_file = os.path.join(TEST_OUTPUT_DIR, f"state_matrix_test_{timestamp}.png")

    plt.figure(figsize=(15, 10))

    # 左上: テスト結果のサマリー
    plt.subplot(2, 2, 1)
    labels = ['成功', '失敗']
    sizes = [results.passed, results.failed]
    colors = ['#4CAF50', '#F44336'] if results.failed == 0 else ['#FFEB3B', '#F44336']
    explode = (0.1, 0) if results.failed == 0 else (0, 0.1)

    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=90)
    plt.axis('equal')
    plt.title('テスト結果概要')

    # 右上: 状態遷移パス可視化
    plt.subplot(2, 2, 2)
    plt.plot(true_path, 'b-', label='正規パス', alpha=0.8)
    plt.plot(false_path, 'r--', label='非正規パス', alpha=0.8)
    plt.xlabel('ステップ')
    plt.ylabel('状態ID')
    plt.title('状態遷移パスの比較')
    plt.legend()
    plt.grid(True, alpha=0.3)

    # 左下: バイアス付き乱数分布
    plt.subplot(2, 2, 3)
    plt.hist(random_values, bins=20, color='purple', alpha=0.7)
    plt.axvline(x=0.5, color='k', linestyle='--', alpha=0.5)
    plt.axvline(x=sum(random_values)/len(random_values), color='r', linestyle='-')
    plt.xlabel('乱数値')
    plt.ylabel('頻度')
    plt.title('バイアス付き乱数の分布')
    plt.grid(True, alpha=0.3)

    # 右下: 遷移頻度分析
    plt.subplot(2, 2, 4)
    true_counts = {i: true_path.count(i) for i in set(true_path)}
    false_counts = {i: false_path.count(i) for i in set(false_path)}

    states = sorted(set(true_path) | set(false_path))
    true_freq = [true_counts.get(s, 0) for s in states]
    false_freq = [false_counts.get(s, 0) for s in states]

    x = np.arange(len(states))
    width = 0.35

    plt.bar(x - width/2, true_freq, width, label='正規パス', color='blue', alpha=0.7)
    plt.bar(x + width/2, false_freq, width, label='非正規パス', color='red', alpha=0.7)
    plt.xlabel('状態ID')
    plt.ylabel('出現頻度')
    plt.title('状態出現頻度の比較')
    plt.xticks(x, states)
    plt.legend()
    plt.grid(True, alpha=0.3)

    # 全体のタイトル
    plt.suptitle('不確定性転写暗号化方式 - 状態マトリクステスト結果', fontsize=16)
    plt.figtext(0.5, 0.01, f'全テスト: {results.total}, 成功: {results.passed}, 失敗: {results.failed}, ' +
                f'成功率: {(results.passed/results.total*100):.1f}% (実行日時: {timestamp})',
                ha='center', fontsize=10)

    # 保存
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(output_file)
    print(f"状態マトリクステスト結果を保存しました: {output_file}")

    return output_file


if __name__ == "__main__":
    print("=== 状態マトリクス生成機構のテスト ===")
    results = test_state_matrix_generation()
    results.print_summary()

    # 終了コードを設定（テスト失敗なら1、成功なら0）
    sys.exit(0 if results.all_passed() else 1)