#!/usr/bin/env python3
"""
状態遷移マトリクスの可視化スクリプト

テスト結果を視覚的に分かりやすくグラフ化します。
"""

import os
import sys
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple, Any

# プロジェクトルートを追加
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)

# テスト対象のモジュールをインポート
from method_10_indeterministic.state_matrix import (
    StateMatrixGenerator, StateExecutor, create_state_matrix_from_key, STATE_TRANSITIONS
)

def import_time_module_with_fallback():
    """
    datetime モジュールをインポートし、失敗した場合はtime.strftimeを使用
    """
    try:
        from datetime import datetime
        return datetime.now()
    except ImportError:
        import time
        return time

def visualize_state_matrix(key: bytes, output_path: str = None):
    """
    状態遷移マトリクスを可視化

    Args:
        key: マスター鍵
        output_path: 出力ファイルパス（省略時は表示のみ）
    """
    # マトリクスの生成
    generator = StateMatrixGenerator(key)
    states = generator.generate_state_matrix()
    true_initial, false_initial = generator.derive_initial_states()

    # 通常キーと異なるキーでの実行パス
    executor1 = StateExecutor(states, true_initial)

    # 異なる鍵を生成（ランダム）
    diff_key = os.urandom(32)
    # 確実に異なる鍵にするため、1バイト反転
    diff_key = diff_key[:0] + bytes([diff_key[0] ^ 0xFF]) + diff_key[1:]

    diff_generator = StateMatrixGenerator(diff_key)
    diff_states = diff_generator.generate_state_matrix()
    diff_true_initial, diff_false_initial = diff_generator.derive_initial_states()
    executor2 = StateExecutor(diff_states, diff_true_initial)

    # 両方のキーについて実行パスをシミュレーション
    path1 = []
    path2 = []

    for _ in range(STATE_TRANSITIONS * 2):
        path1.append(executor1.current_state_id)
        path2.append(executor2.current_state_id)
        executor1.step()
        executor2.step()

    # グラフの設定 - 日本語フォント対応
    plt.figure(figsize=(16, 9))

    # フォント設定を試みる（利用可能なフォントがシステムに依存）
    try:
        # macOSで一般的な日本語フォント
        plt.rcParams['font.family'] = 'Hiragino Sans'
    except:
        try:
            # Windowsで一般的な日本語フォント
            plt.rcParams['font.family'] = 'MS Gothic'
        except:
            # フォールバック：英語表記に切り替え
            use_english_labels = True

    # タイトルと軸ラベルを設定
    title = "State Transitions Matrix Analysis"  # 英語表記
    plt.suptitle(title, fontsize=16)

    # 経路比較のプロット
    plt.subplot(2, 2, 1)
    plt.plot(path1, 'b-', label='Key 1 Path')
    plt.plot(path2, 'r--', label='Key 2 Path')
    plt.title("Path Comparison", fontsize=14)
    plt.xlabel("Transition Count")
    plt.ylabel("State")
    plt.legend()
    plt.grid(True)

    # 状態遷移マトリクスのヒートマップ表示
    plt.subplot(2, 2, 2)
    state_matrix = np.zeros((len(states), len(states)))
    for i in range(len(states)):
        if i in states:
            for j, prob in states[i].transitions.items():
                state_matrix[i, j] = prob

    plt.imshow(state_matrix, cmap='viridis')
    plt.colorbar(label='Transition Probability')
    plt.title("State Transition Matrix", fontsize=14)
    plt.xlabel("Next State")
    plt.ylabel("Current State")

    # 状態出現頻度の分析
    plt.subplot(2, 2, 3)

    # 各状態の出現回数をカウント
    bins = np.zeros(len(states))
    for state in path1:
        bins[state] += 1

    plt.bar(range(len(states)), bins, color='blue', alpha=0.7)
    plt.title("State Frequency Analysis", fontsize=14)
    plt.xlabel("State ID")
    plt.ylabel("Occurrence Count")
    plt.grid(axis='y')

    # パス差異の分析
    plt.subplot(2, 2, 4)

    # 位置ごとにパスが一致しているかどうかを表示
    path_diffs = [int(path1[i] != path2[i]) for i in range(len(path1))]
    plt.plot(path_diffs, 'g-', marker='.', markersize=4)
    plt.title("Path Difference Analysis", fontsize=14)
    plt.xlabel("Transition Step")
    plt.ylabel("Different (1) / Same (0)")
    plt.yticks([0, 1], ['Same', 'Different'])
    plt.grid(True)

    # マトリクスの生成情報を追加
    plt.figtext(0.5, 0.01,
                f"状態数: {len(states)}, 正規初期状態: {true_initial}, "
                f"Diff判定: {'パスが異なる' if path1 != path2 else '同一パス'}",
                ha="center", fontsize=10,
                bbox={"facecolor":"orange", "alpha":0.2, "pad":5})

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])

    if output_path:
        # 出力ディレクトリが存在するか確認
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path)
        print(f"可視化結果を保存しました: {output_path}")
    else:
        plt.show()

    plt.close()

    return {
        "matrix_size": len(states),
        "true_initial": true_initial,
        "false_initial": false_initial,
        "true_path": path1,
        "false_path": path2,
        "paths_differ": path1 != path2
    }

if __name__ == "__main__":
    # テスト用の鍵を生成
    test_key = os.urandom(32)
    print(f"テスト鍵: {test_key.hex()[:16]}...")

    # 出力パスの設定
    timestamp = import_time_module_with_fallback()
    timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(root_dir, "test_output", f"state_matrix_test_{timestamp_str}.png")

    # 可視化の実行
    result = visualize_state_matrix(test_key, output_path)

    # 結果の表示
    print("\n可視化結果:")
    print(f"状態数: {result['matrix_size']}")
    print(f"正規パス初期状態: {result['true_initial']}")
    print(f"非正規パス初期状態: {result['false_initial']}")
    print(f"パスが異なる: {result['paths_differ']}")

    # パスの一部を表示
    true_path_str = ", ".join(map(str, result['true_path'][:5])) + "..."
    false_path_str = ", ".join(map(str, result['false_path'][:5])) + "..."

    print(f"正規パス: [{true_path_str}]")
    print(f"非正規パス: [{false_path_str}]")