#!/usr/bin/env python3
"""
状態遷移マトリクスのテストスクリプト
"""

import os
import sys
import hashlib
from pathlib import Path

# 絶対パスをインポートに追加して安定性を向上
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# state_matrixモジュールをインポート
from state_matrix import (
    StateMatrixGenerator,
    StateExecutor,
    get_biased_random_generator,
    generate_state_matrix,
    STATE_TRANSITIONS
)

def test_state_matrix():
    """
    状態遷移マトリクスの生成と実行をテスト
    """
    # テスト用の鍵を生成（実行ごとに変化）
    test_key = os.urandom(32)

    print(f"テスト鍵: {test_key.hex()[:16]}...")

    # マトリクスの生成
    generator = StateMatrixGenerator(test_key)
    states = generator.generate_state_matrix()
    true_initial, false_initial = generator.derive_initial_states()

    print("状態マトリクス生成完了:")
    print(f"状態数: {len(states)}")
    print(f"正規パスの初期状態: {true_initial}")
    print(f"非正規パスの初期状態: {false_initial}")

    # 正規パスの実行
    print("\n正規パスの実行:")
    true_executor = StateExecutor(states, true_initial)
    true_path = true_executor.run_transitions(STATE_TRANSITIONS)
    print(f"状態遷移: {true_path}")

    # 非正規パスの実行
    print("\n非正規パスの実行:")
    false_executor = StateExecutor(states, false_initial)
    false_path = false_executor.run_transitions(STATE_TRANSITIONS)
    print(f"状態遷移: {false_path}")

    # パスの検証
    paths_differ = true_path != false_path
    print(f"パスが異なる: {paths_differ}")

    if not paths_differ:
        print("警告: 正規パスと非正規パスが同一です")

    # バイアス乱数のテスト
    print("\nバイアス乱数のテスト:")
    biased_gen = get_biased_random_generator(test_key, 0.7)
    biased_values = [biased_gen() for _ in range(10)]
    print(f"バイアス値: {biased_values}")

    # 値の範囲チェック
    all_in_range = all(0 <= v <= 1 for v in biased_values)
    print(f"すべての値が0-1の範囲内: {all_in_range}")

    # 元の実装との連携テスト
    print("\n元の実装との連携テスト:")
    old_matrix = generate_state_matrix(test_key)
    old_matrix.perform_transitions(STATE_TRANSITIONS)
    old_signature = old_matrix.get_state_signature()
    print(f"旧実装シグネチャ: {old_signature.hex()[:16]}...")

    print("\nテスト完了！")
    return True


if __name__ == "__main__":
    success = test_state_matrix()
    sys.exit(0 if success else 1)