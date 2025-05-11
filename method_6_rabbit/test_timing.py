#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
鍵判定ロジックのタイミング攻撃耐性テスト
"""

import os
import sys
import time
import statistics
from typing import List, Dict, Tuple, Any

# インポートエラーを回避するための処理
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from method_6_rabbit.key_analyzer import obfuscated_key_determination, determine_key_type_advanced
from method_6_rabbit.stream_selector import determine_key_type_secure

# 定数
KEY_TYPE_TRUE = "true"
KEY_TYPE_FALSE = "false"
SALT_SIZE = 16

def time_function(func, *args, **kwargs) -> float:
    """
    関数の実行時間を計測する

    Args:
        func: 計測する関数
        *args, **kwargs: 関数に渡す引数

    Returns:
        実行時間（ミリ秒）
    """
    start = time.perf_counter()
    func(*args, **kwargs)
    end = time.perf_counter()
    return (end - start) * 1000  # ミリ秒単位で返す

def run_timing_tests(num_tests: int = 100) -> None:
    """
    タイミング攻撃耐性テストを実行

    Args:
        num_tests: テストの回数
    """
    print(f"=== タイミング攻撃耐性テスト ({num_tests}回) ===")

    # テスト用のデータを準備
    test_salt = os.urandom(SALT_SIZE)
    print(f"使用するソルト: {test_salt.hex()}")

    # テスト用の鍵セット
    test_keys_true = ["true_key_1", "true_key_2", "correct_password"]
    test_keys_false = ["false_key_1", "false_key_2", "wrong_password"]
    random_keys = [os.urandom(16).hex() for _ in range(10)]

    # 各関数の実行時間を計測
    functions = {
        "determine_key_type_secure": determine_key_type_secure,
        "determine_key_type_advanced": determine_key_type_advanced,
        "obfuscated_key_determination": obfuscated_key_determination
    }

    all_results = {}

    for func_name, func in functions.items():
        print(f"\n== {func_name} ==")

        # 'true'と判定される鍵の実行時間
        true_times = []
        for key in test_keys_true:
            times = [time_function(func, key, test_salt) for _ in range(num_tests)]
            true_times.extend(times)
            mean = statistics.mean(times)
            stdev = statistics.stdev(times) if len(times) > 1 else 0
            print(f"鍵 '{key}': 平均 {mean:.3f}ms, 標準偏差 {stdev:.3f}ms")

        # 'false'と判定される鍵の実行時間
        false_times = []
        for key in test_keys_false:
            times = [time_function(func, key, test_salt) for _ in range(num_tests)]
            false_times.extend(times)
            mean = statistics.mean(times)
            stdev = statistics.stdev(times) if len(times) > 1 else 0
            print(f"鍵 '{key}': 平均 {mean:.3f}ms, 標準偏差 {stdev:.3f}ms")

        # ランダム鍵の実行時間
        random_times = []
        for key in random_keys:
            times = [time_function(func, key, test_salt) for _ in range(num_tests)]
            random_times.extend(times)

        # 統計情報
        true_mean = statistics.mean(true_times)
        false_mean = statistics.mean(false_times)
        random_mean = statistics.mean(random_times)

        true_stdev = statistics.stdev(true_times) if len(true_times) > 1 else 0
        false_stdev = statistics.stdev(false_times) if len(false_times) > 1 else 0
        random_stdev = statistics.stdev(random_times) if len(random_times) > 1 else 0

        # 'true'と'false'の時間差の絶対値（タイミング攻撃の可能性）
        time_diff = abs(true_mean - false_mean)
        time_diff_percent = (time_diff / max(true_mean, false_mean)) * 100

        print(f"\n統計情報:")
        print(f"  'true'鍵の平均時間: {true_mean:.3f}ms, 標準偏差: {true_stdev:.3f}ms")
        print(f"  'false'鍵の平均時間: {false_mean:.3f}ms, 標準偏差: {false_stdev:.3f}ms")
        print(f"  ランダム鍵の平均時間: {random_mean:.3f}ms, 標準偏差: {random_stdev:.3f}ms")
        print(f"  true/false時間差: {time_diff:.3f}ms ({time_diff_percent:.2f}%)")

        # タイミング攻撃の可能性を評価
        if time_diff_percent < 5.0:
            vulnerability = "低"
        elif time_diff_percent < 10.0:
            vulnerability = "中"
        else:
            vulnerability = "高"

        print(f"  タイミング攻撃に対する脆弱性: {vulnerability}")

        all_results[func_name] = {
            "true_mean": true_mean,
            "false_mean": false_mean,
            "random_mean": random_mean,
            "time_diff_percent": time_diff_percent,
            "vulnerability": vulnerability
        }

    # 3つの関数の比較
    print("\n=== 関数の比較 ===")
    for func_name, results in all_results.items():
        print(f"{func_name}: 時間差 {results['time_diff_percent']:.2f}%, 脆弱性 {results['vulnerability']}")

    # 最も安全な関数を特定
    most_secure = min(all_results.items(), key=lambda x: x[1]["time_diff_percent"])
    print(f"\n最もタイミング攻撃に強い関数: {most_secure[0]}")

if __name__ == "__main__":
    run_timing_tests()