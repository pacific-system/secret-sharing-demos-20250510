#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
鍵判定ロジックの分布テスト
"""

import os
import sys
import time

# インポートエラーを回避するための処理
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from method_6_rabbit.key_analyzer import obfuscated_key_determination, determine_key_type_advanced

# 定数
KEY_TYPE_TRUE = "true"
KEY_TYPE_FALSE = "false"
SALT_SIZE = 16

def run_distribution_test(num_tests=5000):
    """
    大規模な分布テストを実行
    """
    print(f"=== 分布テスト ({num_tests}回) ===")

    # 同一鍵・異なるソルトでの分布
    distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}
    test_key = "distribution_test_key"

    start_time = time.time()

    for _ in range(num_tests):
        test_salt = os.urandom(SALT_SIZE)
        result = obfuscated_key_determination(test_key, test_salt)
        distribution[result] += 1

    elapsed = time.time() - start_time

    print(f"\n同一鍵・異なるソルトでの分布:")
    print(f"鍵: '{test_key}'")
    print(f"  TRUE: {distribution[KEY_TYPE_TRUE]} ({distribution[KEY_TYPE_TRUE]/num_tests:.2%})")
    print(f"  FALSE: {distribution[KEY_TYPE_FALSE]} ({distribution[KEY_TYPE_FALSE]/num_tests:.2%})")
    print(f"  分布の均一性: {min(distribution.values())/max(distribution.values()):.3f} (1.0が理想)")
    print(f"  処理時間: {elapsed:.2f}秒 ({num_tests/elapsed:.1f}判定/秒)")

    # 異なる鍵・同一ソルトでの分布
    distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}
    test_salt = os.urandom(SALT_SIZE)

    start_time = time.time()

    for i in range(num_tests):
        test_key = f"test_key_{i}"
        result = obfuscated_key_determination(test_key, test_salt)
        distribution[result] += 1

    elapsed = time.time() - start_time

    print(f"\n異なる鍵・同一ソルトでの分布:")
    print(f"ソルト: {test_salt.hex()}")
    print(f"  TRUE: {distribution[KEY_TYPE_TRUE]} ({distribution[KEY_TYPE_TRUE]/num_tests:.2%})")
    print(f"  FALSE: {distribution[KEY_TYPE_FALSE]} ({distribution[KEY_TYPE_FALSE]/num_tests:.2%})")
    print(f"  分布の均一性: {min(distribution.values())/max(distribution.values()):.3f} (1.0が理想)")
    print(f"  処理時間: {elapsed:.2f}秒 ({num_tests/elapsed:.1f}判定/秒)")

    # 同一鍵・同一ソルトでの一貫性テスト
    print("\n同一鍵・同一ソルトでの一貫性テスト:")
    test_keys = [
        "consistency_test_key_1",
        "consistency_test_key_2",
        "consistency_test_key_3"
    ]
    test_salt = os.urandom(SALT_SIZE)

    for key in test_keys:
        results = []
        for _ in range(10):
            result = obfuscated_key_determination(key, test_salt)
            results.append(result)

        consistent = all(r == results[0] for r in results)
        print(f"鍵 '{key}': {'一貫性あり' if consistent else '一貫性なし'}")

if __name__ == "__main__":
    run_distribution_test()