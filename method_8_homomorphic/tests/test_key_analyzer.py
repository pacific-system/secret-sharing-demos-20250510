#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
鍵解析機能のテストスクリプト
"""

import os
import sys
import hashlib
import random
from typing import Tuple, List

# 親ディレクトリをインポートパスに追加
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.abspath(os.path.join(parent_dir, '..')))

from method_8_homomorphic.key_analyzer import analyze_key_type

def test_key_analyzer():
    """
    key_analyzerモジュールのテスト
    """
    # テスト1: 暗号化で生成された鍵の解析
    test_keys = [
        "78be52653aced8287422d0ce032dd9cb0cbfbf80c4c353044baab57680afb57d",
        "fc66f1a401520d52bc4feca298ea2515326bfbcf440e1f7af05313d9bcab81f4",
        "93b77965c46a361499c6e5cc2d9e6706dcdf69807b40b6484fbd5910385f5999"
    ]

    print("既知の鍵の解析:")
    for key_hex in test_keys:
        key = bytes.fromhex(key_hex)
        key_type = analyze_key_type(key)
        print(f"鍵: {key_hex[:8]}... -> {key_type}")

    # テスト2: ランダムな鍵の生成と統計
    num_keys = 100
    true_count = 0
    false_count = 0

    print(f"\nランダムな{num_keys}個の鍵の統計:")
    for _ in range(num_keys):
        # ランダム鍵を生成
        key = os.urandom(32)
        key_type = analyze_key_type(key)

        if key_type == "true":
            true_count += 1
        else:
            false_count += 1

    print(f"true鍵: {true_count}/{num_keys} ({true_count/num_keys*100:.1f}%)")
    print(f"false鍵: {false_count}/{num_keys} ({false_count/num_keys*100:.1f}%)")

    # テスト3: 特定パターンの鍵で解析
    print("\n特定パターンの鍵の解析:")

    # 偶数文字で始まる鍵
    even_key = bytes.fromhex("2" + "0" * 63)
    print(f"偶数文字で始まる鍵: {analyze_key_type(even_key)}")

    # 奇数文字で始まる鍵
    odd_key = bytes.fromhex("1" + "0" * 63)
    print(f"奇数文字で始まる鍵: {analyze_key_type(odd_key)}")

    # 修正テスト: 特定の鍵で両方のタイプを生成
    # ビット操作でわずかに異なる鍵を生成
    base_key = os.urandom(32)
    base_key_hex = base_key.hex()

    # 強制的に偶数文字で始める
    even_start_key = bytes.fromhex("2" + base_key_hex[1:])
    even_key_type = analyze_key_type(even_start_key)

    # 強制的に奇数文字で始める
    odd_start_key = bytes.fromhex("1" + base_key_hex[1:])
    odd_key_type = analyze_key_type(odd_start_key)

    print(f"\n先頭文字制御テスト:")
    print(f"元の鍵: {base_key_hex[:16]}...")
    print(f"偶数文字始まり: {even_start_key.hex()[:16]}... -> {even_key_type}")
    print(f"奇数文字始まり: {odd_start_key.hex()[:16]}... -> {odd_key_type}")

    # テスト4: キーペアの生成
    true_key, false_key = generate_key_pair()
    print(f"\n生成されたキーペア:")
    print(f"true鍵: {true_key.hex()[:16]}... -> {analyze_key_type(true_key)}")
    print(f"false鍵: {false_key.hex()[:16]}... -> {analyze_key_type(false_key)}")

def generate_key_pair() -> Tuple[bytes, bytes]:
    """
    真と偽の鍵ペアを生成

    Returns:
        (真の鍵, 偽の鍵)のタプル
    """
    # ランダムなシード値
    seed = random.randint(0, 0xFFFFFFFF)
    random.seed(seed)

    # 真の鍵を生成
    while True:
        true_key_candidate = os.urandom(32)
        if analyze_key_type(true_key_candidate) == "true":
            true_key = true_key_candidate
            break

    # 偽の鍵を生成
    while True:
        false_key_candidate = os.urandom(32)
        if analyze_key_type(false_key_candidate) == "false":
            false_key = false_key_candidate
            break

    return true_key, false_key

if __name__ == "__main__":
    test_key_analyzer()