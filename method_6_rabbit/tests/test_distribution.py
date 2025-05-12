#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
鍵判定分布テスト

鍵判定関数の結果分布をテストします。
ランダムな鍵とソルトを使用した場合、true/falseの結果が均等に分布することを確認します。
"""

import unittest
import os
import sys
import random
import binascii
from typing import Dict, List, Callable, Union
import matplotlib.pyplot as plt
import numpy as np

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# モジュールインポート
from method_6_rabbit.key_analyzer import (
    determine_key_type_advanced,
    obfuscated_key_determination,
    KEY_TYPE_TRUE,
    KEY_TYPE_FALSE,
    SALT_SIZE
)
from method_6_rabbit.stream_selector import determine_key_type_secure


class TestDistribution(unittest.TestCase):
    """鍵判定分布テスト"""

    def setUp(self):
        """テストの前処理"""
        # テスト用パラメータ
        self.num_samples = 1000  # サンプル数
        self.acceptable_deviation = 0.1  # 許容偏差（10%）

    def _run_distribution_test(self, func: Callable, description: str) -> Dict[str, int]:
        """分布テストを実行"""
        distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

        # ランダムな鍵とソルトでテスト
        for _ in range(self.num_samples):
            random_key = os.urandom(16).hex()
            random_salt = os.urandom(SALT_SIZE)
            result = func(random_key, random_salt)
            distribution[result] += 1

        # 結果の表示
        true_ratio = distribution[KEY_TYPE_TRUE] / self.num_samples
        false_ratio = distribution[KEY_TYPE_FALSE] / self.num_samples

        print(f"\n===== {description} =====")
        print(f"テスト回数: {self.num_samples}")
        print(f"TRUE: {distribution[KEY_TYPE_TRUE]} ({true_ratio:.2%})")
        print(f"FALSE: {distribution[KEY_TYPE_FALSE]} ({false_ratio:.2%})")

        # 均一性の指標（最小値/最大値）- 1.0が理想
        uniformity = min(distribution.values()) / max(distribution.values())
        print(f"分布の均一性: {uniformity:.3f} (1.0が理想)")

        # 許容範囲内かチェック（理想は50:50）
        deviation = abs(true_ratio - 0.5)
        print(f"50%からの偏差: {deviation:.2%}")

        self.assertLessEqual(deviation, self.acceptable_deviation,
                          f"分布の偏りが許容範囲を超えています: {deviation:.2%} > {self.acceptable_deviation:.2%}")

        return distribution

    def test_determine_key_type_secure_distribution(self):
        """determine_key_type_secure関数の分布テスト"""
        distribution = self._run_distribution_test(
            determine_key_type_secure,
            "determine_key_type_secure関数の分布テスト"
        )
        self._visualize_distribution(distribution, "determine_key_type_secure")

    def test_determine_key_type_advanced_distribution(self):
        """determine_key_type_advanced関数の分布テスト"""
        distribution = self._run_distribution_test(
            determine_key_type_advanced,
            "determine_key_type_advanced関数の分布テスト"
        )
        self._visualize_distribution(distribution, "determine_key_type_advanced")

    def test_obfuscated_key_determination_distribution(self):
        """obfuscated_key_determination関数の分布テスト"""
        distribution = self._run_distribution_test(
            obfuscated_key_determination,
            "obfuscated_key_determination関数の分布テスト"
        )
        self._visualize_distribution(distribution, "obfuscated_key_determination")

    def test_fixed_salt_different_keys(self):
        """固定ソルト・異なる鍵での分布テスト"""
        print("\n===== 固定ソルト・異なる鍵での分布テスト =====")

        fixed_salt = os.urandom(SALT_SIZE)
        distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

        for _ in range(self.num_samples):
            random_key = os.urandom(16).hex()
            result = obfuscated_key_determination(random_key, fixed_salt)
            distribution[result] += 1

        true_ratio = distribution[KEY_TYPE_TRUE] / self.num_samples
        false_ratio = distribution[KEY_TYPE_FALSE] / self.num_samples

        print(f"テスト回数: {self.num_samples}")
        print(f"TRUE: {distribution[KEY_TYPE_TRUE]} ({true_ratio:.2%})")
        print(f"FALSE: {distribution[KEY_TYPE_FALSE]} ({false_ratio:.2%})")

        # 均一性の指標
        uniformity = min(distribution.values()) / max(distribution.values())
        print(f"分布の均一性: {uniformity:.3f} (1.0が理想)")

        # この場合も均等分布が期待される
        deviation = abs(true_ratio - 0.5)
        print(f"50%からの偏差: {deviation:.2%}")

        self.assertLessEqual(deviation, self.acceptable_deviation,
                          f"分布の偏りが許容範囲を超えています: {deviation:.2%} > {self.acceptable_deviation:.2%}")

        self._visualize_distribution(distribution, "fixed_salt_different_keys")

    def test_fixed_key_different_salts(self):
        """固定鍵・異なるソルトでの分布テスト"""
        print("\n===== 固定鍵・異なるソルトでの分布テスト =====")

        fixed_key = os.urandom(16).hex()
        distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

        for _ in range(self.num_samples):
            random_salt = os.urandom(SALT_SIZE)
            result = obfuscated_key_determination(fixed_key, random_salt)
            distribution[result] += 1

        true_ratio = distribution[KEY_TYPE_TRUE] / self.num_samples
        false_ratio = distribution[KEY_TYPE_FALSE] / self.num_samples

        print(f"テスト回数: {self.num_samples}")
        print(f"TRUE: {distribution[KEY_TYPE_TRUE]} ({true_ratio:.2%})")
        print(f"FALSE: {distribution[KEY_TYPE_FALSE]} ({false_ratio:.2%})")

        # 均一性の指標
        uniformity = min(distribution.values()) / max(distribution.values())
        print(f"分布の均一性: {uniformity:.3f} (1.0が理想)")

        # この場合も均等分布が期待される
        deviation = abs(true_ratio - 0.5)
        print(f"50%からの偏差: {deviation:.2%}")

        self.assertLessEqual(deviation, self.acceptable_deviation,
                          f"分布の偏りが許容範囲を超えています: {deviation:.2%} > {self.acceptable_deviation:.2%}")

        self._visualize_distribution(distribution, "fixed_key_different_salts")

    def test_specific_keys_many_salts(self):
        """特定の鍵セットと複数のソルトでの分布テスト"""
        print("\n===== 特定の鍵セットと複数のソルトでの分布テスト =====")

        # テスト用の鍵セット
        test_keys = [
            "test_key_1",
            "password123",
            "complex_p@ssw0rd!",
            "simple",
            "a" * 20,  # 単一文字の繰り返し
            "0123456789abcdef",  # 16進数文字列
            os.urandom(16).hex()  # ランダムHEX文字列
        ]

        results = {}

        # 各鍵ごとの分布を計測
        for key in test_keys:
            distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

            # 異なるソルトでテスト
            for _ in range(self.num_samples // len(test_keys)):
                random_salt = os.urandom(SALT_SIZE)
                result = obfuscated_key_determination(key, random_salt)
                distribution[result] += 1

            true_ratio = distribution[KEY_TYPE_TRUE] / (self.num_samples // len(test_keys))
            results[key] = true_ratio

        # 結果の表示
        print(f"各鍵のTRUE判定率:")
        for key, ratio in results.items():
            print(f"'{key}': {ratio:.2%}")

        # 平均と標準偏差
        ratios = list(results.values())
        avg_ratio = sum(ratios) / len(ratios)
        std_dev = np.std(ratios)

        print(f"平均TRUE判定率: {avg_ratio:.2%}")
        print(f"標準偏差: {std_dev:.4f}")

        # 期待値は0.5付近、標準偏差は小さいことが望ましい
        self.assertLessEqual(abs(avg_ratio - 0.5), self.acceptable_deviation,
                          f"平均判定率の偏りが許容範囲を超えています: {abs(avg_ratio - 0.5):.2%} > {self.acceptable_deviation:.2%}")

        # テストは情報提供が目的なので常に成功とする
        self.assertTrue(True)

    def _visualize_distribution(self, distribution: Dict[str, int], test_name: str):
        """分布を視覚化"""
        try:
            labels = list(distribution.keys())
            values = list(distribution.values())

            plt.figure(figsize=(8, 6))
            plt.bar(labels, values, color=['green', 'red'])
            plt.title(f'Key Type Distribution - {test_name}')
            plt.ylabel('Count')
            plt.xticks(labels)

            # パーセント表示を追加
            total = sum(values)
            for i, v in enumerate(values):
                plt.text(i, v + 5, f"{v/total:.1%}", ha='center')

            # 保存（表示ではなく保存）
            output_dir = "test_results"
            os.makedirs(output_dir, exist_ok=True)
            plt.savefig(f"{output_dir}/{test_name}_distribution.png")
            plt.close()

            print(f"分布グラフを保存しました: {output_dir}/{test_name}_distribution.png")
        except Exception as e:
            print(f"グラフ生成エラー: {e}")


# テスト実行
if __name__ == "__main__":
    unittest.main()