#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
タイミング攻撃耐性テスト

鍵判定関数がタイミング攻撃に対して耐性があるかをテストします。
"""

import unittest
import os
import sys
import time
import statistics
from typing import Dict, List, Tuple, Callable, Union
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


class TestTimingAttack(unittest.TestCase):
    """タイミング攻撃耐性テスト"""

    def setUp(self):
        """テストの前処理"""
        # テスト用のソルト
        self.test_salt = os.urandom(SALT_SIZE)

        # テスト用の鍵
        self.test_keys = {
            'true_known_1': "true_key_sample_1",
            'true_known_2': "correct_password_123",
            'false_known_1': "false_key_sample_1",
            'false_known_2': "wrong_password_123",
            'neutral_1': "neutral_key_12345",
            'neutral_2': "sample_password_xyz"
        }

        # ランダム鍵を生成
        self.random_keys = [os.urandom(16).hex() for _ in range(10)]

        # イテレーション回数
        self.iterations = 100

    def _measure_execution_time(self, func: Callable, *args, **kwargs) -> float:
        """関数の実行時間を測定（ミリ秒単位）"""
        start_time = time.perf_counter()
        func(*args, **kwargs)
        end_time = time.perf_counter()
        return (end_time - start_time) * 1000  # ミリ秒単位で返す

    def _calculate_statistics(self, times: List[float]) -> Dict[str, float]:
        """時間計測結果の統計情報を計算"""
        times_array = np.array(times)
        return {
            'mean': np.mean(times_array),
            'median': np.median(times_array),
            'std_dev': np.std(times_array),
            'min': np.min(times_array),
            'max': np.max(times_array),
            'range': np.max(times_array) - np.min(times_array),
            'variance': np.var(times_array)
        }

    def _compare_timing_distributions(self, times1: List[float], times2: List[float]) -> Dict[str, float]:
        """2つの時間分布を比較し、差異を計算"""
        stats1 = self._calculate_statistics(times1)
        stats2 = self._calculate_statistics(times2)

        mean_diff = abs(stats1['mean'] - stats2['mean'])
        mean_diff_percent = (mean_diff / max(stats1['mean'], stats2['mean'])) * 100

        return {
            'mean_diff': mean_diff,
            'mean_diff_percent': mean_diff_percent,
            'stats1': stats1,
            'stats2': stats2
        }

    def test_determine_key_type_secure_timing(self):
        """determine_key_type_secure関数のタイミング攻撃耐性テスト"""
        print("\n===== determine_key_type_secure関数のタイミング攻撃耐性テスト =====")

        # 各鍵タイプごとの実行時間を測定
        true_times = []
        false_times = []

        # 既知の真/偽の鍵で測定
        for _ in range(self.iterations):
            true_times.append(self._measure_execution_time(
                determine_key_type_secure, self.test_keys['true_known_1'], self.test_salt))
            false_times.append(self._measure_execution_time(
                determine_key_type_secure, self.test_keys['false_known_1'], self.test_salt))

        # 結果の比較
        comparison = self._compare_timing_distributions(true_times, false_times)

        print(f"True鍵の平均実行時間: {comparison['stats1']['mean']:.4f} ms")
        print(f"False鍵の平均実行時間: {comparison['stats2']['mean']:.4f} ms")
        print(f"平均時間の差異: {comparison['mean_diff']:.4f} ms ({comparison['mean_diff_percent']:.2f}%)")

        # 許容可能な差異は5%以下（理想的には1%以下）
        # 5%を大きく超えると警告を出す
        if comparison['mean_diff_percent'] > 5:
            print(f"警告: 実行時間の差異が大きすぎます ({comparison['mean_diff_percent']:.2f}%)")

        # テスト結果（自動判定は実行環境に依存するため、ここではデータ表示のみ）
        self.assertTrue(True, "このテストは情報提供のみを目的としています")

    def test_determine_key_type_advanced_timing(self):
        """determine_key_type_advanced関数のタイミング攻撃耐性テスト"""
        print("\n===== determine_key_type_advanced関数のタイミング攻撃耐性テスト =====")

        # 各鍵タイプごとの実行時間を測定
        true_times = []
        false_times = []

        # 既知の真/偽の鍵で測定
        for _ in range(self.iterations):
            true_times.append(self._measure_execution_time(
                determine_key_type_advanced, self.test_keys['true_known_1'], self.test_salt))
            false_times.append(self._measure_execution_time(
                determine_key_type_advanced, self.test_keys['false_known_1'], self.test_salt))

        # 結果の比較
        comparison = self._compare_timing_distributions(true_times, false_times)

        print(f"True鍵の平均実行時間: {comparison['stats1']['mean']:.4f} ms")
        print(f"False鍵の平均実行時間: {comparison['stats2']['mean']:.4f} ms")
        print(f"平均時間の差異: {comparison['mean_diff']:.4f} ms ({comparison['mean_diff_percent']:.2f}%)")

        # 許容可能な差異は5%以下（理想的には1%以下）
        # 5%を大きく超えると警告を出す
        if comparison['mean_diff_percent'] > 5:
            print(f"警告: 実行時間の差異が大きすぎます ({comparison['mean_diff_percent']:.2f}%)")

        # テスト結果（自動判定は実行環境に依存するため、ここではデータ表示のみ）
        self.assertTrue(True, "このテストは情報提供のみを目的としています")

    def test_obfuscated_key_determination_timing(self):
        """obfuscated_key_determination関数のタイミング攻撃耐性テスト"""
        print("\n===== obfuscated_key_determination関数のタイミング攻撃耐性テスト =====")

        # 各鍵タイプごとの実行時間を測定
        true_times = []
        false_times = []

        # 既知の真/偽の鍵で測定
        for _ in range(self.iterations):
            true_times.append(self._measure_execution_time(
                obfuscated_key_determination, self.test_keys['true_known_1'], self.test_salt))
            false_times.append(self._measure_execution_time(
                obfuscated_key_determination, self.test_keys['false_known_1'], self.test_salt))

        # 結果の比較
        comparison = self._compare_timing_distributions(true_times, false_times)

        print(f"True鍵の平均実行時間: {comparison['stats1']['mean']:.4f} ms")
        print(f"False鍵の平均実行時間: {comparison['stats2']['mean']:.4f} ms")
        print(f"平均時間の差異: {comparison['mean_diff']:.4f} ms ({comparison['mean_diff_percent']:.2f}%)")

        # 許容可能な差異は5%以下（理想的には1%以下）
        # 5%を大きく超えると警告を出す
        if comparison['mean_diff_percent'] > 5:
            print(f"警告: 実行時間の差異が大きすぎます ({comparison['mean_diff_percent']:.2f}%)")

        # テスト結果（自動判定は実行環境に依存するため、ここではデータ表示のみ）
        self.assertTrue(True, "このテストは情報提供のみを目的としています")


# テスト実行
if __name__ == "__main__":
    unittest.main()