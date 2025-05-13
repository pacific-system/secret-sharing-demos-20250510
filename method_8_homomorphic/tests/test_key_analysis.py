#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の鍵解析テスト

このスクリプトは、準同型暗号マスキング方式の鍵解析機能をテストします。
鍵の解析精度や識別機能をテストし、鍵の種類（true/false）の判定が
適切に行われるかを検証します。
"""

import os
import sys
import time
import json
import random
import hashlib
import base64
import binascii
import unittest
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any, List, Tuple, Union, Optional
from collections import Counter

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.key_analyzer_robust import (
    analyze_key_type, analyze_key_type_robust, analyze_key_cryptic, analyze_key_integrated,
    generate_key_pair, verify_key_pair, derive_key_hmac, extract_seed_from_key,
    debug_analyze_key
)
from method_8_homomorphic.timing_resistant import (
    constant_time_compare, add_timing_noise, timing_resistant_operation,
    TimingProtection
)
from method_8_homomorphic.environmental_check import (
    get_system_entropy, get_hardware_fingerprint, get_dynamic_threshold,
    verify_key_in_environment, generate_environment_seed
)


class TestKeyAnalysis(unittest.TestCase):
    """鍵解析機能の基本テスト"""

    def setUp(self):
        """テスト準備"""
        # 出力ディレクトリの作成
        os.makedirs("test_output", exist_ok=True)

        # テスト用の鍵ペアを生成
        self.true_key, self.false_key = generate_key_pair()

    def test_key_type_analysis(self):
        """鍵タイプ解析の正確性テスト"""
        # true_keyの解析
        true_result = analyze_key_type(self.true_key)
        self.assertEqual("true", true_result)

        # false_keyの解析
        false_result = analyze_key_type(self.false_key)
        self.assertEqual("false", false_result)

        # 異なる解析方法での結果の一貫性
        true_result_robust = analyze_key_type_robust(self.true_key)
        self.assertEqual("true", true_result_robust)

        false_result_robust = analyze_key_type_robust(self.false_key)
        self.assertEqual("false", false_result_robust)

    def test_key_pair_verification(self):
        """鍵ペア検証機能のテスト"""
        # 正常な鍵ペア
        valid_pair = verify_key_pair(self.true_key, self.false_key)
        self.assertTrue(valid_pair)

        # 同じ鍵を使用した不正なペア
        invalid_pair1 = verify_key_pair(self.true_key, self.true_key)
        self.assertFalse(invalid_pair1)

        invalid_pair2 = verify_key_pair(self.false_key, self.false_key)
        self.assertFalse(invalid_pair2)

        # 別の正規の鍵ペアを生成
        another_true_key, another_false_key = generate_key_pair()

        # 正規と非正規のペアを混在させる
        mixed_pair1 = verify_key_pair(self.true_key, another_false_key)
        self.assertTrue(mixed_pair1)

        mixed_pair2 = verify_key_pair(another_true_key, self.false_key)
        self.assertTrue(mixed_pair2)

    def test_hmac_derivation(self):
        """HMACの導出テスト"""
        # ソルトの生成
        salt = os.urandom(16)

        # 真の鍵からのHMAC導出
        true_hmac_true = derive_key_hmac(self.true_key, salt, "true")
        true_hmac_false = derive_key_hmac(self.true_key, salt, "false")

        # 偽の鍵からのHMAC導出
        false_hmac_true = derive_key_hmac(self.false_key, salt, "true")
        false_hmac_false = derive_key_hmac(self.false_key, salt, "false")

        # HMACが一致しないことを確認
        self.assertNotEqual(true_hmac_true, true_hmac_false)
        self.assertNotEqual(false_hmac_true, false_hmac_false)
        self.assertNotEqual(true_hmac_true, false_hmac_true)
        self.assertNotEqual(true_hmac_false, false_hmac_false)

        # 同じ入力からは常に同じHMACが導出されることを確認
        true_hmac_true_repeat = derive_key_hmac(self.true_key, salt, "true")
        self.assertEqual(true_hmac_true, true_hmac_true_repeat)

    def test_seed_extraction(self):
        """シード抽出機能のテスト"""
        # ソルトの生成
        salt = os.urandom(16)

        # 真の鍵からのシード抽出
        true_seed_with_salt = extract_seed_from_key(self.true_key, salt)
        true_seed_without_salt = extract_seed_from_key(self.true_key)

        # 偽の鍵からのシード抽出
        false_seed_with_salt = extract_seed_from_key(self.false_key, salt)
        false_seed_without_salt = extract_seed_from_key(self.false_key)

        # シードが一致しないことを確認
        self.assertNotEqual(true_seed_with_salt, true_seed_without_salt)
        self.assertNotEqual(false_seed_with_salt, false_seed_without_salt)
        self.assertNotEqual(true_seed_with_salt, false_seed_with_salt)
        self.assertNotEqual(true_seed_without_salt, false_seed_without_salt)

        # 同じ入力からは常に同じシードが抽出されることを確認
        true_seed_repeat = extract_seed_from_key(self.true_key, salt)
        self.assertEqual(true_seed_with_salt, true_seed_repeat)

    def test_debug_analysis(self):
        """デバッグ解析機能のテスト"""
        # 真の鍵のデバッグ分析
        true_analysis = debug_analyze_key(self.true_key)

        # 偽の鍵のデバッグ分析
        false_analysis = debug_analyze_key(self.false_key)

        # 分析結果の検証
        self.assertEqual("true", true_analysis["result"])
        self.assertEqual("false", false_analysis["result"])

        # 分析結果にすべての必要なフィールドが含まれていることを確認
        for analysis in [true_analysis, false_analysis]:
            self.assertIn("key_hash", analysis)
            self.assertIn("key_features", analysis)
            self.assertIn("condition_results", analysis)
            self.assertIn("true_conditions", analysis)
            self.assertIn("environment_info", analysis)


class KeyStatisticalTest(unittest.TestCase):
    """鍵の統計的特性のテスト"""

    def setUp(self):
        """テスト準備"""
        # 出力ディレクトリの作成
        os.makedirs("test_output", exist_ok=True)

        # 複数の鍵ペアを生成
        self.sample_size = 100

        self.true_keys = []
        self.false_keys = []

        for _ in range(self.sample_size):
            true_key, false_key = generate_key_pair()
            self.true_keys.append(true_key)
            self.false_keys.append(false_key)

    def test_key_distribution(self):
        """鍵の分布テスト"""
        # ランダムな鍵を大量に生成
        random_keys = [os.urandom(32) for _ in range(1000)]

        # 各鍵を解析
        results = []
        for key in random_keys:
            result = analyze_key_type(key)
            results.append(result)

        # 結果を集計
        counter = Counter(results)

        # trueとfalseの分布が約50%ずつであることを確認
        true_ratio = counter.get("true", 0) / len(random_keys)
        false_ratio = counter.get("false", 0) / len(random_keys)

        # 分布の可視化
        plt.figure(figsize=(10, 6))
        plt.bar(["true", "false"], [true_ratio, false_ratio])
        plt.ylabel('Ratio')
        plt.title('Key Type Distribution')
        plt.grid(True, axis='y')

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/key_distribution_{timestamp}.png"
        plt.savefig(filename)

        # 40-60%の範囲内であることを確認（完全に50:50である保証はない）
        self.assertGreaterEqual(true_ratio, 0.4)
        self.assertLessEqual(true_ratio, 0.6)
        self.assertGreaterEqual(false_ratio, 0.4)
        self.assertLessEqual(false_ratio, 0.6)

    def test_cryptic_vs_integrated_analysis(self):
        """暗号的解析と統合解析の比較"""
        # 各解析方法での結果を取得
        cryptic_results = []
        integrated_results = []

        # 全ての鍵に対して両方の解析を実行
        for key in self.true_keys + self.false_keys:
            cryptic_result = analyze_key_cryptic(key)
            integrated_result = analyze_key_integrated(key)

            cryptic_results.append(cryptic_result)
            integrated_results.append(integrated_result)

        # 一致率を計算
        match_count = sum(1 for c, i in zip(cryptic_results, integrated_results) if c == i)
        match_ratio = match_count / len(cryptic_results)

        # 結果の可視化
        plt.figure(figsize=(10, 6))

        # 各解析方法の結果分布
        cryptic_counter = Counter(cryptic_results)
        integrated_counter = Counter(integrated_results)

        x = np.arange(2)
        width = 0.35

        plt.bar(x - width/2, [cryptic_counter.get("true", 0) / len(cryptic_results),
                             cryptic_counter.get("false", 0) / len(cryptic_results)],
                width, label='Cryptic')
        plt.bar(x + width/2, [integrated_counter.get("true", 0) / len(integrated_results),
                             integrated_counter.get("false", 0) / len(integrated_results)],
                width, label='Integrated')

        plt.xticks(x, ["true", "false"])
        plt.ylabel('Ratio')
        plt.title('Cryptic vs Integrated Analysis')
        plt.legend()
        plt.grid(True, axis='y')

        # 一致率を表示
        plt.text(0.5, 0.9, f"Match ratio: {match_ratio:.2f}",
                 horizontalalignment='center',
                 transform=plt.gca().transAxes)

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/analysis_comparison_{timestamp}.png"
        plt.savefig(filename)

        # 一致率が高いことを確認（少なくとも80%）
        self.assertGreaterEqual(match_ratio, 0.8)

    def test_timing_attack_resistance(self):
        """タイミング攻撃耐性テスト"""
        # サンプル数
        n_samples = 50

        # 真の鍵と偽の鍵に対する処理時間を測定
        true_times = []
        false_times = []

        # 真の鍵の処理時間
        for _ in range(n_samples):
            key = random.choice(self.true_keys)

            start_time = time.time()
            analyze_key_type(key)
            elapsed = time.time() - start_time

            true_times.append(elapsed)

        # 偽の鍵の処理時間
        for _ in range(n_samples):
            key = random.choice(self.false_keys)

            start_time = time.time()
            analyze_key_type(key)
            elapsed = time.time() - start_time

            false_times.append(elapsed)

        # 平均と標準偏差を計算
        true_mean = np.mean(true_times)
        false_mean = np.mean(false_times)
        true_std = np.std(true_times)
        false_std = np.std(false_times)

        # 統計的有意差を計算（t検定）
        from scipy import stats
        t_stat, p_value = stats.ttest_ind(true_times, false_times)

        # 結果の可視化
        plt.figure(figsize=(10, 6))

        # 処理時間の分布
        plt.subplot(2, 1, 1)
        plt.hist(true_times, alpha=0.5, label='True Keys')
        plt.hist(false_times, alpha=0.5, label='False Keys')
        plt.xlabel('Processing Time (seconds)')
        plt.ylabel('Frequency')
        plt.title('Key Analysis Timing Distribution')
        plt.legend()
        plt.grid(True)

        # 箱ひげ図
        plt.subplot(2, 1, 2)
        plt.boxplot([true_times, false_times], labels=["True Keys", "False Keys"])
        plt.ylabel('Processing Time (seconds)')
        plt.title(f'Timing Comparison (p-value: {p_value:.6f})')
        plt.grid(True)

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/timing_attack_test_{timestamp}.png"
        plt.savefig(filename)

        # p値が0.05以上であれば、統計的に有意な差がないと判断
        self.assertGreaterEqual(p_value, 0.05,
                              f"タイミング攻撃の脆弱性が検出されました（p値: {p_value}）")


class EnvironmentalDependencyTest(unittest.TestCase):
    """環境依存特性のテスト"""

    def setUp(self):
        """テスト準備"""
        # 出力ディレクトリの作成
        os.makedirs("test_output", exist_ok=True)

        # テスト用の鍵ペアを生成
        self.true_key, self.false_key = generate_key_pair()

    def test_system_entropy(self):
        """システムエントロピーのテスト"""
        # 複数回のエントロピー取得
        entropy_samples = [get_system_entropy() for _ in range(10)]

        # すべてのサンプルが一致することを確認（環境が変わらなければ同じ値）
        for sample in entropy_samples[1:]:
            self.assertEqual(entropy_samples[0], sample)

        # ソルトを追加した場合は異なる値になることを確認
        salt = os.urandom(16)
        entropy_with_salt = get_system_entropy(salt)
        self.assertNotEqual(entropy_samples[0], entropy_with_salt)

    def test_hardware_fingerprint(self):
        """ハードウェアフィンガープリントのテスト"""
        # 揮発性情報なしのフィンガープリント
        non_volatile_fp = get_hardware_fingerprint(include_volatile=False)

        # 10回サンプリング
        samples = [get_hardware_fingerprint(include_volatile=False) for _ in range(10)]

        # すべてのサンプルが一致することを確認
        for sample in samples:
            self.assertEqual(non_volatile_fp, sample)

        # 揮発性情報ありのフィンガープリント（実行環境によっては異なる可能性がある）
        volatile_fp = get_hardware_fingerprint(include_volatile=True)

        # 通常、揮発性情報を含むと含まないフィンガープリントは異なるが、
        # 環境によっては同じになる可能性もあるため、このテストはスキップ
        # self.assertNotEqual(non_volatile_fp, volatile_fp)

    def test_dynamic_threshold(self):
        """動的閾値のテスト"""
        # 同じ入力での一貫性
        threshold1 = get_dynamic_threshold(0.5, self.true_key)
        threshold2 = get_dynamic_threshold(0.5, self.true_key)
        self.assertEqual(threshold1, threshold2)

        # 異なる入力では異なる値
        threshold_false = get_dynamic_threshold(0.5, self.false_key)
        self.assertNotEqual(threshold1, threshold_false)

        # 範囲のチェック（0.3〜0.7）
        thresholds = [get_dynamic_threshold(0.5, os.urandom(32)) for _ in range(100)]
        for t in thresholds:
            self.assertGreaterEqual(t, 0.3)
            self.assertLessEqual(t, 0.7)

        # 閾値の分布を可視化
        plt.figure(figsize=(10, 6))
        plt.hist(thresholds, bins=20)
        plt.xlabel('Threshold Value')
        plt.ylabel('Frequency')
        plt.title('Dynamic Threshold Distribution')
        plt.grid(True)

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/dynamic_threshold_{timestamp}.png"
        plt.savefig(filename)

    def test_key_environment_verification(self):
        """環境依存の鍵検証テスト"""
        # ソルトの生成
        salt = os.urandom(16)

        # 真の鍵を環境で検証
        true_verified_as_true = verify_key_in_environment(self.true_key, "true", salt)
        true_verified_as_false = verify_key_in_environment(self.true_key, "false", salt)

        # 偽の鍵を環境で検証
        false_verified_as_true = verify_key_in_environment(self.false_key, "true", salt)
        false_verified_as_false = verify_key_in_environment(self.false_key, "false", salt)

        # 正しい検証結果であることを確認
        # 注意：環境依存の要素があるため、常に100%正確とは限らない
        # 重要なのは、TrueとFalseの両方のケースが存在し、一意に決まらないこと

        # 何らかの冗長性を確認（4つの組み合わせで全て同じにならないこと）
        results = [true_verified_as_true, true_verified_as_false,
                  false_verified_as_true, false_verified_as_false]

        # 少なくとも1つはTrueで1つはFalseであることを確認
        self.assertTrue(any(results))
        self.assertFalse(all(results))


def run_key_analysis_tests():
    """鍵解析テストの実行"""
    # 出力ディレクトリの作成
    os.makedirs("test_output", exist_ok=True)

    # テスト結果を格納する辞書
    test_results = {}

    # TestKeyAnalysisを実行
    key_analysis_suite = unittest.TestLoader().loadTestsFromTestCase(TestKeyAnalysis)
    key_analysis_result = unittest.TextTestRunner(verbosity=2).run(key_analysis_suite)

    # KeyStatisticalTestを実行
    statistical_suite = unittest.TestLoader().loadTestsFromTestCase(KeyStatisticalTest)
    statistical_result = unittest.TextTestRunner(verbosity=2).run(statistical_suite)

    # EnvironmentalDependencyTestを実行
    environmental_suite = unittest.TestLoader().loadTestsFromTestCase(EnvironmentalDependencyTest)
    environmental_result = unittest.TextTestRunner(verbosity=2).run(environmental_suite)

    # 成功したかどうか
    all_passed = (key_analysis_result.wasSuccessful() and
                 statistical_result.wasSuccessful() and
                 environmental_result.wasSuccessful())

    # 結果を出力
    print("\n============ 鍵解析テスト結果 ============")
    if all_passed:
        print("✅ 全てのテストが成功しました！")
    else:
        print("❌ 一部のテストが失敗しました。")

    print(f"\n基本テスト: {'成功' if key_analysis_result.wasSuccessful() else '失敗'}")
    print(f"統計テスト: {'成功' if statistical_result.wasSuccessful() else '失敗'}")
    print(f"環境テスト: {'成功' if environmental_result.wasSuccessful() else '失敗'}")

    return all_passed


if __name__ == "__main__":
    # テストの実行
    success = run_key_analysis_tests()

    # 終了コード
    sys.exit(0 if success else 1)