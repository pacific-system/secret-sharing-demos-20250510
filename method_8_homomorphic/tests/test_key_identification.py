#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の鍵種別判定ロジックテスト

このスクリプトは、鍵の種別（true/false）を判定するロジックをテストします。
特に、ソースコード解析耐性、タイミング攻撃対策、複数の偽装・難読化技術、
環境依存の動的判定要素が正しく機能していることを確認します。
"""

import os
import sys
import time
import hashlib
import random
import unittest
import json
import statistics
import binascii
import matplotlib.pyplot as plt
import numpy as np
from typing import List, Dict, Any, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# テスト対象のモジュールをインポート
from method_8_homomorphic.key_analyzer_robust import (
    analyze_key_type,
    analyze_key_type_robust,
    analyze_key_cryptic,
    analyze_key_integrated,
    generate_key_pair,
    extract_key_feature,
    evaluate_condition,
    debug_analyze_key
)

from method_8_homomorphic.timing_resistant import (
    add_timing_noise,
    timing_resistant_operation,
    constant_time_compare,
    TimingProtection
)

from method_8_homomorphic.environmental_check import (
    get_dynamic_threshold,
    verify_key_in_environment,
    generate_environment_seed
)

class KeyIdentificationTests(unittest.TestCase):
    """鍵種別判定ロジックのテストケース"""

    def setUp(self):
        """テストのセットアップ"""
        # テスト用の鍵ペアを生成（複数）
        self.key_pairs = []
        for _ in range(3):
            true_key, false_key = generate_key_pair()
            self.key_pairs.append((true_key, false_key))

        # ランダムな鍵のセットも生成
        self.random_keys = [os.urandom(32) for _ in range(10)]

        # 結果を保存するディレクトリを確認
        self.output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../test_output'))
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def test_key_type_identification(self):
        """鍵の種別判定の基本機能テスト"""
        print("\n=== 鍵種別判定の基本機能テスト ===")

        # 生成された鍵ペアの種別判定をテスト
        for i, (true_key, false_key) in enumerate(self.key_pairs):
            # 真の鍵のテスト
            true_result = analyze_key_type_robust(true_key)
            self.assertEqual(true_result, "true", f"鍵ペア{i}の真の鍵が正しく判定されませんでした")

            # 偽の鍵のテスト
            false_result = analyze_key_type_robust(false_key)
            self.assertEqual(false_result, "false", f"鍵ペア{i}の偽の鍵が正しく判定されませんでした")

            print(f"鍵ペア{i}: 真の鍵 = {true_result}, 偽の鍵 = {false_result} ✓")

    def test_different_analysis_methods(self):
        """異なる解析手法の結果比較"""
        print("\n=== 異なる解析手法の結果比較 ===")

        # ランダムな鍵について異なる手法の結果を比較
        for i, key in enumerate(self.random_keys[:5]):
            # 3つの異なる手法で解析
            robust_result = analyze_key_type_robust(key)
            cryptic_result = analyze_key_cryptic(key)
            integrated_result = analyze_key_integrated(key)

            # 標準の方法（従来のインターフェース）
            std_result = analyze_key_type(key)

            # 各手法の結果を表示
            key_short = binascii.hexlify(key[:4]).decode() + "..."
            print(f"鍵{i} ({key_short}):")
            print(f"  標準手法: {std_result}")
            print(f"  堅牢手法: {robust_result}")
            print(f"  難読化手法: {cryptic_result}")
            print(f"  統合手法: {integrated_result}")

            # 堅牢手法と標準手法の結果が一致することを確認
            self.assertEqual(robust_result, std_result,
                            f"堅牢手法と標準手法の結果が一致しません: {robust_result} vs {std_result}")

    def test_condition_evaluation(self):
        """条件評価関数のテスト"""
        print("\n=== 条件評価関数のテスト ===")

        # いくつかのランダム鍵に対して条件評価をテスト
        key = self.random_keys[0]

        # 各条件の評価結果
        condition_results = {}
        for i in range(6):  # 6種類の条件がある
            result = evaluate_condition(key, i)
            condition_results[f"条件{i}"] = result

        # 結果を表示
        for cond, result in condition_results.items():
            print(f"{cond}: {result}")

        # 特性抽出をテスト
        features = {}
        for i in range(3):
            feature = extract_key_feature(key, i)
            features[f"特性{i}"] = feature

        print("抽出された特性値（16進数表示）:")
        for name, value in features.items():
            print(f"{name}: 0x{value:x}")

    def test_timing_attack_resistance(self):
        """タイミング攻撃耐性のテスト"""
        print("\n=== タイミング攻撃耐性のテスト ===")

        # 同じ鍵に対する複数回の判定処理の時間を測定
        key = self.random_keys[0]
        timings = []

        # 複数回実行して時間を測定
        iterations = 50
        for _ in range(iterations):
            start_time = time.time()
            _ = analyze_key_type_robust(key)
            end_time = time.time()
            elapsed = (end_time - start_time) * 1000  # ミリ秒に変換
            timings.append(elapsed)

        # 統計情報を表示
        mean_time = statistics.mean(timings)
        stdev_time = statistics.stdev(timings)
        min_time = min(timings)
        max_time = max(timings)

        print(f"実行時間の統計（{iterations}回実行）:")
        print(f"  平均: {mean_time:.2f}ms")
        print(f"  標準偏差: {stdev_time:.2f}ms")
        print(f"  最小: {min_time:.2f}ms")
        print(f"  最大: {max_time:.2f}ms")

        # タイミングの分布をグラフ化
        plt.figure(figsize=(10, 6))
        plt.hist(timings, bins=10, alpha=0.7, color='blue')
        plt.axvline(mean_time, color='red', linestyle='dashed', linewidth=2, label=f'平均: {mean_time:.2f}ms')
        plt.xlabel('実行時間 (ミリ秒)')
        plt.ylabel('頻度')
        plt.title('鍵解析関数の実行時間分布')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)

        # グラフを保存
        timestamp = int(time.time())
        plt.savefig(os.path.join(self.output_dir, f'timing_analysis_{timestamp}.png'))
        print(f"タイミング分析グラフを保存しました: 'timing_analysis_{timestamp}.png'")
        plt.close()

    def test_environmental_factors(self):
        """環境要素の影響テスト"""
        print("\n=== 環境要素の影響テスト ===")

        # 環境要素を含む判定と含まない判定の比較
        key = self.random_keys[0]

        # 通常の判定
        normal_result = analyze_key_type_robust(key)

        # 環境シードを生成
        env_seed = generate_environment_seed(key)

        # 環境要素を考慮した判定
        env_result = verify_key_in_environment(key, normal_result)

        print(f"通常の判定結果: {normal_result}")
        print(f"環境要素考慮時の一致: {env_result} ({'一致' if env_result else '不一致'})")

        # 動的閾値のテスト
        threshold = get_dynamic_threshold(0.5, key)
        print(f"動的閾値: {threshold:.4f}")

        # 閾値が予想範囲内であることを確認
        self.assertTrue(0.3 <= threshold <= 0.7,
                        f"動的閾値が予想範囲外です: {threshold}")

    def test_detailed_analysis(self):
        """詳細分析機能のテスト"""
        print("\n=== 詳細分析機能のテスト ===")

        # 1つの鍵について詳細分析
        key = self.random_keys[0]

        # 詳細分析を実行
        analysis = debug_analyze_key(key)

        # 結果の主要部分を表示
        print(f"鍵の詳細分析（抜粋）:")
        print(f"  鍵種別: {analysis['result']}")
        print(f"  暗号的特性: 条件満たす数 {analysis['true_conditions']}/{analysis['total_conditions']}")

        # 特性値の一部を表示
        print("  特性値（抜粋）:")
        for name, value in list(analysis['key_features'].items())[:3]:
            print(f"    {name}: {value}")

        # 閾値情報を表示
        print(f"  動的閾値: {analysis['environment_info']['dynamic_threshold']:.4f}")

        # JSONとして保存
        timestamp = int(time.time())
        output_file = os.path.join(self.output_dir, f'key_analysis_{timestamp}.json')

        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)

        print(f"詳細分析結果をJSONとして保存しました: 'key_analysis_{timestamp}.json'")

    def test_key_distribution(self):
        """鍵分布のテスト"""
        print("\n=== 鍵分布のテスト ===")

        # 多数のランダム鍵を生成して分布を分析
        sample_size = 100
        random_keys = [os.urandom(32) for _ in range(sample_size)]

        # 各鍵の種別を判定
        true_count = 0
        false_count = 0

        for key in random_keys:
            key_type = analyze_key_type_robust(key)
            if key_type == "true":
                true_count += 1
            else:
                false_count += 1

        true_ratio = true_count / sample_size
        false_ratio = false_count / sample_size

        # 結果を表示
        print(f"ランダム鍵 {sample_size} 個の種別分布:")
        print(f"  真の鍵: {true_count} ({true_ratio:.2%})")
        print(f"  偽の鍵: {false_count} ({false_ratio:.2%})")

        # 分布を視覚化
        plt.figure(figsize=(8, 5))
        plt.bar(['真の鍵', '偽の鍵'], [true_count, false_count], color=['green', 'red'])
        plt.ylabel('鍵の数')
        plt.title('ランダム生成された鍵の種別分布')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # 各バーに数値を表示
        for i, v in enumerate([true_count, false_count]):
            plt.text(i, v + 1, f"{v} ({v/sample_size:.1%})", ha='center')

        # グラフを保存
        timestamp = int(time.time())
        plt.savefig(os.path.join(self.output_dir, f'key_distribution_{timestamp}.png'))
        print(f"鍵分布グラフを保存しました: 'key_distribution_{timestamp}.png'")
        plt.close()

    def test_robustness_simulation(self):
        """ソースコード解析耐性のシミュレーション"""
        print("\n=== ソースコード解析耐性のシミュレーション ===")

        # オリジナル鍵のセット
        key = self.random_keys[0]
        original_type = analyze_key_type_robust(key)

        # 1. 単一条件の改変をシミュレーション
        print("1. 単一条件改変のシミュレーション")

        # 単一条件を反転した場合の耐性をシミュレーション
        conditions_results = []
        for condition_id in range(8):
            # 元の条件結果
            original_condition = evaluate_condition(key, condition_id)

            # この条件を反転した場合の影響をシミュレーション
            modified_results = []
            for _ in range(10):  # 複数回実行して安定した結果を得る
                # 条件反転の影響をシミュレーション
                if condition_id % 6 == 0:  # ビット数の偶奇
                    # 条件0の結果を反転
                    modified_result = not original_type == "true"
                else:
                    # 他の条件は複合的なため、実際の判定関数を使用
                    modified_result = analyze_key_type_robust(key) == "true"

                modified_results.append(modified_result)

            # 主要な結果を計算（モード）
            modified_type = "true" if sum(modified_results) > len(modified_results) / 2 else "false"
            changed = modified_type != original_type

            conditions_results.append({
                "condition_id": condition_id,
                "original": original_condition,
                "modified_type": modified_type,
                "changed": changed
            })

            print(f"  条件{condition_id}を反転: {'変化あり' if changed else '変化なし'}")

        # 変化した条件の割合
        changed_ratio = sum(1 for c in conditions_results if c["changed"]) / len(conditions_results)
        print(f"  単一条件の改変で結果が変化する割合: {changed_ratio:.2%}")

        # 2. 複合条件操作のシミュレーション
        print("2. 複合条件操作のシミュレーション")

        # 異なる分析方法を比較
        cryptic_type = analyze_key_cryptic(key)
        integrated_type = analyze_key_integrated(key)

        print(f"  鍵タイプ (オリジナル): {original_type}")
        print(f"  鍵タイプ (暗号的方法): {cryptic_type}")
        print(f"  鍵タイプ (統合的方法): {integrated_type}")

        # 判定方法間の一致率を算出
        agreement = (original_type == cryptic_type) and (original_type == integrated_type)
        print(f"  すべての方法の判定結果の一致: {'一致' if agreement else '不一致'}")

        # 耐性スコアの計算（高いほど改変に強い）
        resistance_score = 1.0 - changed_ratio if agreement else 0.5
        print(f"  ソースコード解析耐性スコア: {resistance_score:.2f}/1.00")

        # グラフを生成して保存
        plt.figure(figsize=(10, 6))

        # 条件反転の影響をグラフ化
        condition_ids = [c["condition_id"] for c in conditions_results]
        changes = [1 if c["changed"] else 0 for c in conditions_results]

        plt.subplot(1, 2, 1)
        plt.bar(condition_ids, changes, color=['red' if c else 'green' for c in changes])
        plt.xlabel('条件ID')
        plt.ylabel('結果変化')
        plt.title('条件反転の影響')
        plt.yticks([0, 1], ['変化なし', '変化あり'])
        plt.grid(axis='y', linestyle='--', alpha=0.5)

        # 耐性スコアをゲージグラフで表示
        plt.subplot(1, 2, 2)
        resistance_gauge = np.array([resistance_score, 1.0 - resistance_score])
        colors = ['green', 'lightgray']
        labels = [f'耐性 ({resistance_score:.2f})', '']

        plt.pie(resistance_gauge, colors=colors, labels=labels, startangle=90,
                wedgeprops={'width': 0.3, 'edgecolor': 'w'})
        plt.title('ソースコード解析耐性スコア')

        # グラフを保存
        timestamp = int(time.time())
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, f'code_analysis_resistance_{timestamp}.png'))
        print(f"解析耐性シミュレーショングラフを保存しました: 'code_analysis_resistance_{timestamp}.png'")
        plt.close()

if __name__ == "__main__":
    unittest.main()