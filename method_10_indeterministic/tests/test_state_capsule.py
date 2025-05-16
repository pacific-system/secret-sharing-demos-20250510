#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
StateCapsuleの単体テスト

カプセル化、解析、抽出の一連のプロセスをテストします。
"""

import os
import sys
import unittest
import hashlib
import tempfile
import random
import time
import matplotlib.pyplot as plt
import numpy as np
from typing import Tuple, List, Dict, Any, Optional
from collections import Counter

# 親ディレクトリをパスに追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# テスト対象のモジュールをインポート
from state_capsule import StateCapsule, AnalysisResistanceLevel
from capsule_analyzer import CapsuleAnalyzer, AnalysisLevel

# 出力ディレクトリの設定
TEST_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "test_output")
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)


class TestStateCapsule(unittest.TestCase):
    """StateCapsuleのテストケース"""

    def setUp(self):
        """テスト前の準備"""
        # テスト用の鍵とソルト
        self.key = os.urandom(32)
        self.salt = os.urandom(16)

        # テスト用データ（サイズ違い）
        self.small_data = os.urandom(1024)  # 1KB
        self.medium_data = os.urandom(64 * 1024)  # 64KB
        self.large_data = os.urandom(1024 * 1024)  # 1MB

        # テスト用のファイルパス
        self.test_files = []

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # テスト用ファイルの削除
        for file_path in self.test_files:
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    print(f"警告: テストファイル '{file_path}' の削除に失敗しました: {e}", file=sys.stderr)

    def test_basic_capsule_operations(self):
        """基本的なカプセル化・抽出操作のテスト"""
        # StateCapsuleの初期化
        capsule = StateCapsule(self.key, self.salt)

        # テスト用のデータとシグネチャ
        true_data = b"This is true data for testing"
        false_data = b"This is false data for testing"
        true_signature = hashlib.sha256(true_data).digest()
        false_signature = hashlib.sha256(false_data).digest()

        # カプセル化
        capsule_data = capsule.create_capsule(true_data, false_data, true_signature, false_signature)

        # データが実際にカプセル化されていることを確認
        self.assertIsNotNone(capsule_data)
        self.assertTrue(len(capsule_data) > 0)

        # 正規パスからデータを抽出
        extracted_true_data, extracted_true_signature = capsule.extract_data(capsule_data, True)

        # 非正規パスからデータを抽出
        extracted_false_data, extracted_false_signature = capsule.extract_data(capsule_data, False)

        # 抽出データを検証
        self.assertEqual(true_data, extracted_true_data)
        self.assertEqual(false_data, extracted_false_data)
        self.assertEqual(true_signature, extracted_true_signature)
        self.assertEqual(false_signature, extracted_false_signature)

    def test_interleave_capsule(self):
        """インターリーブモードでのカプセル化のテスト"""
        # 高解析耐性レベルでStateCapsuleを初期化
        capsule = StateCapsule(self.key, self.salt, resistance_level=AnalysisResistanceLevel.HIGH)

        # テスト用のデータとシグネチャ
        true_data = b"Interleaved true data for testing"
        false_data = b"Interleaved false data for testing"
        true_signature = hashlib.sha256(true_data).digest()
        false_signature = hashlib.sha256(false_data).digest()

        # カプセル化
        capsule_data = capsule.create_capsule(true_data, false_data, true_signature, false_signature)

        # データが実際にカプセル化されていることを確認
        self.assertIsNotNone(capsule_data)
        self.assertTrue(len(capsule_data) > 0)

        # 正規パスからデータを抽出
        extracted_true_data, extracted_true_signature = capsule.extract_data(capsule_data, True)

        # 非正規パスからデータを抽出
        extracted_false_data, extracted_false_signature = capsule.extract_data(capsule_data, False)

        # 抽出データを検証
        self.assertEqual(true_data, extracted_true_data)
        self.assertEqual(false_data, extracted_false_data)
        self.assertEqual(true_signature, extracted_true_signature)
        self.assertEqual(false_signature, extracted_false_signature)

    def test_sequential_capsule(self):
        """シーケンシャルモードでのカプセル化のテスト"""
        # 低解析耐性レベルでStateCapsuleを初期化
        capsule = StateCapsule(self.key, self.salt, resistance_level=AnalysisResistanceLevel.LOW)

        # テスト用のデータとシグネチャ
        true_data = b"Sequential true data for testing"
        false_data = b"Sequential false data for testing"
        true_signature = hashlib.sha256(true_data).digest()
        false_signature = hashlib.sha256(false_data).digest()

        # カプセル化
        capsule_data = capsule.create_capsule(true_data, false_data, true_signature, false_signature)

        # データが実際にカプセル化されていることを確認
        self.assertIsNotNone(capsule_data)
        self.assertTrue(len(capsule_data) > 0)

        # 正規パスからデータを抽出
        extracted_true_data, extracted_true_signature = capsule.extract_data(capsule_data, True)

        # 非正規パスからデータを抽出
        extracted_false_data, extracted_false_signature = capsule.extract_data(capsule_data, False)

        # 抽出データを検証
        self.assertEqual(true_data, extracted_true_data)
        self.assertEqual(false_data, extracted_false_data)
        self.assertEqual(true_signature, extracted_true_signature)
        self.assertEqual(false_signature, extracted_false_signature)

    def test_large_data_capsule(self):
        """大きなデータのカプセル化テスト"""
        # StateCapsuleの初期化
        capsule = StateCapsule(self.key, self.salt)

        # 大きなデータを作成
        true_data = self.medium_data
        false_data = self.medium_data[::-1]  # 反転したデータ
        true_signature = hashlib.sha256(true_data).digest()
        false_signature = hashlib.sha256(false_data).digest()

        # カプセル化
        capsule_data = capsule.create_capsule(true_data, false_data, true_signature, false_signature)

        # データが実際にカプセル化されていることを確認
        self.assertIsNotNone(capsule_data)
        self.assertTrue(len(capsule_data) > 0)

        # 正規パスからデータを抽出
        extracted_true_data, extracted_true_signature = capsule.extract_data(capsule_data, True)

        # 非正規パスからデータを抽出
        extracted_false_data, extracted_false_signature = capsule.extract_data(capsule_data, False)

        # 抽出データを検証
        self.assertEqual(true_data, extracted_true_data)
        self.assertEqual(false_data, extracted_false_data)
        self.assertEqual(true_signature, extracted_true_signature)
        self.assertEqual(false_signature, extracted_false_signature)

    def test_shuffle_effectiveness(self):
        """シャッフル機能の有効性テスト"""
        # StateCapsuleの初期化
        capsule = StateCapsule(self.key, self.salt)

        # テスト用のデータとシグネチャ
        true_data = bytes([i % 256 for i in range(1024)])  # パターン化されたデータ
        false_data = bytes([(255 - i) % 256 for i in range(1024)])  # 反転パターン
        true_signature = hashlib.sha256(true_data).digest()
        false_signature = hashlib.sha256(false_data).digest()

        # カプセル化
        capsule_data = capsule.create_capsule(true_data, false_data, true_signature, false_signature)

        # カプセル化データのバイト分布を分析
        byte_counts = Counter(capsule_data)

        # シャッフル前後のバイト値の分布を比較（可視化）
        input_bytes = list(true_data) + list(false_data)
        input_byte_counts = Counter(input_bytes)
        output_byte_counts = Counter(capsule_data)

        # 結果を可視化
        plt.figure(figsize=(15, 10))

        # 入力データのバイト分布
        plt.subplot(2, 1, 1)
        input_x = list(input_byte_counts.keys())
        input_y = list(input_byte_counts.values())
        plt.bar(input_x, input_y, color='blue', alpha=0.7)
        plt.title('入力データのバイト分布')
        plt.xlabel('バイト値')
        plt.ylabel('頻度')

        # 出力（カプセル化）データのバイト分布
        plt.subplot(2, 1, 2)
        output_x = list(output_byte_counts.keys())
        output_y = list(output_byte_counts.values())
        plt.bar(output_x, output_y, color='red', alpha=0.7)
        plt.title('カプセル化データのバイト分布')
        plt.xlabel('バイト値')
        plt.ylabel('頻度')

        # グラフの保存
        timestamp = int(time.time())
        output_file = os.path.join(TEST_OUTPUT_DIR, f"capsule_shuffle_effectiveness_{timestamp}.png")
        plt.tight_layout()
        plt.savefig(output_file)

        # テスト用ファイルを記録
        self.test_files.append(output_file)

        # シャッフルの有効性を評価
        # 1. 均一分布への近さ
        expected_freq = len(capsule_data) / 256
        variance = sum((output_byte_counts[i] - expected_freq) ** 2 for i in range(256)) / 256
        normalized_variance = variance / expected_freq if expected_freq > 0 else float('inf')

        # 2. オートコリレーション（自己相関）の低さ
        autocorr = []
        for lag in range(1, min(100, len(capsule_data) // 10)):
            series1 = capsule_data[:-lag]
            series2 = capsule_data[lag:]
            corr = sum(a == b for a, b in zip(series1, series2)) / len(series1)
            autocorr.append(corr)

        avg_autocorr = sum(autocorr) / len(autocorr) if autocorr else 0

        # 結果のアサーション
        # 完全な均一分布は難しいが、ある程度の均一性を期待
        self.assertLess(normalized_variance, 0.5, "シャッフル後のバイト分布の分散が大きすぎます")

        # 自己相関は低いはず（ランダムに近いデータ）
        self.assertLess(avg_autocorr, 0.3, "シャッフル後のデータの自己相関が高すぎます")

    def test_capsule_analyzer_integration(self):
        """CapsuleAnalyzerとの統合テスト"""
        # StateCapsuleの初期化
        capsule = StateCapsule(self.key, self.salt, resistance_level=AnalysisResistanceLevel.HIGH)

        # テスト用のデータとシグネチャ
        true_data = os.urandom(10240)  # 10KB
        false_data = os.urandom(10240)  # 10KB
        true_signature = hashlib.sha256(true_data).digest()
        false_signature = hashlib.sha256(false_data).digest()

        # カプセル化
        capsule_data = capsule.create_capsule(true_data, false_data, true_signature, false_signature)

        # CapsuleAnalyzerで分析
        analyzer = CapsuleAnalyzer(analysis_level=AnalysisLevel.DETAILED)
        analysis_result = analyzer.analyze(capsule_data, self.key)

        # 分析結果の確認
        self.assertIsNotNone(analysis_result)
        self.assertTrue(hasattr(analysis_result, 'entropy'))
        self.assertTrue(hasattr(analysis_result, 'resistance_score'))

        # エントロピーが高いことを確認（ランダム性が高い）
        self.assertGreater(analysis_result.entropy, 7.0, "カプセル化データのエントロピーが低すぎます")

        # 解析耐性スコアが高いことを確認
        self.assertGreater(analysis_result.resistance_score, 7.0, "カプセル化データの解析耐性スコアが低すぎます")

        # 分析結果の可視化
        plt.figure(figsize=(15, 15))

        # エントロピーの可視化
        plt.subplot(3, 1, 1)
        if analysis_result.entropy_per_block:
            block_indices = list(range(len(analysis_result.entropy_per_block)))
            plt.plot(block_indices, analysis_result.entropy_per_block, 'r-', linewidth=2)
            plt.axhline(y=analysis_result.entropy, color='b', linestyle='--', label=f'全体エントロピー: {analysis_result.entropy:.2f}')
            plt.title('ブロックごとのエントロピー')
            plt.xlabel('ブロックインデックス')
            plt.ylabel('エントロピー値')
            plt.legend()

        # バイト分布の可視化
        plt.subplot(3, 1, 2)
        byte_values = sorted(analysis_result.byte_distribution.keys())
        frequencies = [analysis_result.byte_distribution[b] for b in byte_values]
        plt.bar(byte_values, frequencies, color='green', alpha=0.7)
        plt.title('バイト値の分布')
        plt.xlabel('バイト値')
        plt.ylabel('相対頻度')

        # 解析耐性スコアとランダム性スコアの可視化
        plt.subplot(3, 1, 3)
        scores = ['解析耐性', 'ランダム性']
        values = [analysis_result.resistance_score, analysis_result.randomness_score]
        plt.bar(scores, values, color=['blue', 'orange'])
        plt.title('セキュリティスコア')
        plt.ylabel('スコア（0-10）')
        plt.ylim([0, 10])

        for i, v in enumerate(values):
            plt.text(i, v + 0.1, f"{v:.2f}", ha='center')

        # グラフの保存
        timestamp = int(time.time())
        output_file = os.path.join(TEST_OUTPUT_DIR, f"capsule_analysis_results_{timestamp}.png")
        plt.tight_layout()
        plt.savefig(output_file)

        # テスト用ファイルを記録
        self.test_files.append(output_file)

        # カプセルから正しくデータが抽出できることを確認
        extracted_true_data, extracted_true_signature = capsule.extract_data(capsule_data, True)
        extracted_false_data, extracted_false_signature = capsule.extract_data(capsule_data, False)

        # 抽出データを検証
        self.assertEqual(true_data, extracted_true_data)
        self.assertEqual(false_data, extracted_false_data)
        self.assertEqual(true_signature, extracted_true_signature)
        self.assertEqual(false_signature, extracted_false_signature)

    def test_block_processing_types(self):
        """様々なブロック処理タイプのテスト"""
        # 異なる解析耐性レベルでStateCapsuleを初期化
        low_capsule = StateCapsule(self.key, self.salt, resistance_level=AnalysisResistanceLevel.LOW)
        medium_capsule = StateCapsule(self.key, self.salt, resistance_level=AnalysisResistanceLevel.MEDIUM)
        high_capsule = StateCapsule(self.key, self.salt, resistance_level=AnalysisResistanceLevel.HIGH)

        # テスト用のデータとシグネチャ
        true_data = bytes([i % 256 for i in range(2048)])  # パターン化されたデータ
        false_data = bytes([(255 - i) % 256 for i in range(2048)])  # 反転パターン
        true_signature = hashlib.sha256(true_data).digest()
        false_signature = hashlib.sha256(false_data).digest()

        # 各レベルでカプセル化
        low_capsule_data = low_capsule.create_capsule(true_data, false_data, true_signature, false_signature)
        medium_capsule_data = medium_capsule.create_capsule(true_data, false_data, true_signature, false_signature)
        high_capsule_data = high_capsule.create_capsule(true_data, false_data, true_signature, false_signature)

        # 各カプセルデータを分析
        analyzer = CapsuleAnalyzer(analysis_level=AnalysisLevel.STANDARD)
        low_result = analyzer.analyze(low_capsule_data)
        medium_result = analyzer.analyze(medium_capsule_data)
        high_result = analyzer.analyze(high_capsule_data)

        # 結果の可視化
        plt.figure(figsize=(15, 12))

        # エントロピー比較
        plt.subplot(2, 2, 1)
        resistance_levels = ['LOW', 'MEDIUM', 'HIGH']
        entropy_values = [low_result.entropy, medium_result.entropy, high_result.entropy]
        plt.bar(resistance_levels, entropy_values, color=['lightblue', 'blue', 'darkblue'])
        plt.title('解析耐性レベルごとのエントロピー')
        plt.ylabel('エントロピー値')

        for i, v in enumerate(entropy_values):
            plt.text(i, v + 0.1, f"{v:.2f}", ha='center')

        # 解析耐性スコア比較
        plt.subplot(2, 2, 2)
        resistance_scores = [low_result.resistance_score, medium_result.resistance_score, high_result.resistance_score]
        plt.bar(resistance_levels, resistance_scores, color=['lightgreen', 'green', 'darkgreen'])
        plt.title('解析耐性レベルごとの耐性スコア')
        plt.ylabel('耐性スコア（0-10）')
        plt.ylim([0, 10])

        for i, v in enumerate(resistance_scores):
            plt.text(i, v + 0.1, f"{v:.2f}", ha='center')

        # バイト分布のKL Divergence（理想的な均一分布からの距離）
        plt.subplot(2, 2, 3)

        def kl_divergence(actual_dist, uniform_dist=None):
            """KLダイバージェンス（情報理論的な距離）の計算"""
            if uniform_dist is None:
                # 均一分布（理想的なランダム分布）
                uniform_dist = {b: 1/256 for b in range(256)}

            # 実際の分布にすべてのバイト値が含まれているか確認
            for b in range(256):
                if b not in actual_dist:
                    actual_dist[b] = 0

            # KLダイバージェンスの計算
            return sum(actual_dist[b] * np.log2(actual_dist[b] / uniform_dist[b])
                      for b in range(256) if actual_dist[b] > 0)

        # 均一分布
        uniform_dist = {b: 1/256 for b in range(256)}

        # KLダイバージェンス計算
        kl_values = []

        # 完全な分布を用意（欠落値を0で補完）
        for result in [low_result, medium_result, high_result]:
            full_dist = {b: result.byte_distribution.get(b, 0) for b in range(256)}
            kl = kl_divergence(full_dist, uniform_dist)
            kl_values.append(kl)

        plt.bar(resistance_levels, kl_values, color=['salmon', 'red', 'darkred'])
        plt.title('均一分布からの距離（KLダイバージェンス）')
        plt.ylabel('KL距離（小さいほど良い）')

        for i, v in enumerate(kl_values):
            plt.text(i, v + 0.01, f"{v:.4f}", ha='center')

        # 検出されたパターン数の比較
        plt.subplot(2, 2, 4)
        pattern_counts = [len(low_result.repeated_patterns),
                          len(medium_result.repeated_patterns),
                          len(high_result.repeated_patterns)]
        plt.bar(resistance_levels, pattern_counts, color=['plum', 'purple', 'indigo'])
        plt.title('検出されたパターン数')
        plt.ylabel('パターン数（少ないほど良い）')

        for i, v in enumerate(pattern_counts):
            plt.text(i, v + 0.1, f"{v}", ha='center')

        # グラフの保存
        timestamp = int(time.time())
        output_file = os.path.join(TEST_OUTPUT_DIR, f"capsule_resistance_levels_{timestamp}.png")
        plt.tight_layout()
        plt.savefig(output_file)

        # テスト用ファイルを記録
        self.test_files.append(output_file)

        # 各カプセルからデータが正しく抽出できることを確認
        for level_name, capsule_obj, capsule_data in [
            ("LOW", low_capsule, low_capsule_data),
            ("MEDIUM", medium_capsule, medium_capsule_data),
            ("HIGH", high_capsule, high_capsule_data)
        ]:
            # 正規パスからデータを抽出
            extracted_true_data, extracted_true_signature = capsule_obj.extract_data(capsule_data, True)

            # 非正規パスからデータを抽出
            extracted_false_data, extracted_false_signature = capsule_obj.extract_data(capsule_data, False)

            # 抽出データを検証
            self.assertEqual(true_data, extracted_true_data,
                             f"{level_name}レベルでの正規データ抽出に失敗")
            self.assertEqual(false_data, extracted_false_data,
                             f"{level_name}レベルでの非正規データ抽出に失敗")
            self.assertEqual(true_signature, extracted_true_signature,
                             f"{level_name}レベルでの正規署名抽出に失敗")
            self.assertEqual(false_signature, extracted_false_signature,
                             f"{level_name}レベルでの非正規署名抽出に失敗")

        # HIGH レベルの耐性が最も高いことを確認
        self.assertGreater(high_result.resistance_score, medium_result.resistance_score,
                          "HIGHレベルの耐性スコアがMEDIUMレベルよりも低い")
        self.assertGreater(medium_result.resistance_score, low_result.resistance_score,
                          "MEDIUMレベルの耐性スコアがLOWレベルよりも低い")


if __name__ == "__main__":
    unittest.main()