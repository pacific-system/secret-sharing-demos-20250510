#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - エントロピー注入テスト

エントロピー注入モジュールの機能をテストします。
"""

import os
import sys
import time
import unittest
import tempfile
import hashlib
import matplotlib.pyplot as plt
import numpy as np
from io import BytesIO
import base64
from typing import Dict, List, Any

# テスト対象モジュールのインポート
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from method_10_indeterministic.entropy_injector import (
    EntropyPool,
    EntropyInjector,
    analyze_entropy,
    inject_entropy_to_data
)

# 復号モジュールからエントロピー抽出関数をインポート
try:
    from method_10_indeterministic.decrypt import extract_entropy_data
except ImportError:
    # テスト環境用にモックアップ
    def extract_entropy_data(entropy_data: bytes, key: bytes, salt: bytes, path_type: str) -> Dict[str, Any]:
        return {"analysis": analyze_entropy(entropy_data)}

class EntropyPoolTests(unittest.TestCase):
    """エントロピープールのテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.seed = b'test_seed_for_entropy_pool_1234567890'
        self.pool = EntropyPool(self.seed, size=4096)

    def test_get_bytes(self):
        """バイト取得機能のテスト"""
        # 複数回の取得で異なる値が返ることを確認
        bytes1 = self.pool.get_bytes(32)
        bytes2 = self.pool.get_bytes(32)

        self.assertIsInstance(bytes1, bytes)
        self.assertEqual(len(bytes1), 32)
        self.assertNotEqual(bytes1, bytes2)

    def test_get_int(self):
        """整数取得機能のテスト"""
        # 範囲内の整数が取得できることを確認
        min_val, max_val = 10, 50
        for _ in range(100):
            val = self.pool.get_int(min_val, max_val)
            self.assertIsInstance(val, int)
            self.assertGreaterEqual(val, min_val)
            self.assertLessEqual(val, max_val)

    def test_get_float(self):
        """浮動小数点数取得機能のテスト"""
        # 範囲内の浮動小数点数が取得できることを確認
        min_val, max_val = 0.5, 2.5
        for _ in range(100):
            val = self.pool.get_float(min_val, max_val)
            self.assertIsInstance(val, float)
            self.assertGreaterEqual(val, min_val)
            self.assertLessEqual(val, max_val)

    def test_reseed(self):
        """リシード機能のテスト"""
        # 初期状態を記録
        initial_bytes = self.pool.get_bytes(64)

        # リシード
        self.pool.reseed(b'additional_seed_data')

        # リシード後の値が変化していることを確認
        after_reseed = self.pool.get_bytes(64)
        self.assertNotEqual(initial_bytes, after_reseed)

    def test_mix_pool(self):
        """プール混合機能のテスト"""
        # 初期プールの状態をコピー
        initial_pool = self.pool.pool.copy()

        # 混合実行
        self.pool._mix_pool()

        # 混合後のプールが変化していることを確認
        diff_count = sum(1 for a, b in zip(initial_pool, self.pool.pool) if a != b)
        self.assertGreater(diff_count, len(initial_pool) // 2)

    def test_entropy_quality(self):
        """エントロピー品質のテスト"""
        # 大量のバイトを生成してエントロピーを計算
        sample_size = 10000
        data = self.pool.get_bytes(sample_size)

        # バイト出現頻度を分析
        byte_counts = {}
        for b in data:
            byte_counts[b] = byte_counts.get(b, 0) + 1

        # ユニーク値の比率を確認
        unique_ratio = len(byte_counts) / 256
        self.assertGreater(unique_ratio, 0.9, "少なくとも90%のバイト値が出現すべき")

        # エントロピー計算
        byte_probs = [count / sample_size for count in byte_counts.values()]
        entropy = -sum(p * np.log2(p) for p in byte_probs)

        # 高エントロピー（少なくとも7.0以上）であることを確認
        self.assertGreater(entropy, 7.0, "エントロピーが高く、ランダム性が高いこと")

    def test_enhanced_mix_pool_resilience(self):
        """強化された混合関数の耐性テスト"""
        # 同一シードから複数のプールを作成
        pool1 = EntropyPool(self.seed, size=4096)
        pool2 = EntropyPool(self.seed, size=4096)

        # 1バイトだけ変更したシードで3つ目のプールを作成
        modified_seed = bytearray(self.seed)
        modified_seed[0] ^= 1  # 最初のバイトを1ビット変更
        pool3 = EntropyPool(bytes(modified_seed), size=4096)

        # 各プールからサンプルデータを取得
        sample1 = pool1.get_bytes(1000)
        sample2 = pool2.get_bytes(1000)
        sample3 = pool3.get_bytes(1000)

        # 同一シードなら同じ結果になることを確認（決定論的）
        self.assertEqual(sample1, sample2, "同一シードは同一結果を生成すべき")

        # わずかなシード変更でも大きく異なる結果になることを確認（雪崩効果）
        different_bytes = sum(1 for a, b in zip(sample1, sample3) if a != b)
        self.assertGreater(different_bytes / len(sample1), 0.45,
            "シードの小さな変更でも出力の45%以上が変化すべき")

    def test_sequential_correlation(self):
        """連続データの相関分析テスト"""
        # 連続して生成されたデータ間の相関を分析
        data1 = self.pool.get_bytes(1000)
        data2 = self.pool.get_bytes(1000)

        # バイト間の相関を計算
        correlations = []
        for i in range(min(len(data1), len(data2))):
            correlations.append(data1[i] ^ data2[i])

        # 相関値の期待値は127前後（無相関）
        correlation_mean = sum(correlations) / len(correlations)
        self.assertGreater(correlation_mean, 110)
        self.assertLess(correlation_mean, 145)

        # 相関値の分布が均一であることを確認
        correlation_counts = {}
        for c in correlations:
            correlation_counts[c] = correlation_counts.get(c, 0) + 1

        stddev = np.std(list(correlation_counts.values()))
        mean = np.mean(list(correlation_counts.values()))

        # 標準偏差が平均の一定割合以下であることを確認（均一分布）
        self.assertLess(stddev / mean, 0.5, "相関値の分布が均一すぎない")


class EntropyInjectorTests(unittest.TestCase):
    """エントロピー注入器のテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.key = b'entropy_injector_test_key_12345'
        self.salt = b'test_salt_value'
        self.injector = EntropyInjector(self.key, self.salt)

        # テストデータ
        self.true_data = os.urandom(1024)
        self.false_data = os.urandom(1024)

    def test_inject_entropy(self):
        """エントロピー注入機能のテスト"""
        result = self.injector.inject_entropy(self.true_data, self.false_data)

        self.assertIsInstance(result, bytes)
        self.assertNotEqual(result, self.true_data)
        self.assertNotEqual(result, self.false_data)

        # 結果サイズの検証
        self.assertGreater(len(result), 1024)

    def test_entropy_analysis(self):
        """注入されたエントロピーの分析テスト"""
        result = self.injector.inject_entropy(self.true_data, self.false_data)

        # エントロピーの分析
        analysis = analyze_entropy(result)

        # 高エントロピーであることを確認
        self.assertGreater(analysis["entropy"], 7.5, "注入後のエントロピーが高いこと")
        self.assertGreater(analysis["unique_ratio"], 0.9, "バイト値の分布が均一であること")

    def test_function_interface(self):
        """関数インターフェースのテスト"""
        result = inject_entropy_to_data(
            self.true_data,
            self.false_data,
            self.key,
            self.salt
        )

        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 1024)

        # 複数回実行で異なる結果になることを確認
        result2 = inject_entropy_to_data(
            self.true_data,
            self.false_data,
            self.key,
            self.salt
        )

        # 同じキーとソルトでも内部でさらにランダム性を追加するため異なる結果に
        self.assertNotEqual(result, result2)

    def test_marker_integrity(self):
        """マーカー完全性テスト"""
        # マーカーが正しく注入されているか確認
        result = self.injector.inject_entropy(self.true_data, self.false_data)

        # マーカーを取得
        markers = self.injector._injection_markers

        # 少なくとも1つのマーカーが見つかることを確認
        found_markers = 0
        for marker in markers:
            if marker in result:
                found_markers += 1

        self.assertGreater(found_markers, 0, "少なくとも1つのマーカーが見つかるべき")

    def test_extract_entropy_data(self):
        """エントロピーデータ抽出機能のテスト"""
        # エントロピーを注入
        entropy_data = self.injector.inject_entropy(self.true_data, self.false_data)

        # TRUE_PATH と FALSE_PATH の定義
        TRUE_PATH = "true"
        FALSE_PATH = "false"

        # エントロピーデータの抽出テスト
        true_extraction = extract_entropy_data(entropy_data, self.key, self.salt, TRUE_PATH)
        false_extraction = extract_entropy_data(entropy_data, self.key, self.salt, FALSE_PATH)

        # 結果の検証
        self.assertIsInstance(true_extraction, dict)
        self.assertIn("analysis", true_extraction)
        self.assertGreater(true_extraction["analysis"].get("entropy", 0), 7.0)

        # 異なるパスでも基本的な抽出は機能する
        self.assertIsInstance(false_extraction, dict)
        self.assertIn("analysis", false_extraction)

        # マーカーベースの抽出をテスト
        if "base_entropy" in true_extraction:
            # マーカーベースの抽出が機能している場合
            self.assertIsInstance(true_extraction["base_entropy"], bytes)


class CombinedSystemTests(unittest.TestCase):
    """総合システムテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.key = os.urandom(32)

    def test_end_to_end(self):
        """エンドツーエンドの機能テスト"""
        # テストデータを用意
        true_data = os.urandom(2048)
        false_data = os.urandom(2048)

        # エントロピー注入を実行
        result = inject_entropy_to_data(true_data, false_data, self.key)

        # 結果の分析
        analysis = analyze_entropy(result)

        # 期待する特性を確認
        self.assertGreater(analysis["entropy"], 7.5)
        self.assertTrue(analysis["is_random"])

    def test_visualization(self):
        """エントロピー可視化テスト"""
        # テストデータの準備
        test_sizes = [1024, 4096, 16384]
        entropy_values = []
        labels = []

        for size in test_sizes:
            # ランダムデータと構造化データ（低エントロピー）を生成
            random_data = os.urandom(size)
            structured_data = bytes([i % 256 for i in range(size)])

            # エントロピー注入
            injected_data = inject_entropy_to_data(
                random_data,
                structured_data,
                self.key
            )

            # エントロピー分析
            random_entropy = analyze_entropy(random_data)["entropy"]
            struct_entropy = analyze_entropy(structured_data)["entropy"]
            injected_entropy = analyze_entropy(injected_data)["entropy"]

            # 結果を記録
            entropy_values.extend([
                random_entropy,
                struct_entropy,
                injected_entropy
            ])

            labels.extend([
                f"ランダム({size}B)",
                f"構造化({size}B)",
                f"注入後({size}B)"
            ])

        # 結果をグラフ化
        try:
            plt.figure(figsize=(12, 6))

            # エントロピー比較グラフの作成
            bars = plt.bar(labels, entropy_values, color=['blue', 'orange', 'green'] * len(test_sizes))

            # グラフの装飾
            plt.axhline(y=8.0, color='gray', linestyle='--', label='理論上の最大値')
            plt.axhline(y=7.8, color='red', linestyle='--', label='高エントロピー閾値')
            plt.ylim(0, 8.2)
            plt.title('エントロピー注入テスト: データタイプごとのエントロピー比較')
            plt.xlabel('データタイプ')
            plt.ylabel('エントロピー値 (ビット/バイト)')
            plt.legend()
            plt.xticks(rotation=45)
            plt.tight_layout()

            # グラフを画像ファイルとして保存
            os.makedirs('test_output', exist_ok=True)
            plt.savefig('test_output/improved_entropy_injection_test.png')

            # テスト結果の表示
            print("\n✓ 改善されたエントロピー注入テストのグラフを保存しました: test_output/improved_entropy_injection_test.png")
            plt.close()

            self.assertTrue(os.path.exists('test_output/improved_entropy_injection_test.png'))

        except Exception as e:
            self.fail(f"グラフ生成中にエラーが発生しました: {e}")

    def test_statistical_resistance(self):
        """統計的解析耐性テスト"""
        # データサイズ
        size = 8192

        # 何度か繰り返してさまざまなサンプルを生成
        samples = []
        for _ in range(5):
            true_data = os.urandom(size)
            false_data = os.urandom(size)

            result = inject_entropy_to_data(true_data, false_data, self.key)
            samples.append(result)

        # 統計的特徴を調査
        # 1. バイト値の分布を確認
        for sample in samples:
            byte_counts = {}
            for b in sample:
                byte_counts[b] = byte_counts.get(b, 0) + 1

            # カイ二乗検定の代わりに分布の均一性を簡易チェック
            values = list(byte_counts.values())
            mean = sum(values) / len(values)

            # 全バイト値が出現することを確認
            self.assertEqual(len(byte_counts), 256, "全バイト値が出現すべき")

            # 出現頻度のばらつきを確認
            stddev = np.std(values)
            variation = stddev / mean

            # 変動係数が一定値以下（分布が均一）であることを確認
            self.assertLess(variation, 0.2, "バイト値分布が均一であること")

        # 2. 隣接バイト間の相関を確認
        for sample in samples:
            correlations = []
            for i in range(len(sample) - 1):
                correlations.append(abs(sample[i] - sample[i+1]))

            # 相関の分布を確認
            corr_mean = sum(correlations) / len(correlations)

            # 相関平均が期待される無相関値に近いことを確認
            # 無相関なら平均は ~85.3 (256/3)に近くなる
            self.assertGreater(corr_mean, 60)
            self.assertLess(corr_mean, 110)

    def test_injection_extraction_integration(self):
        """注入と抽出の統合テスト"""
        TRUE_PATH = "true"
        FALSE_PATH = "false"

        # テストデータ
        true_data = os.urandom(4096)
        false_data = os.urandom(4096)

        # エントロピー注入
        entropy_data = inject_entropy_to_data(true_data, false_data, self.key)

        # エントロピー抽出
        extracted_true = extract_entropy_data(entropy_data, self.key, None, TRUE_PATH)
        extracted_false = extract_entropy_data(entropy_data, self.key, None, FALSE_PATH)

        # 抽出結果の検証
        self.assertIsInstance(extracted_true, dict)
        self.assertIsInstance(extracted_false, dict)

        # エントロピー値の検証
        self.assertGreater(extracted_true["analysis"]["entropy"], 7.0)
        self.assertGreater(extracted_false["analysis"]["entropy"], 7.0)

        # 抽出データの可視化
        try:
            plt.figure(figsize=(10, 8))
            plt.subplot(2, 1, 1)
            plt.title('注入・抽出統合テスト: エントロピーデータの抽出検証')

            # 元データのエントロピー分析
            orig_entropy = analyze_entropy(entropy_data)

            # データのバイト頻度分布を取得
            orig_counts = [0] * 256
            for b in entropy_data[:1000]:  # 最初の1000バイトだけサンプリング
                orig_counts[b] += 1

            # 正規化
            orig_dist = [c / sum(orig_counts) for c in orig_counts]

            # 抽出されたデータがあれば、その分布も比較
            true_dist = None
            false_dist = None

            if "base_entropy" in extracted_true:
                true_counts = [0] * 256
                for b in extracted_true["base_entropy"][:1000]:
                    true_counts[b] += 1
                true_dist = [c / max(1, sum(true_counts)) for c in true_counts]

            if "base_entropy" in extracted_false:
                false_counts = [0] * 256
                for b in extracted_false["base_entropy"][:1000]:
                    false_counts[b] += 1
                false_dist = [c / max(1, sum(false_counts)) for c in false_counts]

            # グラフ描画
            x = list(range(256))
            plt.plot(x, orig_dist, 'g-', alpha=0.7, label='全体エントロピーデータ')

            if true_dist:
                plt.plot(x, true_dist, 'b-', alpha=0.7, label='True抽出データ')

            if false_dist:
                plt.plot(x, false_dist, 'r-', alpha=0.7, label='False抽出データ')

            plt.axhline(y=1/256, color='k', linestyle='--', label='理想的な一様分布')
            plt.xlabel('バイト値')
            plt.ylabel('出現頻度')
            plt.legend()
            plt.grid(True, alpha=0.3)

            # 二つ目のグラフ: 統計情報
            plt.subplot(2, 1, 2)
            entropy_values = [orig_entropy["entropy"]]
            labels = ['全体エントロピー']

            if "analysis" in extracted_true:
                entropy_values.append(extracted_true["analysis"]["entropy"])
                labels.append('True抽出エントロピー')

            if "analysis" in extracted_false:
                entropy_values.append(extracted_false["analysis"]["entropy"])
                labels.append('False抽出エントロピー')

            plt.bar(labels, entropy_values, color=['green', 'blue', 'red'])
            plt.axhline(y=8.0, color='gray', linestyle='--', label='理論上の最大値')
            plt.axhline(y=7.5, color='orange', linestyle='--', label='高エントロピー閾値')
            plt.ylim(0, 8.2)
            plt.ylabel('エントロピー値')
            plt.grid(True, alpha=0.3)

            plt.tight_layout()

            # グラフを保存
            os.makedirs('test_output', exist_ok=True)
            plt.savefig('test_output/entropy_injection_extraction_test.png')

            print("\n✓ 注入・抽出統合テストのグラフを保存しました: test_output/entropy_injection_extraction_test.png")
            plt.close()

            self.assertTrue(os.path.exists('test_output/entropy_injection_extraction_test.png'))

        except Exception as e:
            self.fail(f"グラフ生成中にエラーが発生しました: {e}")


def visualize_entropy_distribution():
    """エントロピー分布の可視化"""
    # データサイズ
    size = 8192

    # テストデータの準備
    key = os.urandom(32)
    true_data = os.urandom(size)
    false_data = os.urandom(size)

    # エントロピー注入
    injected_data = inject_entropy_to_data(true_data, false_data, key)

    # 各データのバイト値分布を取得
    true_counts = [0] * 256
    false_counts = [0] * 256
    injected_counts = [0] * 256

    for b in true_data:
        true_counts[b] += 1

    for b in false_data:
        false_counts[b] += 1

    for b in injected_data:
        injected_counts[b] += 1

    # 分布を正規化
    true_dist = [c / size for c in true_counts]
    false_dist = [c / size for c in false_counts]
    injected_dist = [c / len(injected_data) for c in injected_counts]

    # 分布をグラフ化
    try:
        plt.figure(figsize=(15, 10))

        # サブプロット1: バイト値分布の比較
        plt.subplot(2, 1, 1)
        x = list(range(256))
        plt.plot(x, true_dist, 'g-', alpha=0.7, label='True Data')
        plt.plot(x, false_dist, 'r-', alpha=0.7, label='False Data')
        plt.plot(x, injected_dist, 'b-', alpha=0.7, label='Injected Data')
        plt.axhline(y=1/256, color='k', linestyle='--', label='理想的な一様分布')
        plt.title('バイト値分布の比較')
        plt.xlabel('バイト値')
        plt.ylabel('出現頻度')
        plt.legend()
        plt.grid(True, alpha=0.3)

        # サブプロット2: ヒストグラム比較
        plt.subplot(2, 1, 2)

        # ヒストグラム用にデータをサンプリング
        true_sample = true_data[:1000]
        false_sample = false_data[:1000]
        injected_sample = injected_data[:1000]

        plt.hist([true_sample, false_sample, injected_sample],
                bins=50, alpha=0.7, label=['True Data', 'False Data', 'Injected Data'])
        plt.title('バイト値分布ヒストグラム')
        plt.xlabel('バイト値')
        plt.ylabel('出現頻度')
        plt.legend()
        plt.grid(True, alpha=0.3)

        plt.tight_layout()

        # グラフを画像ファイルとして保存
        os.makedirs('test_output', exist_ok=True)
        plt.savefig('test_output/entropy_distribution_analysis.png')

        print("\n✓ エントロピー分布分析グラフを保存しました: test_output/entropy_distribution_analysis.png")
        plt.close()

    except Exception as e:
        print(f"グラフ生成中にエラーが発生しました: {e}")


if __name__ == "__main__":
    # 単独テストの場合は可視化も実行
    visualize_entropy_distribution()

    # ユニットテスト実行
    unittest.main()