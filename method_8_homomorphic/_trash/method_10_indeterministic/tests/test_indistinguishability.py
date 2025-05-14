#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 区別不可能性テスト

暗号化されたデータから真偽が区別できないことを検証します。
"""

import os
import sys
import random
import unittest
import tempfile
import hashlib
import statistics
import time
import matplotlib.pyplot as plt
import numpy as np
from typing import Tuple, Dict, List, Any

# テスト用にモジュールパスを追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.encrypt import encrypt_files, generate_master_key
from method_10_indeterministic.decrypt import decrypt_file, determine_path_type
from method_10_indeterministic.indeterministic import create_indeterministic_capsule
from method_10_indeterministic.state_matrix import generate_state_matrix
from method_10_indeterministic.probability_engine import calculate_probability_distribution
from method_10_indeterministic.config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
    STATE_MATRIX_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION
)

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = "test_output"

class TestIndistinguishability(unittest.TestCase):
    """区別不可能性テスト"""

    @classmethod
    def setUpClass(cls):
        """テスト前の準備"""
        # テスト出力ディレクトリの作成
        os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

        # テスト用ファイルの存在確認
        assert os.path.exists(TRUE_TEXT_PATH), f"真のテキストファイル {TRUE_TEXT_PATH} が見つかりません"
        assert os.path.exists(FALSE_TEXT_PATH), f"偽のテキストファイル {FALSE_TEXT_PATH} が見つかりません"

        # テストファイルの内容を読み込み
        with open(TRUE_TEXT_PATH, 'rb') as f:
            cls.true_content = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            cls.false_content = f.read()

    def setUp(self):
        """各テスト前の準備"""
        # テスト用の出力ファイル名を生成
        self.encrypted_file = os.path.join(TEST_OUTPUT_DIR, f"test_indist_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")

        # 暗号化を実行
        self.keys, _ = encrypt_files(
            TRUE_TEXT_PATH,
            FALSE_TEXT_PATH,
            self.encrypted_file,
            verbose=False
        )

    def test_statistical_indistinguishability(self):
        """統計的区別不可能性をテスト"""
        # 大量の鍵を生成して、復号結果の分布を確認
        num_tests = 100
        true_count = 0
        false_count = 0

        # 各鍵で復号を実行
        for i in range(num_tests):
            key = generate_master_key()
            output_file = os.path.join(TEST_OUTPUT_DIR, f"test_stat_{i}_{os.urandom(4).hex()}.txt")

            # 復号
            decrypt_file(self.encrypted_file, key, output_file)

            # 結果を確認
            with open(output_file, 'rb') as f:
                content = f.read()

            if content == self.true_content:
                true_count += 1
            elif content == self.false_content:
                false_count += 1
            else:
                self.fail(f"復号結果が真または偽のテキストと一致しません: {i}")

        # 結果の表示
        true_percentage = (true_count / num_tests) * 100
        false_percentage = (false_count / num_tests) * 100
        print(f"統計的区別不可能性テスト結果:")
        print(f"  真テキスト復号: {true_count}/{num_tests} ({true_percentage:.1f}%)")
        print(f"  偽テキスト復号: {false_count}/{num_tests} ({false_percentage:.1f}%)")

        # 理想的には真偽の割合が50%ずつに近いことが望ましい
        # 実際のアルゴリズムによって偏りが生じる可能性もあるため、
        # かなり広めの閾値でチェック
        expected_min = 0.2 * num_tests  # 20%
        expected_max = 0.8 * num_tests  # 80%

        # 分布が極端に偏っていないことを確認
        self.assertTrue(expected_min <= true_count <= expected_max,
                       f"真の復号比率が想定範囲外です: {true_percentage:.1f}%")
        self.assertTrue(expected_min <= false_count <= expected_max,
                       f"偽の復号比率が想定範囲外です: {false_percentage:.1f}%")

        # グラフを作成
        self._create_distribution_graph([true_count, false_count], ["True", "False"], "statistical_indistinguishability")

    def test_timing_attack_resistance(self):
        """タイミング攻撃への耐性をテスト"""
        num_tests = 50
        true_timings = []
        false_timings = []
        unknown_timings = []

        # あらかじめ鍵の種類を把握
        known_true_key = self.keys["master_key"]
        known_false_key = generate_master_key()  # ランダムな鍵、確率的に偽になることが多い

        # 既知の鍵の種類を確認
        true_path = determine_path_type(known_true_key)
        false_path = determine_path_type(known_false_key)

        # 偽の鍵が真の鍵と同じパスタイプならば再生成
        if false_path == true_path:
            for _ in range(10):  # 10回まで再試行
                known_false_key = generate_master_key()
                false_path = determine_path_type(known_false_key)
                if false_path != true_path:
                    break

        print(f"真の鍵のパスタイプ: {true_path}")
        print(f"偽の鍵のパスタイプ: {false_path}")

        # 各鍵タイプで複数回復号し、処理時間を測定
        for _ in range(num_tests):
            # 1. 真の鍵での復号時間
            output_file = os.path.join(TEST_OUTPUT_DIR, f"test_timing_true_{os.urandom(4).hex()}.txt")
            start_time = time.time()
            decrypt_file(self.encrypted_file, known_true_key, output_file)
            end_time = time.time()
            true_timings.append(end_time - start_time)

            # 2. 偽の鍵での復号時間
            output_file = os.path.join(TEST_OUTPUT_DIR, f"test_timing_false_{os.urandom(4).hex()}.txt")
            start_time = time.time()
            decrypt_file(self.encrypted_file, known_false_key, output_file)
            end_time = time.time()
            false_timings.append(end_time - start_time)

            # 3. ランダムな未知の鍵での復号時間
            unknown_key = generate_master_key()
            output_file = os.path.join(TEST_OUTPUT_DIR, f"test_timing_unknown_{os.urandom(4).hex()}.txt")
            start_time = time.time()
            decrypt_file(self.encrypted_file, unknown_key, output_file)
            end_time = time.time()
            unknown_timings.append(end_time - start_time)

        # 統計量を計算
        true_mean = statistics.mean(true_timings)
        false_mean = statistics.mean(false_timings)
        unknown_mean = statistics.mean(unknown_timings)

        true_stddev = statistics.stdev(true_timings) if len(true_timings) > 1 else 0
        false_stddev = statistics.stdev(false_timings) if len(false_timings) > 1 else 0
        unknown_stddev = statistics.stdev(unknown_timings) if len(unknown_timings) > 1 else 0

        # 結果を表示
        print(f"タイミング攻撃耐性テスト結果:")
        print(f"  真の鍵による復号: {true_mean:.6f}秒 (標準偏差: {true_stddev:.6f})")
        print(f"  偽の鍵による復号: {false_mean:.6f}秒 (標準偏差: {false_stddev:.6f})")
        print(f"  未知の鍵による復号: {unknown_mean:.6f}秒 (標準偏差: {unknown_stddev:.6f})")

        # 差の計算（絶対値）
        true_false_diff = abs(true_mean - false_mean)
        true_unknown_diff = abs(true_mean - unknown_mean)
        false_unknown_diff = abs(false_mean - unknown_mean)

        # 標準偏差の平均
        avg_stddev = (true_stddev + false_stddev + unknown_stddev) / 3

        # 復号プロセスの時間差が十分に小さいかを検証
        # 標準偏差の3倍以内の差は統計的に区別困難と考える
        max_acceptable_diff = 3 * avg_stddev

        print(f"  平均標準偏差: {avg_stddev:.6f}秒")
        print(f"  真/偽の時間差: {true_false_diff:.6f}秒 (許容範囲: {max_acceptable_diff:.6f}秒)")
        print(f"  真/未知の時間差: {true_unknown_diff:.6f}秒")
        print(f"  偽/未知の時間差: {false_unknown_diff:.6f}秒")

        self.assertTrue(true_false_diff <= max_acceptable_diff,
                       f"真と偽の鍵による復号時間の差が大きすぎます: {true_false_diff:.6f} > {max_acceptable_diff:.6f}")

        # グラフを作成
        self._create_timing_graph(true_timings, false_timings, unknown_timings)

    def test_content_indistinguishability(self):
        """暗号文からの内容区別不可能性をテスト"""
        # 1. オリジナルの暗号文を生成
        original_file = os.path.join(TEST_OUTPUT_DIR, f"test_content_original_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")
        encrypt_files(TRUE_TEXT_PATH, FALSE_TEXT_PATH, original_file)

        # 2. 入れ替えた暗号文を生成（真偽を入れ替え）
        swapped_file = os.path.join(TEST_OUTPUT_DIR, f"test_content_swapped_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")
        encrypt_files(FALSE_TEXT_PATH, TRUE_TEXT_PATH, swapped_file)

        # ファイルサイズを比較
        original_size = os.path.getsize(original_file)
        swapped_size = os.path.getsize(swapped_file)

        # サイズ比較の結果を表示
        print(f"暗号文サイズ比較:")
        print(f"  オリジナル: {original_size} バイト")
        print(f"  入れ替え: {swapped_size} バイト")
        print(f"  差異: {abs(original_size - swapped_size)} バイト")

        # ファイルの内容を読み込み
        with open(original_file, 'rb') as f:
            original_content = f.read()
        with open(swapped_file, 'rb') as f:
            swapped_content = f.read()

        # ハッシュ値を計算して比較
        original_hash = hashlib.sha256(original_content).hexdigest()
        swapped_hash = hashlib.sha256(swapped_content).hexdigest()

        print(f"暗号文ハッシュ:")
        print(f"  オリジナル: {original_hash}")
        print(f"  入れ替え: {swapped_hash}")

        # ファイルの構造を比較
        # ヘッダーが同じか確認
        header_length = 8  # ヘッダーの長さ（例: "INDET01"）
        original_header = original_content[:header_length]
        swapped_header = swapped_content[:header_length]

        self.assertEqual(original_header, swapped_header, "暗号文のヘッダーが異なります")

        # 暗号文に単純なパターンがないことを確認
        # バイナリパターン分析（簡易版）
        self._analyze_binary_patterns(original_content, "オリジナル暗号文")
        self._analyze_binary_patterns(swapped_content, "入れ替え暗号文")

        # バイト分布の類似性を確認
        similarity = self._calculate_byte_distribution_similarity(original_content, swapped_content)
        print(f"バイト分布の類似度: {similarity:.2f}%")

        # 十分な類似性があることを確認（50%以上の類似度）
        self.assertTrue(similarity >= 50.0, f"暗号文のバイト分布の類似度が低すぎます: {similarity:.2f}%")

    def _analyze_binary_patterns(self, data: bytes, label: str) -> None:
        """バイナリデータのパターンを簡易分析"""
        # バイト出現頻度
        byte_counts = {}
        for b in data:
            byte_counts[b] = byte_counts.get(b, 0) + 1

        # 頻度上位10バイト
        top_bytes = sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # エントロピー計算
        total_bytes = len(data)
        entropy = 0
        for _, count in byte_counts.items():
            prob = count / total_bytes
            entropy -= prob * (np.log2(prob) if prob > 0 else 0)

        print(f"{label} 分析:")
        print(f"  サイズ: {total_bytes} バイト")
        print(f"  ユニークバイト数: {len(byte_counts)}")
        print(f"  エントロピー: {entropy:.2f} ビット/バイト")
        print(f"  頻出バイト: {', '.join([f'0x{b:02x}({c})' for b, c in top_bytes[:5]])}")

    def _calculate_byte_distribution_similarity(self, data1: bytes, data2: bytes) -> float:
        """2つのバイナリデータのバイト分布の類似度を計算"""
        # バイト出現頻度
        counts1 = {}
        counts2 = {}

        for b in data1:
            counts1[b] = counts1.get(b, 0) + 1

        for b in data2:
            counts2[b] = counts2.get(b, 0) + 1

        # すべてのユニークバイト
        all_bytes = set(counts1.keys()) | set(counts2.keys())

        # 各バイトの頻度を正規化
        total1 = len(data1)
        total2 = len(data2)

        similarity_sum = 0

        for b in all_bytes:
            freq1 = counts1.get(b, 0) / total1
            freq2 = counts2.get(b, 0) / total2

            # 2つの頻度の小さい方を類似度として加算
            similarity_sum += min(freq1, freq2)

        # 合計類似度（0.0〜1.0）を百分率に変換
        return similarity_sum * 100

    def _create_distribution_graph(self, counts: List[int], labels: List[str], filename_prefix: str) -> None:
        """分布グラフを作成"""
        plt.figure(figsize=(10, 6))
        bars = plt.bar(labels, counts, color=['blue', 'orange'])

        # バーの上に数値を表示
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height}',
                    ha='center', va='bottom')

        plt.title('区別不可能性テスト - 復号結果分布')
        plt.ylabel('復号回数')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # 50%ラインを表示
        total = sum(counts)
        plt.axhline(y=total/2, color='r', linestyle='-', alpha=0.3)
        plt.text(0.5, total/2 + 1, '理想的な50%ライン', color='r', ha='center')

        # グラフを保存
        timestamp = int(time.time())
        graph_path = os.path.join(TEST_OUTPUT_DIR, f"{filename_prefix}_{timestamp}.png")
        plt.savefig(graph_path)
        plt.close()

        print(f"分布グラフを保存しました: {graph_path}")

    def _create_timing_graph(self, true_timings: List[float], false_timings: List[float],
                           unknown_timings: List[float]) -> None:
        """タイミング分析グラフを作成"""
        plt.figure(figsize=(12, 8))

        # 箱ひげ図
        plt.subplot(2, 1, 1)
        plt.boxplot([true_timings, false_timings, unknown_timings],
                  labels=['真の鍵', '偽の鍵', '未知の鍵'])
        plt.title('復号処理時間の箱ひげ図')
        plt.ylabel('処理時間 (秒)')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # ヒストグラム
        plt.subplot(2, 1, 2)
        plt.hist([true_timings, false_timings, unknown_timings],
               bins=20, alpha=0.7, label=['真の鍵', '偽の鍵', '未知の鍵'])
        plt.title('復号処理時間の分布')
        plt.xlabel('処理時間 (秒)')
        plt.ylabel('頻度')
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        plt.tight_layout()

        # グラフを保存
        timestamp = int(time.time())
        graph_path = os.path.join(TEST_OUTPUT_DIR, f"timing_analysis_{timestamp}.png")
        plt.savefig(graph_path)
        plt.close()

        print(f"タイミング分析グラフを保存しました: {graph_path}")

    def tearDown(self):
        """各テスト後のクリーンアップ"""
        # テスト生成ファイルの削除は行わない
        # タイムスタンプ付きでエビデンスとして保存
        pass

if __name__ == "__main__":
    unittest.main()
