#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
カプセル構造分析モジュール

カプセル化されたデータの構造を分析し、
特性やパターンに関する詳細な情報を提供します。
"""

import os
import time
import math
import hashlib
import base64
import statistics
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from enum import IntEnum

class AnalysisLevel(IntEnum):
    """分析レベル"""
    BASIC = 0    # 基本情報のみ
    STANDARD = 1 # 標準的な分析
    DETAILED = 2 # 詳細な分析
    ADVANCED = 3 # 高度な分析（計算コスト大）

class AnalysisResult:
    """分析結果クラス"""

    def __init__(self):
        # 基本情報
        self.size = 0                # 合計サイズ（バイト）
        self.timestamp = 0           # 分析時刻
        self.execution_time = 0      # 実行時間（秒）

        # 構造情報
        self.block_size = 0          # 推定ブロックサイズ
        self.block_count = 0         # ブロック数
        self.signature_size = 0      # 署名サイズ

        # バイト分布
        self.byte_distribution = {}  # バイト値ごとの出現頻度
        self.entropy = 0.0           # エントロピー値
        self.entropy_per_block = []  # ブロックごとのエントロピー

        # パターン分析
        self.repeated_patterns = []  # 繰り返しパターン
        self.block_similarity = []   # ブロック間の類似性
        self.structure_type = ""     # 構造タイプ推定

        # 統計情報
        self.mean = 0.0              # 平均値
        self.median = 0.0            # 中央値
        self.std_dev = 0.0           # 標準偏差
        self.correlation = 0.0       # 相関係数

        # 暗号強度評価
        self.resistance_score = 0.0  # 解析耐性スコア
        self.randomness_score = 0.0  # ランダム性スコア

        # 詳細分析結果
        self.detailed_results = {}   # 詳細結果（高度な分析用）

class CapsuleAnalyzer:
    """
    カプセル構造分析クラス

    カプセル化されたデータの構造を分析し、様々な統計情報を提供します。
    データのエントロピー、バイト分布、ブロック構造、パターンなどを
    調査することで、暗号強度の評価や潜在的な脆弱性の特定に役立ちます。
    """

    def __init__(self, analysis_level: AnalysisLevel = AnalysisLevel.STANDARD):
        """
        分析器の初期化

        Args:
            analysis_level: 分析レベル（詳細度と計算コスト）
        """
        self.analysis_level = analysis_level
        self.result = AnalysisResult()

        # 分析パラメータ
        self._param_min_block_size = 16
        self._param_max_block_size = 2048
        self._param_pattern_size_min = 3
        self._param_pattern_size_max = 32
        self._param_sample_size = 16384  # 16KB

        # 内部状態
        self._data = None
        self._blocks = []
        self._sliding_windows = {}

    def analyze(self, data: bytes, key: Optional[bytes] = None,
                metadata: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """
        カプセルデータを分析

        Args:
            data: 分析対象のカプセル化データ
            key: 分析で使用する鍵（オプション）
            metadata: 関連メタデータ（オプション）

        Returns:
            分析結果
        """
        start_time = time.time()
        self.result = AnalysisResult()
        self.result.timestamp = int(start_time)
        self._data = data

        try:
            # 基本情報の収集
            self._analyze_basic_info()

            # メタデータを使用した追加分析
            if metadata:
                self._analyze_with_metadata(metadata)

            # ブロック構造の分析
            self._analyze_block_structure()

            # バイト分布とエントロピーの分析
            self._analyze_byte_distribution()

            # 基本統計の計算
            self._compute_basic_statistics()

            # 標準以上のレベルでの追加分析
            if self.analysis_level >= AnalysisLevel.STANDARD:
                # パターン分析
                self._analyze_patterns()

                # ブロック間の関係性分析
                self._analyze_block_relationships()

            # 詳細分析
            if self.analysis_level >= AnalysisLevel.DETAILED:
                # 周波数領域分析
                self._analyze_frequency_domain()

                # エントロピー詳細分析
                self._detailed_entropy_analysis()

            # 高度な分析
            if self.analysis_level >= AnalysisLevel.ADVANCED and key:
                # 鍵を使用した高度な分析
                self._analyze_with_key(key)

            # 総合評価スコアの計算
            self._compute_resistance_score()

        except Exception as e:
            # エラーが発生しても可能な限り情報を返す
            self.result.detailed_results["error"] = str(e)

        finally:
            # 実行時間の記録
            self.result.execution_time = time.time() - start_time

            # メモリ使用量削減のためのクリーンアップ
            self._cleanup()

        return self.result

    def _analyze_basic_info(self) -> None:
        """基本情報の収集"""
        data = self._data
        self.result.size = len(data)

        # ファイルヘッダーらしき情報の検出
        if len(data) >= 16:
            header = data[:16]
            if b"INDETERM" in header:
                self.result.detailed_results["file_marker"] = "INDETERM"
                self.result.detailed_results["header_detected"] = True

    def _analyze_with_metadata(self, metadata: Dict[str, Any]) -> None:
        """メタデータを使用した追加分析"""
        # メタデータからブロックサイズ情報を取得
        if "block_size" in metadata:
            self.result.block_size = metadata["block_size"]

        # 署名サイズ情報
        if "signature_size" in metadata:
            self.result.signature_size = metadata["signature_size"]

        # その他のメタデータを詳細結果に保存
        for key, value in metadata.items():
            if key not in ("block_size", "signature_size"):
                self.result.detailed_results[f"metadata_{key}"] = value

    def _analyze_block_structure(self) -> None:
        """ブロック構造の分析"""
        data = self._data

        # ブロックサイズの推定（ヒューリスティック）
        # 署名サイズを排除した部分でブロックサイズを推定

        # いくつかの候補サイズでの評価スコアを計算
        block_size_scores = {}

        # 分析するデータサイズを制限（大きなファイルの場合）
        analysis_size = min(len(data), 102400)  # 最大100KB
        analysis_data = data[:analysis_size]

        # 候補ブロックサイズでの評価
        for block_size in range(self._param_min_block_size,
                               min(self._param_max_block_size, analysis_size // 4),
                               8):  # 8バイト単位で増加
            # このブロックサイズでブロックに分割
            blocks = [analysis_data[i:i+block_size]
                     for i in range(0, len(analysis_data), block_size)]

            # 少なくとも3つのブロックが必要
            if len(blocks) < 3:
                continue

            # 隣接ブロック間の差異を計算
            diffs = []
            for i in range(len(blocks) - 1):
                # 最小サイズのブロックに合わせる
                min_size = min(len(blocks[i]), len(blocks[i+1]))

                # ハミング距離（異なるビット数）
                diff = sum(bin(blocks[i][j] ^ blocks[i+1][j]).count('1')
                          for j in range(min_size))
                # ブロックサイズで正規化
                diffs.append(diff / (min_size * 8))

            # 標準偏差を評価スコアとして使用
            # 本当のブロックサイズでは差異の標準偏差が小さくなる傾向
            if diffs:
                std_dev = statistics.stdev(diffs) if len(diffs) > 1 else float('inf')
                block_size_scores[block_size] = std_dev

        # 最も評価の高いブロックサイズを選択
        if block_size_scores:
            best_block_size = min(block_size_scores.items(), key=lambda x: x[1])[0]
            self.result.block_size = best_block_size

            # ブロック数の計算
            self.result.block_count = len(data) // best_block_size

            # ブロックに分割
            self._blocks = [data[i:i+best_block_size]
                           for i in range(0, len(data), best_block_size)]

            # 推定署名サイズ（最初の2ブロックが署名と仮定）
            self.result.signature_size = min(best_block_size * 2, len(data))
        else:
            # 推定失敗時のフォールバック
            self.result.block_size = 64  # デフォルト値
            self.result.block_count = len(data) // 64
            self._blocks = [data[i:i+64] for i in range(0, len(data), 64)]
            self.result.signature_size = 128

    def _analyze_byte_distribution(self) -> None:
        """バイト分布とエントロピーの分析"""
        data = self._data

        # サンプリング（大きなデータの場合）
        if len(data) > self._param_sample_size:
            # 均等にサンプリング
            sample_data = bytes([data[i] for i in range(0, len(data), len(data) // self._param_sample_size)])
            if len(sample_data) > self._param_sample_size:
                sample_data = sample_data[:self._param_sample_size]
        else:
            sample_data = data

        # バイト分布の計算
        byte_counts = {}
        for b in sample_data:
            byte_counts[b] = byte_counts.get(b, 0) + 1

        # 頻度に変換
        total_bytes = len(sample_data)
        self.result.byte_distribution = {b: count / total_bytes for b, count in byte_counts.items()}

        # シャノンエントロピーの計算
        entropy = -sum(freq * math.log2(freq) for freq in self.result.byte_distribution.values())
        self.result.entropy = entropy

        # ブロックごとのエントロピー（最大20ブロックまで）
        if self._blocks:
            blocks_to_analyze = self._blocks[:min(20, len(self._blocks))]
            for block in blocks_to_analyze:
                # ブロックごとのバイト分布
                block_byte_counts = {}
                for b in block:
                    block_byte_counts[b] = block_byte_counts.get(b, 0) + 1

                # ブロックのエントロピー計算
                if block_byte_counts:
                    block_total = len(block)
                    block_freqs = {b: count / block_total for b, count in block_byte_counts.items()}
                    block_entropy = -sum(freq * math.log2(freq) for freq in block_freqs.values())
                    self.result.entropy_per_block.append(block_entropy)

    def _compute_basic_statistics(self) -> None:
        """基本統計の計算"""
        data = self._data

        # サンプリング（大きなデータの場合）
        if len(data) > self._param_sample_size:
            sample_indices = [i for i in range(0, len(data), len(data) // self._param_sample_size)]
            if len(sample_indices) > self._param_sample_size:
                sample_indices = sample_indices[:self._param_sample_size]
            sample_data = [data[i] for i in sample_indices]
        else:
            sample_data = list(data)

        # 基本統計量
        self.result.mean = statistics.mean(sample_data)
        self.result.median = statistics.median(sample_data)

        if len(sample_data) > 1:
            self.result.std_dev = statistics.stdev(sample_data)

        # 隣接バイト間の相関
        if len(sample_data) > 1:
            try:
                # NumPyを使用した効率的な相関計算
                correlations = np.corrcoef(sample_data[:-1], sample_data[1:])
                self.result.correlation = correlations[0, 1]
            except Exception:
                # NumPyが使用できない場合や計算エラー時
                # 簡易相関係数の計算
                x = sample_data[:-1]
                y = sample_data[1:]
                x_mean = statistics.mean(x)
                y_mean = statistics.mean(y)

                numerator = sum((xi - x_mean) * (yi - y_mean) for xi, yi in zip(x, y))
                denominator = (sum((xi - x_mean) ** 2 for xi in x) *
                              sum((yi - y_mean) ** 2 for yi in y)) ** 0.5

                if denominator:
                    self.result.correlation = numerator / denominator
                else:
                    self.result.correlation = 0

    def _analyze_patterns(self) -> None:
        """パターン分析"""
        data = self._data

        # 分析するデータサイズを制限
        analysis_size = min(len(data), 4096)  # 最大4KB
        analysis_data = data[:analysis_size]

        patterns = []

        # 繰り返しパターンの検出
        for pattern_size in range(self._param_pattern_size_min,
                                 min(self._param_pattern_size_max, analysis_size // 4)):
            # スライディングウィンドウでパターンをスキャン
            pattern_counts = {}

            for i in range(0, len(analysis_data) - pattern_size + 1):
                pattern = analysis_data[i:i+pattern_size]
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

            # 複数回出現するパターンのみを記録
            for pattern, count in pattern_counts.items():
                if count > 1:
                    patterns.append((pattern, count, pattern_size))

        # 最も頻度の高いパターンを記録（最大5つ）
        if patterns:
            top_patterns = sorted(patterns, key=lambda x: x[1], reverse=True)[:5]
            self.result.repeated_patterns = [
                {
                    "pattern_hex": pattern.hex(),
                    "count": count,
                    "size": size
                }
                for pattern, count, size in top_patterns
            ]

    def _analyze_block_relationships(self) -> None:
        """ブロック間の関係性分析"""
        if not self._blocks or len(self._blocks) < 2:
            return

        # 分析するブロック数を制限
        blocks_to_analyze = self._blocks[:min(10, len(self._blocks))]

        # ブロック間の類似性を計算
        similarities = []

        for i in range(len(blocks_to_analyze) - 1):
            block1 = blocks_to_analyze[i]
            block2 = blocks_to_analyze[i + 1]

            # 共通部分の長さを計算
            min_len = min(len(block1), len(block2))

            # バイト単位の類似度（一致率）
            byte_matches = sum(1 for j in range(min_len) if block1[j] == block2[j])
            byte_similarity = byte_matches / min_len if min_len > 0 else 0

            # ハミング距離（ビット単位の違い）
            bit_differences = sum(bin(block1[j] ^ block2[j]).count('1') for j in range(min_len))
            bit_similarity = 1 - (bit_differences / (min_len * 8)) if min_len > 0 else 0

            similarities.append({
                "blocks": (i, i+1),
                "byte_similarity": byte_similarity,
                "bit_similarity": bit_similarity
            })

        self.result.block_similarity = similarities

        # 構造タイプの推定
        avg_byte_similarity = statistics.mean([s["byte_similarity"] for s in similarities])
        avg_bit_similarity = statistics.mean([s["bit_similarity"] for s in similarities])

        # 構造タイプの判定ロジック
        if avg_byte_similarity > 0.8:
            self.result.structure_type = "highly_repetitive"
        elif avg_byte_similarity > 0.5:
            self.result.structure_type = "moderately_repetitive"
        elif avg_bit_similarity > 0.8:
            self.result.structure_type = "bit_level_patterns"
        elif self.result.entropy > 7.8:
            self.result.structure_type = "highly_random"
        elif self.result.entropy > 7.0:
            self.result.structure_type = "pseudo_random"
        else:
            self.result.structure_type = "structured_with_patterns"

    def _analyze_frequency_domain(self) -> None:
        """周波数領域での分析"""
        try:
            # サンプリング
            if len(self._data) > self._param_sample_size:
                sample_indices = list(range(0, len(self._data), len(self._data) // self._param_sample_size))
                if len(sample_indices) > self._param_sample_size:
                    sample_indices = sample_indices[:self._param_sample_size]
                sample_data = [self._data[i] for i in sample_indices]
            else:
                sample_data = list(self._data)

            # FFTに必要なサイズ調整（2のべき乗）
            power = 10
            while 2**power < len(sample_data):
                power += 1

            # 2のべき乗にパディング
            padded_data = sample_data + [0] * (2**power - len(sample_data))

            # FFT実行
            fft_result = np.fft.fft(padded_data)
            fft_magnitude = np.abs(fft_result)

            # 低周波成分と高周波成分の比率を計算
            half_point = len(fft_magnitude) // 2
            low_freq_power = np.sum(fft_magnitude[:half_point//4])
            high_freq_power = np.sum(fft_magnitude[half_point - half_point//4:half_point])

            freq_ratio = high_freq_power / low_freq_power if low_freq_power > 0 else float('inf')

            self.result.detailed_results["frequency_analysis"] = {
                "low_freq_power": float(low_freq_power),
                "high_freq_power": float(high_freq_power),
                "freq_ratio": float(freq_ratio)
            }

            # ホワイトノイズ特性の評価
            # ホワイトノイズでは全周波数帯で均等なパワー分布が期待される
            expected_uniform = np.mean(fft_magnitude[:half_point])
            deviation = np.std(fft_magnitude[:half_point]) / expected_uniform if expected_uniform > 0 else float('inf')

            self.result.detailed_results["whiteness_score"] = 1.0 / (1.0 + float(deviation))

        except Exception as e:
            self.result.detailed_results["frequency_analysis_error"] = str(e)

    def _detailed_entropy_analysis(self) -> None:
        """エントロピーの詳細分析"""
        data = self._data

        # 分析するデータサイズを制限
        analysis_size = min(len(data), 16384)  # 最大16KB
        analysis_data = data[:analysis_size]

        # スライディングウィンドウエントロピー
        window_sizes = [16, 32, 64, 128]
        sliding_entropies = {}

        for window_size in window_sizes:
            if len(analysis_data) < window_size:
                continue

            entropies = []

            for i in range(0, len(analysis_data) - window_size + 1, window_size // 2):
                window = analysis_data[i:i+window_size]

                # ウィンドウ内のバイト分布
                window_counts = {}
                for b in window:
                    window_counts[b] = window_counts.get(b, 0) + 1

                # ウィンドウのエントロピー計算
                window_freqs = {b: count / window_size for b, count in window_counts.items()}
                window_entropy = -sum(freq * math.log2(freq) for freq in window_freqs.values())
                entropies.append(window_entropy)

            if entropies:
                sliding_entropies[window_size] = {
                    "mean": statistics.mean(entropies),
                    "min": min(entropies),
                    "max": max(entropies),
                    "std_dev": statistics.stdev(entropies) if len(entropies) > 1 else 0
                }

        self.result.detailed_results["sliding_entropy"] = sliding_entropies

        # ブロック間エントロピー安定性の評価
        if self.result.entropy_per_block and len(self.result.entropy_per_block) > 1:
            entropy_stability = statistics.stdev(self.result.entropy_per_block)
            self.result.detailed_results["entropy_stability"] = entropy_stability

            # 安定性スコア（低いほど安定）
            self.result.detailed_results["entropy_stability_score"] = 1.0 / (1.0 + entropy_stability)

    def _analyze_with_key(self, key: bytes) -> None:
        """鍵を使用した高度な分析"""
        # 鍵依存ハッシュ
        key_hash = hashlib.sha256(key).digest()

        # 鍵から導出したシーケンスとの相関
        derived_sequence = []
        for i in range(min(1024, len(self._data))):
            derived_byte = hashlib.sha256(key_hash + i.to_bytes(4, 'big')).digest()[0]
            derived_sequence.append(derived_byte)

        data_sample = list(self._data[:min(1024, len(self._data))])

        try:
            # 相関係数の計算
            correlation = np.corrcoef(derived_sequence, data_sample)[0, 1]
            self.result.detailed_results["key_correlation"] = float(correlation)
        except Exception:
            # 代替計算方法
            correlation = 0
            self.result.detailed_results["key_correlation"] = correlation

        # 鍵依存の構造分析
        structure_tests = []

        # いくつかの鍵依存オフセットでデータをチェック
        for i in range(4):
            offset = int.from_bytes(key_hash[i*4:(i+1)*4], 'big') % max(1, len(self._data) - 16)
            test_data = self._data[offset:offset+16]

            # このデータと鍵のハッシュを比較
            similarity = sum(1 for a, b in zip(test_data, key_hash) if a == b) / 16
            structure_tests.append(similarity)

        self.result.detailed_results["key_structure_test"] = statistics.mean(structure_tests)

    def _compute_resistance_score(self) -> None:
        """解析耐性スコアの計算"""
        # 各種メトリクスから総合評価スコアを計算

        # エントロピーに基づくスコア（0-10）
        # 理想的なランダムデータでは8に近い値になる
        entropy_score = min(10, self.result.entropy * 10 / 8)

        # 繰り返しパターンの少なさによるスコア
        pattern_count = len(self.result.repeated_patterns)
        pattern_score = 10 - min(10, pattern_count * 2)

        # ブロック間の類似性の低さによるスコア
        if self.result.block_similarity:
            similarity_values = [s["byte_similarity"] for s in self.result.block_similarity]
            avg_similarity = statistics.mean(similarity_values)
            similarity_score = 10 * (1 - avg_similarity)
        else:
            similarity_score = 5  # デフォルト値

        # 相関係数の低さによるスコア
        correlation_score = 10 * (1 - abs(self.result.correlation))

        # 追加スコア（詳細分析が実行されている場合）
        additional_score = 0

        if "whiteness_score" in self.result.detailed_results:
            whiteness_score = self.result.detailed_results["whiteness_score"] * 10
            additional_score += whiteness_score

        if "entropy_stability_score" in self.result.detailed_results:
            stability_score = self.result.detailed_results["entropy_stability_score"] * 10
            additional_score += stability_score

            # 平均で追加スコアを計算
            additional_score /= 2

        # 総合スコアの計算
        weights = {
            "entropy": 0.4,
            "patterns": 0.2,
            "similarity": 0.15,
            "correlation": 0.15,
            "additional": 0.1
        }

        resistance_score = (
            weights["entropy"] * entropy_score +
            weights["patterns"] * pattern_score +
            weights["similarity"] * similarity_score +
            weights["correlation"] * correlation_score +
            weights["additional"] * additional_score
        )

        # ランダム性スコアの計算
        randomness_score = (
            0.5 * entropy_score +
            0.3 * correlation_score +
            0.2 * (10 - abs(self.result.correlation * 10))
        )

        self.result.resistance_score = resistance_score
        self.result.randomness_score = randomness_score

        # スコアの詳細を保存
        self.result.detailed_results["score_components"] = {
            "entropy_score": entropy_score,
            "pattern_score": pattern_score,
            "similarity_score": similarity_score,
            "correlation_score": correlation_score,
            "additional_score": additional_score
        }

    def _cleanup(self) -> None:
        """メモリ使用量削減のためのクリーンアップ"""
        # 巨大なデータ参照を削除
        self._data = None
        self._blocks = []
        self._sliding_windows = {}