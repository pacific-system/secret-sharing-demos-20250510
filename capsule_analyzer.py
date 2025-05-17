"""
不確定性転写暗号化方式 - カプセル構造分析モジュール (CapsuleAnalyzer)

このモジュールは、カプセル化されたデータの構造を分析し、
解析耐性を評価するためのツールを提供します。
"""

import os
import sys
import hashlib
import hmac
import random
import struct
import math
import logging
import numpy as np
from collections import Counter
from typing import Tuple, List, Dict, Any, Optional, Union

# ブロック処理タイプの定義（StateCapsuleと整合させる必要がある）
BLOCK_TYPE_SEQUENTIAL = 1  # 順次配置
BLOCK_TYPE_INTERLEAVE = 2  # インターリーブ配置

# シグネチャ関連の定数
SIGNATURE_SIZE = 32  # HMAC-SHA256のサイズ

# ヘッダーサイズの定数（StateCapsuleと同期必要）
CAPSULE_MARKER = b'\xCA\xB0\x0D\xCA'
HEADER_SIZE = len(CAPSULE_MARKER) + 4 + 4 + 4 + 4 + SIGNATURE_SIZE

# ロガーの設定
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.WARNING)


class CapsuleAnalyzer:
    """
    カプセル構造を分析するためのクラス。

    エントロピー計算、バイト分布分析、ブロック間類似性などの
    解析機能を提供します。
    """

    def __init__(self) -> None:
        """初期化メソッド"""
        self.analysis_results = {}
        self.entropy_block_size = 16  # デフォルト値（解析時に更新される）

    def analyze_capsule(self, capsule: bytes) -> Dict[str, Any]:
        """
        カプセルの構造を分析する

        Args:
            capsule: 分析対象のカプセル

        Returns:
            Dict[str, Any]: 分析結果
        """
        # ヘッダーの解析
        header_valid, header_data = self._parse_header(capsule)
        if not header_valid:
            logger.error("カプセルヘッダーが無効です")
            return {"error": "無効なカプセルヘッダー"}

        # ヘッダー情報の取得
        version = header_data['version']
        block_type = header_data['block_type']
        self.entropy_block_size = header_data['entropy_block_size']
        flags = header_data['flags']
        signature = header_data['signature']

        # カプセルデータの取得
        capsule_data = capsule[HEADER_SIZE:]

        # 署名の検証
        signature_valid = False
        try:
            # ここでは検証のためだけに署名をチェックする
            # 厳密な検証はStateCapsuleの役割
            signature_valid = len(signature) == SIGNATURE_SIZE
        except Exception as e:
            logger.warning(f"署名の検証に失敗しました: {e}")

        # 各種分析の実行
        entropy_analysis = self._analyze_entropy(capsule_data)
        byte_distribution = self._analyze_byte_distribution(capsule_data)
        block_analysis = self._analyze_block_structure(capsule_data, block_type)
        resistance_score = self._calculate_resistance_score(
            entropy_analysis, byte_distribution, block_analysis
        )

        # 分析結果のまとめ
        analysis_results = {
            "header": {
                "valid": header_valid,
                "version": version,
                "block_type": block_type,
                "entropy_block_size": self.entropy_block_size,
                "flags": flags,
                "signature_valid": signature_valid
            },
            "entropy_analysis": entropy_analysis,
            "byte_distribution": byte_distribution,
            "block_analysis": block_analysis,
            "resistance_score": resistance_score
        }

        self.analysis_results = analysis_results
        return analysis_results

    def get_resistance_level(self) -> str:
        """
        解析耐性レベルを文字列で取得する

        Returns:
            str: 解析耐性レベル（低/中/高）
        """
        if not self.analysis_results or "resistance_score" not in self.analysis_results:
            return "不明"

        score = self.analysis_results["resistance_score"]["total"]
        if score >= 8.0:
            return "高"
        elif score >= 5.0:
            return "中"
        else:
            return "低"

    def _parse_header(self, capsule: bytes) -> Tuple[bool, Dict[str, Any]]:
        """
        カプセルのヘッダーを解析する

        Args:
            capsule: 分析対象のカプセル

        Returns:
            Tuple[bool, Dict]: (ヘッダーが有効か, ヘッダー情報)
        """
        if len(capsule) < HEADER_SIZE:
            return False, {}

        try:
            # ヘッダーデータの取得
            marker = capsule[0:4]
            version = struct.unpack("<I", capsule[4:8])[0]
            block_type = struct.unpack("<I", capsule[8:12])[0]
            entropy_block_size = struct.unpack("<I", capsule[12:16])[0]
            flags = struct.unpack("<I", capsule[16:20])[0]
            signature = capsule[20:52]  # SIGNATURE_SIZE = 32

            # マーカーの検証
            if marker != CAPSULE_MARKER:
                return False, {}

            # ヘッダー情報の返却
            header_data = {
                'marker': marker,
                'version': version,
                'block_type': block_type,
                'entropy_block_size': entropy_block_size,
                'flags': flags,
                'signature': signature
            }

            return True, header_data
        except Exception as e:
            logger.error(f"ヘッダー解析エラー: {e}")
            return False, {}

    def _analyze_entropy(self, data: bytes) -> Dict[str, Any]:
        """
        データのエントロピーを分析する

        Args:
            data: 分析対象のデータ

        Returns:
            Dict[str, Any]: エントロピー分析結果
        """
        if not data:
            return {
                "shannon_entropy": 0,
                "normalized_entropy": 0,
                "entropy_per_block": [],
                "entropy_uniformity": 0
            }

        # 全体のエントロピー計算
        shannon_entropy = self._calculate_shannon_entropy(data)
        normalized_entropy = shannon_entropy / 8.0  # 8ビット（1バイト）に対する正規化

        # ブロックごとのエントロピー計算
        block_size = self.entropy_block_size
        entropy_per_block = []

        for i in range(0, len(data), block_size):
            end = min(i + block_size, len(data))
            block = data[i:end]
            if len(block) >= 4:  # 最低限の解析可能サイズ
                block_entropy = self._calculate_shannon_entropy(block)
                entropy_per_block.append(block_entropy / 8.0)

        # エントロピー分布の均一性（標準偏差の逆数で表現）
        entropy_uniformity = 0
        if entropy_per_block:
            std_dev = np.std(entropy_per_block) if len(entropy_per_block) > 1 else 0
            entropy_uniformity = 1.0 / (1.0 + std_dev)  # 標準偏差が小さいほど均一

        return {
            "shannon_entropy": shannon_entropy,
            "normalized_entropy": normalized_entropy,
            "entropy_per_block": entropy_per_block,
            "entropy_uniformity": entropy_uniformity
        }

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """
        シャノンエントロピーを計算する

        Args:
            data: 分析対象のデータ

        Returns:
            float: シャノンエントロピー値
        """
        if not data:
            return 0.0

        # バイト出現頻度のカウント
        counter = Counter(data)
        data_len = len(data)
        entropy = 0.0

        # エントロピー計算
        for count in counter.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _analyze_byte_distribution(self, data: bytes) -> Dict[str, Any]:
        """
        バイト分布を分析する

        Args:
            data: 分析対象のデータ

        Returns:
            Dict[str, Any]: バイト分布分析結果
        """
        if not data:
            return {
                "unique_bytes": 0,
                "distribution_uniformity": 0,
                "chi_square": 0,
                "distribution": {}
            }

        # バイト出現頻度のカウント
        counter = Counter(data)
        total_bytes = len(data)

        # ユニークなバイト数
        unique_bytes = len(counter)

        # 分布の均一性（理想的な分布からの偏差）
        expected_count = total_bytes / 256  # 256種類のバイト値が均等に分布する場合
        chi_square = 0

        for i in range(256):
            observed = counter.get(i, 0)
            chi_square += ((observed - expected_count) ** 2) / expected_count

        # 分布の均一性スコア（0〜1、1が完全均一）
        distribution_uniformity = 1.0 / (1.0 + chi_square / total_bytes)

        # 圧縮後のサイズ比を評価（圧縮効率が低いほど高いエントロピー）
        try:
            import zlib
            compressed = zlib.compress(data)
            compression_ratio = len(compressed) / total_bytes
        except Exception:
            compression_ratio = 1.0

        return {
            "unique_bytes": unique_bytes,
            "distribution_uniformity": distribution_uniformity,
            "chi_square": chi_square,
            "compression_ratio": compression_ratio,
            "distribution": dict(counter)
        }

    def _analyze_block_structure(self, data: bytes, block_type: int) -> Dict[str, Any]:
        """
        ブロック構造を分析する

        Args:
            data: 分析対象のデータ
            block_type: ブロック処理タイプ

        Returns:
            Dict[str, Any]: ブロック構造分析結果
        """
        if not data or len(data) < SIGNATURE_SIZE * 2:
            return {
                "block_count": 0,
                "avg_block_similarity": 0,
                "signature_analysis": {"found": False}
            }

        block_size = self.entropy_block_size
        sig_size = SIGNATURE_SIZE

        # シグネチャの検出を試みる（簡易的な検出）
        signature_analysis = self._analyze_signatures(data, block_type)

        # ブロック数の推定
        estimated_blocks = max(1, (len(data) - sig_size * 2) // block_size)

        # ブロック間の類似性分析
        block_similarities = []
        for i in range(0, len(data) - block_size * 2, block_size):
            block1 = data[i:i+block_size]
            block2 = data[i+block_size:i+block_size*2]
            if len(block1) == block_size and len(block2) == block_size:
                similarity = self._calculate_block_similarity(block1, block2)
                block_similarities.append(similarity)

        avg_similarity = 0
        if block_similarities:
            avg_similarity = sum(block_similarities) / len(block_similarities)

        # ブロック間の相関分析（インターリーブの場合）
        interleave_analysis = {}
        if block_type == BLOCK_TYPE_INTERLEAVE and len(data) >= sig_size * 2 + block_size * 4:
            # インターリーブブロックの特徴分析
            # シグネチャ後の最初の4ブロックを取得
            offset = sig_size * 2
            block1 = data[offset:offset+block_size]
            block2 = data[offset+block_size:offset+block_size*2]
            block3 = data[offset+block_size*2:offset+block_size*3]
            block4 = data[offset+block_size*3:offset+block_size*4]

            # 偶数ブロック同士、奇数ブロック同士の類似性
            even_similarity = self._calculate_block_similarity(block1, block3)
            odd_similarity = self._calculate_block_similarity(block2, block4)
            cross_similarity = (
                self._calculate_block_similarity(block1, block2) +
                self._calculate_block_similarity(block1, block4) +
                self._calculate_block_similarity(block3, block2) +
                self._calculate_block_similarity(block3, block4)
            ) / 4

            interleave_analysis = {
                "even_blocks_similarity": even_similarity,
                "odd_blocks_similarity": odd_similarity,
                "cross_similarity": cross_similarity,
                "interleave_detectability": (even_similarity + odd_similarity) / (2 * cross_similarity) if cross_similarity else 0
            }

        return {
            "block_count": estimated_blocks,
            "avg_block_similarity": avg_similarity,
            "signature_analysis": signature_analysis,
            "interleave_analysis": interleave_analysis
        }

    def _analyze_signatures(self, data: bytes, block_type: int) -> Dict[str, Any]:
        """
        シグネチャを分析する

        Args:
            data: 分析対象のデータ
            block_type: ブロック処理タイプ

        Returns:
            Dict[str, Any]: シグネチャ分析結果
        """
        sig_size = SIGNATURE_SIZE
        if len(data) < sig_size * 2:
            return {"found": False}

        # ブロック処理タイプに応じてシグネチャの位置を推定
        if block_type == BLOCK_TYPE_SEQUENTIAL:
            # 順次配置の場合、先頭と中間あたりにシグネチャがある可能性
            sig1 = data[:sig_size]

            # 中間位置の推定（単純な半分の位置）
            mid_pos = len(data) // 2
            # シグネチャをスキャンする範囲を設定
            scan_start = max(sig_size, mid_pos - sig_size * 5)  # 中間付近から前方
            scan_end = min(len(data) - sig_size, mid_pos + sig_size * 5)  # 中間付近から後方

            # 2つ目のシグネチャをスキャン
            sig2 = None
            sig2_pos = -1
            max_entropy = 0

            for i in range(scan_start, scan_end, sig_size // 2):
                if i + sig_size <= len(data):
                    candidate = data[i:i+sig_size]
                    entropy = self._calculate_shannon_entropy(candidate)
                    if entropy > max_entropy:
                        max_entropy = entropy
                        sig2 = candidate
                        sig2_pos = i

            if sig2 is not None:
                similarity = self._calculate_block_similarity(sig1, sig2)
                return {
                    "found": True,
                    "sig1_pos": 0,
                    "sig2_pos": sig2_pos,
                    "similarity": similarity,
                    "entropy": max_entropy
                }

        elif block_type == BLOCK_TYPE_INTERLEAVE:
            # インターリーブ配置の場合、先頭に2つのシグネチャが連続している可能性
            sig1 = data[:sig_size]
            sig2 = data[sig_size:sig_size*2]
            similarity = self._calculate_block_similarity(sig1, sig2)
            entropy1 = self._calculate_shannon_entropy(sig1)
            entropy2 = self._calculate_shannon_entropy(sig2)

            return {
                "found": True,
                "sig1_pos": 0,
                "sig2_pos": sig_size,
                "similarity": similarity,
                "entropy1": entropy1,
                "entropy2": entropy2
            }

        return {"found": False}

    def _calculate_block_similarity(self, block1: bytes, block2: bytes) -> float:
        """
        2つのブロック間の類似性を計算する

        Args:
            block1: 1つ目のブロック
            block2: 2つ目のブロック

        Returns:
            float: 類似性スコア（0～1、1が完全一致）
        """
        if not block1 or not block2:
            return 0.0

        # 長さの調整
        min_len = min(len(block1), len(block2))
        b1 = block1[:min_len]
        b2 = block2[:min_len]

        # バイトごとの一致度計算
        matching_bytes = sum(1 for a, b in zip(b1, b2) if a == b)
        similarity = matching_bytes / min_len

        # ハッシュの類似度も考慮（より厳密な比較）
        h1 = hashlib.sha256(b1).digest()
        h2 = hashlib.sha256(b2).digest()
        hash_similarity = sum(1 for a, b in zip(h1, h2) if a == b) / len(h1)

        # 類似度の平均値
        return (similarity + hash_similarity) / 2

    def _calculate_resistance_score(
        self, entropy_analysis: Dict[str, Any],
        byte_distribution: Dict[str, Any],
        block_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        解析耐性スコアを計算する

        Args:
            entropy_analysis: エントロピー分析結果
            byte_distribution: バイト分布分析結果
            block_analysis: ブロック構造分析結果

        Returns:
            Dict[str, Any]: 解析耐性スコア
        """
        # エントロピースコア（0～3）
        entropy_score = min(3.0, entropy_analysis["normalized_entropy"] * 3.0)

        # 分布均一性スコア（0～3）
        distribution_score = min(3.0, byte_distribution["distribution_uniformity"] * 3.0)

        # ブロック類似性スコア（0～4）
        # 類似性が低いほど解析が困難
        avg_similarity = block_analysis["avg_block_similarity"]
        block_score = 4.0 * (1.0 - avg_similarity)

        # 総合スコア（0～10）
        total_score = entropy_score + distribution_score + block_score

        return {
            "entropy_score": entropy_score,
            "distribution_score": distribution_score,
            "block_score": block_score,
            "total": total_score
        }