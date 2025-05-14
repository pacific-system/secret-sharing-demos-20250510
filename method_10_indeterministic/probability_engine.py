#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 確率エンジンモジュール

鍵から確率分布を生成し、それに基づいて復号時の真偽を決定します。
同一の鍵からは同一の決定が導出されることを保証しながら、
鍵の違いが確率的な決定に影響することを実現します。
"""

import hashlib
import secrets
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, ByteString

# 内部モジュールのインポート
from .config import (
    MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS,
    TRUE_TEXT_PATH, FALSE_TEXT_PATH
)
from .state_matrix import StateMatrix

class ProbabilityEngine:
    """確率エンジンクラス"""

    def __init__(self, probability_steps: int = PROBABILITY_STEPS):
        """
        確率エンジンを初期化

        Args:
            probability_steps: 確率分布の解像度
        """
        self.probability_steps = probability_steps
        self.distribution = np.zeros(probability_steps, dtype=np.float64)
        self.key_hash = None
        self.initialized = False

    def initialize(self, key: bytes, state_matrix: Optional[StateMatrix] = None) -> None:
        """
        キーから確率分布を初期化

        Args:
            key: 初期化に使用する鍵
            state_matrix: 状態マトリクス（オプション）
        """
        # 鍵のハッシュを計算
        self.key_hash = hashlib.sha512(key).digest()

        # シード値を抽出
        seed = int.from_bytes(self.key_hash[:8], byteorder='big')

        # 乱数発生器を初期化
        rng = np.random.RandomState(seed)

        if state_matrix and state_matrix.initialized:
            # 状態マトリクスが提供された場合、その情報を利用
            self._initialize_from_state_matrix(state_matrix, rng)
        else:
            # 従来の方法で初期化
            self._initialize_standard(rng)

        # 分布の正規化
        self._normalize_distribution()

        self.initialized = True

    def _initialize_standard(self, rng: np.random.RandomState) -> None:
        """
        標準的な方法で確率分布を初期化

        Args:
            rng: 初期化済み乱数生成器
        """
        # 基本分布の生成（いくつかのランダム分布を組み合わせる）
        distribution_type = rng.randint(0, 4)

        if distribution_type == 0:
            # 正規分布ベース
            mean = rng.uniform(0.2, 0.8)
            std = rng.uniform(0.1, 0.3)
            x = np.linspace(0, 1, self.probability_steps)
            self.distribution = np.exp(-0.5 * ((x - mean) / std) ** 2)

        elif distribution_type == 1:
            # ベータ分布ベース
            a = rng.uniform(0.5, 5.0)
            b = rng.uniform(0.5, 5.0)
            x = np.linspace(0, 1, self.probability_steps)
            self.distribution = x ** (a - 1) * (1 - x) ** (b - 1)

        elif distribution_type == 2:
            # 複数のピークを持つ分布
            x = np.linspace(0, 1, self.probability_steps)
            num_peaks = rng.randint(2, 5)
            self.distribution = np.zeros(self.probability_steps)

            for _ in range(num_peaks):
                peak_pos = rng.uniform(0, 1)
                peak_width = rng.uniform(0.05, 0.2)
                peak_height = rng.uniform(0.5, 1.0)
                self.distribution += peak_height * np.exp(-0.5 * ((x - peak_pos) / peak_width) ** 2)

        elif distribution_type == 3:
            # 一様分布からランダムな変形
            self.distribution = rng.uniform(0.5, 1.0, self.probability_steps)
            # スムージング
            window_size = self.probability_steps // 10
            kernel = np.ones(window_size) / window_size
            self.distribution = np.convolve(self.distribution, kernel, mode='same')

        # キーの情報を分布に埋め込む
        self._embed_key_info()

    def _initialize_from_state_matrix(self, state_matrix: StateMatrix,
                                     rng: np.random.RandomState) -> None:
        """
        状態マトリクスから確率分布を初期化

        Args:
            state_matrix: 初期化済み状態マトリクス
            rng: 初期化済み乱数生成器
        """
        # 状態マトリクスからいくつかの行を選択
        self.distribution = np.zeros(self.probability_steps)
        num_rows = min(5, state_matrix.size)

        for i in range(num_rows):
            # ランダムな行を選択
            row_idx = rng.randint(0, state_matrix.size)
            row_probs = state_matrix.get_row_probabilities(row_idx)

            # 行の確率を拡張/縮小して分布のサイズに合わせる
            if len(row_probs) != self.probability_steps:
                indices = np.linspace(0, len(row_probs) - 1, self.probability_steps)
                row_probs = np.interp(indices, np.arange(len(row_probs)), row_probs)

            # 分布に追加
            weight = 1.0 / num_rows
            self.distribution += weight * row_probs

        # キーの情報を埋め込む
        self._embed_key_info()

    def _embed_key_info(self) -> None:
        """キーの特徴を確率分布に埋め込む"""
        if not self.key_hash:
            return

        # キーハッシュから特定のバイトを抽出
        for i in range(min(16, len(self.key_hash))):
            # ハッシュの各バイトで異なる位置の分布を微調整
            byte_val = self.key_hash[i]
            idx = (byte_val * self.probability_steps) // 256

            if idx < self.probability_steps:
                # バイト値に応じた調整を行う
                # 値が大きいほど強い影響を与える
                adjustment = (byte_val / 256.0) * 0.2  # 最大20%の調整
                self.distribution[idx] *= (1.0 + adjustment)

    def _normalize_distribution(self) -> None:
        """確率分布を正規化"""
        # ゼロ以上に強制
        self.distribution = np.maximum(0, self.distribution)

        # 合計が1になるよう正規化
        total = np.sum(self.distribution)
        if total > 0:
            self.distribution /= total

        # 累積分布を計算（後で使用）
        self.cumulative_distribution = np.cumsum(self.distribution)

    def calculate_probability(self, value: float) -> float:
        """
        0〜1の値から確率分布上の確率を計算

        Args:
            value: 0〜1の値

        Returns:
            対応する確率（0.0〜1.0）
        """
        if not self.initialized:
            raise ValueError("確率エンジンが初期化されていません")

        # 値を0〜1の範囲に制限
        value = max(0.0, min(1.0, value))

        # インデックスを計算
        idx = int(value * (self.probability_steps - 1))

        # 確率値を返す
        return float(self.distribution[idx])

    def sample(self, seed_value: Optional[bytes] = None) -> float:
        """
        確率分布からサンプリングして値を取得

        Args:
            seed_value: 追加のシード値（オプション）

        Returns:
            サンプリングされた値（0.0〜1.0）
        """
        if not self.initialized:
            raise ValueError("確率エンジンが初期化されていません")

        # 追加のシード値が提供された場合は使用
        if seed_value:
            if isinstance(seed_value, bytes):
                random_value = int.from_bytes(hashlib.sha256(self.key_hash + seed_value).digest()[:8],
                                            byteorder='big') / (2**64 - 1)
            else:
                random_value = secrets.randbelow(10000) / 10000.0
        else:
            random_value = secrets.randbelow(10000) / 10000.0

        # 累積分布関数から値を取得
        idx = np.searchsorted(self.cumulative_distribution, random_value)

        # インデックスを0〜1の範囲に変換
        return idx / (self.probability_steps - 1)

    def determine_path(self, threshold: float = 0.5) -> str:
        """
        現在の確率分布から真偽パスを決定

        Args:
            threshold: 決定の閾値（0.0〜1.0）

        Returns:
            パスタイプ（"true" または "false"）
        """
        if not self.initialized:
            raise ValueError("確率エンジンが初期化されていません")

        # 確率分布の特性を分析
        mean_prob = np.sum(self.distribution * np.linspace(0, 1, self.probability_steps))

        # 適応的閾値（鍵ハッシュの最初のバイトに基づいて調整）
        if self.key_hash:
            # 鍵ハッシュの最初のバイト（0〜255）を利用
            first_byte = self.key_hash[0]
            # 閾値を±10%の範囲で調整
            threshold_adjustment = (first_byte / 255.0 - 0.5) * 0.2
            adaptive_threshold = threshold + threshold_adjustment
        else:
            adaptive_threshold = threshold

        # 平均確率と閾値を比較して決定
        return "true" if mean_prob > adaptive_threshold else "false"

    def get_path_file(self, path_type: str) -> str:
        """
        パスタイプに対応するファイルパスを取得

        Args:
            path_type: パスタイプ（"true" または "false"）

        Returns:
            ファイルパス
        """
        if path_type == "true":
            return TRUE_TEXT_PATH
        elif path_type == "false":
            return FALSE_TEXT_PATH
        else:
            raise ValueError(f"不正なパスタイプです: {path_type}")

    def reset(self) -> None:
        """状態をリセット"""
        self.distribution = np.zeros(self.probability_steps, dtype=np.float64)
        self.key_hash = None
        self.initialized = False

def calculate_probability_distribution(key: bytes, state_matrix: Optional[StateMatrix] = None,
                                    steps: int = PROBABILITY_STEPS) -> ProbabilityEngine:
    """
    キーから確率分布エンジンを生成

    Args:
        key: 初期化に使用する鍵
        state_matrix: 状態マトリクス（オプション）
        steps: 確率分布の解像度

    Returns:
        初期化された確率エンジン
    """
    engine = ProbabilityEngine(steps)
    engine.initialize(key, state_matrix)
    return engine
