#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 状態マトリクスモジュール

暗号化の状態を保持するマトリクスの生成と操作を行います。
このマトリクスは鍵と入力データに基づいて初期化され、
暗号化および復号プロセスの状態遷移を制御します。
"""

import os
import hashlib
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, ByteString

# 内部モジュールのインポート
from .config import STATE_MATRIX_SIZE, STATE_TRANSITIONS
from .entropy_injector import get_entropy_bytes

class StateMatrix:
    """状態マトリクスクラス"""

    def __init__(self, size: int = STATE_MATRIX_SIZE):
        """
        状態マトリクスを初期化

        Args:
            size: マトリクスのサイズ（N x N）
        """
        self.size = size
        # 零行列で初期化
        self.matrix = np.zeros((size, size), dtype=np.float32)
        self.initialized = False
        self.transition_count = 0

    def initialize(self, key: bytes, data: Optional[bytes] = None,
                  salt: Optional[bytes] = None,
                  true_bias: float = 0.5) -> None:
        """
        キーとデータを元に状態マトリクスを初期化

        Args:
            key: 初期化に使用する鍵
            data: 追加の初期化データ（オプション）
            salt: ソルト値（オプション）
            true_bias: 真の方向へのバイアス（0.0〜1.0）
        """
        if self.initialized:
            # 既に初期化されている場合はリセット
            self.reset()

        # シード値を生成
        seed_material = key
        if data:
            seed_material += data
        if salt:
            seed_material += salt

        # ハッシュを計算
        hash_value = hashlib.sha512(seed_material).digest()

        # ハッシュからシード値を抽出
        seed = int.from_bytes(hash_value[:8], byteorder='big')

        # 乱数生成器を初期化
        rng = np.random.RandomState(seed)

        # バイアスを適用
        bias = true_bias - 0.5  # -0.5〜0.5の範囲に変換

        # マトリクスの生成（一様分布 + バイアス）
        self.matrix = rng.rand(self.size, self.size).astype(np.float32)

        # バイアスを適用
        if bias != 0:
            self.matrix += bias
            # 値が[0,1]の範囲に収まるよう調整
            self.matrix = np.clip(self.matrix, 0, 1)

        # 正規化（各行の合計を1にする）
        row_sums = self.matrix.sum(axis=1, keepdims=True)
        self.matrix /= row_sums

        # パターンを追加して複雑にする
        self._add_complexity_patterns(rng)

        self.initialized = True
        self.transition_count = 0

    def _add_complexity_patterns(self, rng: np.random.RandomState) -> None:
        """
        マトリクスに複雑なパターンを追加

        Args:
            rng: 初期化済み乱数生成器
        """
        # 1. 一部のセルを強調
        highlight_count = self.size // 4
        for _ in range(highlight_count):
            i, j = rng.randint(0, self.size, 2)
            # 強調（最大2倍まで）
            self.matrix[i, j] *= (1.0 + rng.rand())

        # 2. グラデーションパターンを追加
        gradient = np.outer(
            np.linspace(0, 1, self.size),
            np.linspace(1, 0, self.size)
        )
        # 元の値の80%〜120%の間で変動
        factor = 0.8 + 0.4 * rng.rand()
        self.matrix = self.matrix * (1.0 + factor * (gradient - 0.5) * 0.2)

        # 3. ブロックパターンを追加
        block_size = self.size // 4
        if block_size > 1:
            for i in range(0, self.size, block_size):
                for j in range(0, self.size, block_size):
                    # ブロック内の値を微調整
                    block_factor = 0.9 + 0.2 * rng.rand()
                    i_end = min(i + block_size, self.size)
                    j_end = min(j + block_size, self.size)
                    self.matrix[i:i_end, j:j_end] *= block_factor

        # 再度正規化
        row_sums = self.matrix.sum(axis=1, keepdims=True)
        self.matrix /= row_sums

    def transition(self) -> None:
        """
        状態マトリクスを遷移させる

        マトリクスに対して行列演算を適用して状態を進める
        """
        if not self.initialized:
            raise ValueError("状態マトリクスが初期化されていません")

        # 遷移パターンを選択（遷移回数によって異なる操作を適用）
        operation = self.transition_count % 4

        if operation == 0:
            # 行列の累乗（自己遷移）
            self.matrix = np.matmul(self.matrix, self.matrix)
        elif operation == 1:
            # 行と列を入れ替え、その後行を正規化
            self.matrix = self.matrix.T
        elif operation == 2:
            # エントロピーを注入
            entropy = get_entropy_bytes(self.size * 4)
            entropy_array = np.frombuffer(entropy, dtype=np.uint8).astype(np.float32)
            entropy_array = entropy_array[:self.size*self.size].reshape(self.size, self.size) / 255.0

            # エントロピーを10%混合
            self.matrix = 0.9 * self.matrix + 0.1 * entropy_array
        elif operation == 3:
            # 非線形変換を適用
            self.matrix = np.sin(self.matrix * np.pi / 2)

        # 必ず0〜1の範囲に収める
        self.matrix = np.clip(self.matrix, 0, 1)

        # 再度正規化
        row_sums = self.matrix.sum(axis=1, keepdims=True)
        self.matrix /= row_sums

        # 遷移カウントを更新
        self.transition_count += 1

    def get_probability(self, row: int, col: int) -> float:
        """
        特定位置の確率値を取得

        Args:
            row: 行インデックス
            col: 列インデックス

        Returns:
            確率値（0.0〜1.0）
        """
        if not self.initialized:
            raise ValueError("状態マトリクスが初期化されていません")

        if 0 <= row < self.size and 0 <= col < self.size:
            return float(self.matrix[row, col])
        else:
            raise ValueError(f"インデックスが範囲外です: ({row}, {col})")

    def get_row_probabilities(self, row: int) -> np.ndarray:
        """
        特定行の確率分布を取得

        Args:
            row: 行インデックス

        Returns:
            確率分布（サイズNの配列）
        """
        if not self.initialized:
            raise ValueError("状態マトリクスが初期化されていません")

        if 0 <= row < self.size:
            return self.matrix[row, :].copy()
        else:
            raise ValueError(f"行インデックスが範囲外です: {row}")

    def get_state_signature(self) -> bytes:
        """
        現在の状態のシグネチャを取得

        Returns:
            現在の状態を表すハッシュ値
        """
        if not self.initialized:
            raise ValueError("状態マトリクスが初期化されていません")

        # 行列を平坦化
        flat_data = self.matrix.flatten().tobytes()

        # 遷移カウントも含める
        count_bytes = self.transition_count.to_bytes(4, byteorder='big')

        # ハッシュを計算
        return hashlib.sha256(flat_data + count_bytes).digest()

    def perform_transitions(self, count: int = STATE_TRANSITIONS) -> None:
        """
        複数回の遷移を一括実行

        Args:
            count: 遷移回数
        """
        for _ in range(count):
            self.transition()

    def reset(self) -> None:
        """状態をリセット"""
        self.matrix = np.zeros((self.size, self.size), dtype=np.float32)
        self.initialized = False
        self.transition_count = 0

    def clone(self) -> 'StateMatrix':
        """
        現在の状態マトリクスの複製を作成

        Returns:
            複製された状態マトリクス
        """
        clone = StateMatrix(self.size)
        clone.matrix = self.matrix.copy()
        clone.initialized = self.initialized
        clone.transition_count = self.transition_count
        return clone

def generate_state_matrix(key: bytes, data: Optional[bytes] = None,
                         salt: Optional[bytes] = None,
                         true_bias: float = 0.5,
                         size: int = STATE_MATRIX_SIZE) -> StateMatrix:
    """
    キーとデータから状態マトリクスを生成

    Args:
        key: 初期化に使用する鍵
        data: 追加の初期化データ（オプション）
        salt: ソルト値（オプション）
        true_bias: 真の方向へのバイアス（0.0〜1.0）
        size: マトリクスサイズ

    Returns:
        初期化された状態マトリクス
    """
    matrix = StateMatrix(size)
    matrix.initialize(key, data, salt, true_bias)
    return matrix
