#!/usr/bin/env python3
"""
状態遷移マトリクス生成モジュール

鍵に基づいて確率的状態遷移マトリクスを生成し、
非決定論的な実行パスを構築するための基盤を提供します。
"""

import os
import secrets
import hashlib
import hmac
import math
import numpy as np
import sys
from typing import Dict, List, Tuple, Optional, Union, Any, Callable, ByteString
from pathlib import Path

# パッケージとして利用する場合と直接実行する場合でインポートを切り替え
if __name__ == "__main__" or __name__ == "state_matrix":
    try:
        # 相対パスをフルパスに変換して安定性を向上
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.append(current_dir)
        from config import STATE_MATRIX_SIZE, STATE_TRANSITIONS, MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS
    except ImportError:
        # テスト用のデフォルト値
        STATE_MATRIX_SIZE = 16
        STATE_TRANSITIONS = 10
        MIN_PROBABILITY = 0.05
        MAX_PROBABILITY = 0.95
        PROBABILITY_STEPS = 100
else:
    # 内部モジュールのインポート
    from .config import (
        STATE_MATRIX_SIZE, STATE_TRANSITIONS,
        MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS
    )

class State:
    """
    状態を表すクラス

    非決定論的状態機械の各状態を表し、状態の属性と
    次状態への遷移確率を保持します。
    """

    def __init__(self, state_id: int, attributes: Dict[str, Any] = None):
        """
        状態の初期化

        Args:
            state_id: 状態のID
            attributes: 状態の属性辞書
        """
        self.state_id = state_id
        self.attributes = attributes or {}
        self.transitions = {}  # {next_state_id: probability}

    def add_transition(self, next_state_id: int, probability: float):
        """
        状態遷移を追加

        Args:
            next_state_id: 遷移先の状態ID
            probability: 遷移確率
        """
        self.transitions[next_state_id] = probability

    def normalize_transitions(self):
        """
        遷移確率の合計が1になるように正規化
        """
        total = sum(self.transitions.values())
        if total > 0:
            for state_id in self.transitions:
                self.transitions[state_id] /= total

    def next_state(self, random_value: float) -> int:
        """
        次の状態を確率的に決定

        Args:
            random_value: 0から1の間の乱数

        Returns:
            次の状態ID
        """
        cumulative = 0.0
        for state_id, prob in self.transitions.items():
            cumulative += prob
            if random_value <= cumulative:
                return state_id

        # 浮動小数点誤差対策（通常ここには到達しない）
        if self.transitions:
            return list(self.transitions.keys())[-1]
        return self.state_id  # 遷移先がなければ自分自身


class StateMatrixGenerator:
    """
    状態遷移マトリクス生成器

    鍵に基づいて確率的な状態遷移マトリクスを生成します。
    このマトリクスは非決定論的な実行パスを提供します。
    """

    def __init__(self, key: bytes, salt: Optional[bytes] = None):
        """
        生成器の初期化

        Args:
            key: マスター鍵
            salt: ソルト値（省略時はランダム生成）
        """
        self.key = key
        self.salt = salt or os.urandom(16)
        self.states = {}  # {state_id: State}
        self.true_initial_state = None
        self.false_initial_state = None

    def _generate_random_from_key(self, purpose: bytes, min_val: float, max_val: float) -> float:
        """
        鍵から特定の目的のための乱数を生成

        Args:
            purpose: 乱数生成の目的を表す識別子
            min_val: 生成する乱数の最小値
            max_val: 生成する乱数の最大値

        Returns:
            min_valからmax_valの間の乱数
        """
        # 鍵とソルトから目的別のシード値を生成
        hmac_result = hmac.new(self.key, purpose + self.salt, hashlib.sha256).digest()

        # 生成した値を0-1の間の浮動小数点数に変換
        random_bytes = int.from_bytes(hmac_result[:8], byteorder='big')
        normalized = random_bytes / (2**64 - 1)  # 0-1の間に正規化

        # 指定範囲にスケーリング
        return min_val + normalized * (max_val - min_val)

    def _derive_state_params(self, state_id: int) -> Dict[str, Any]:
        """
        状態IDから状態パラメータを導出

        Args:
            state_id: 状態ID

        Returns:
            状態パラメータ辞書
        """
        purpose = f"state_params_{state_id}".encode('utf-8')
        hmac_result = hmac.new(self.key, purpose + self.salt, hashlib.sha256).digest()

        # 状態パラメータの生成（各状態の特性を決定）
        params = {
            "complexity": int.from_bytes(hmac_result[0:4], byteorder='big') % 100,
            "volatility": int.from_bytes(hmac_result[4:8], byteorder='big') % 100,
            "memory_impact": int.from_bytes(hmac_result[8:12], byteorder='big') % 100,
            "hash_seed": hmac_result[12:20],
            "transform_key": hmac_result[20:28]
        }

        return params

    def generate_state_matrix(self) -> Dict[int, State]:
        """
        状態遷移マトリクスを生成

        Returns:
            生成された状態辞書 {state_id: State}
        """
        # 状態の作成
        for i in range(STATE_MATRIX_SIZE):
            params = self._derive_state_params(i)
            self.states[i] = State(i, params)

        # 状態間の遷移確率の設定
        for i in range(STATE_MATRIX_SIZE):
            # 各状態から遷移先をいくつか選択
            num_transitions = 1 + int(self._generate_random_from_key(
                f"num_transitions_{i}".encode('utf-8'),
                1,
                min(5, STATE_MATRIX_SIZE - 1)
            ))

            # 遷移先の選択と確率の設定
            available_states = list(range(STATE_MATRIX_SIZE))
            available_states.remove(i)  # 自己遷移を避ける（オプション）

            selected_states = []
            remaining = num_transitions

            while remaining > 0 and available_states:
                # 次の遷移先をランダムに選択
                selection_seed = f"state_selection_{i}_{len(selected_states)}".encode('utf-8')
                selection_val = self._generate_random_from_key(selection_seed, 0, 1)
                index = int(selection_val * len(available_states))
                index = min(index, len(available_states) - 1)  # 境界チェック

                selected_states.append(available_states.pop(index))
                remaining -= 1

            # 選択された各状態に遷移確率を設定
            for j, next_state in enumerate(selected_states):
                prob_seed = f"transition_prob_{i}_{next_state}".encode('utf-8')
                probability = self._generate_random_from_key(
                    prob_seed,
                    MIN_PROBABILITY,
                    MAX_PROBABILITY / num_transitions
                )
                self.states[i].add_transition(next_state, probability)

            # 確率の正規化
            self.states[i].normalize_transitions()

        return self.states

    def derive_initial_states(self) -> Tuple[int, int]:
        """
        正規/非正規パスの初期状態を導出

        Returns:
            (true_initial_state, false_initial_state): 正規/非正規パスの初期状態ID
        """
        # 正規パスの初期状態
        true_purpose = b"true_path_initial_state"
        true_random = self._generate_random_from_key(true_purpose, 0, 1)
        self.true_initial_state = int(true_random * STATE_MATRIX_SIZE) % STATE_MATRIX_SIZE

        # 非正規パスの初期状態（正規と異なるようにする）
        false_purpose = b"false_path_initial_state"
        false_random = self._generate_random_from_key(false_purpose, 0, 1)

        # 少なくとも1つは状態があるため、正規と異なる状態を選択
        remaining_states = list(range(STATE_MATRIX_SIZE))
        remaining_states.remove(self.true_initial_state)

        if remaining_states:
            index = int(false_random * len(remaining_states)) % len(remaining_states)
            self.false_initial_state = remaining_states[index]
        else:
            # エッジケース: 状態が1つしかない場合は同じ状態を使用
            self.false_initial_state = self.true_initial_state

        return self.true_initial_state, self.false_initial_state

    def get_state_visualization(self) -> str:
        """
        状態遷移マトリクスの可視化文字列を取得（デバッグ用）

        Returns:
            マトリクスの文字列表現
        """
        if not self.states:
            return "状態マトリクスがまだ生成されていません"

        result = "状態遷移マトリクス:\n"
        result += "-" * 50 + "\n"

        for state_id, state in sorted(self.states.items()):
            result += f"状態 {state_id}:\n"
            result += f"  属性: {state.attributes}\n"
            result += "  遷移:\n"

            for next_id, prob in sorted(state.transitions.items()):
                result += f"    → 状態 {next_id}: {prob:.4f}\n"

            result += "-" * 30 + "\n"

        result += f"正規パスの初期状態: {self.true_initial_state}\n"
        result += f"非正規パスの初期状態: {self.false_initial_state}\n"

        return result


class StateExecutor:
    """
    状態実行エンジン

    生成された状態マトリクスに基づいて状態遷移を実行します。
    """

    def __init__(self, states: Dict[int, State], initial_state: int):
        """
        実行エンジンの初期化

        Args:
            states: 状態辞書 {state_id: State}
            initial_state: 初期状態ID
        """
        self.states = states
        self.current_state_id = initial_state
        self.path_history = [initial_state]

    def step(self, random_value: Optional[float] = None) -> int:
        """
        1ステップ実行して次の状態に移動

        Args:
            random_value: 使用する乱数（指定しない場合はランダム生成）

        Returns:
            次の状態ID
        """
        if random_value is None:
            random_value = secrets.randbelow(10000) / 10000.0

        current_state = self.states.get(self.current_state_id)
        if not current_state:
            raise ValueError(f"状態ID {self.current_state_id} が見つかりません")

        next_state_id = current_state.next_state(random_value)
        self.current_state_id = next_state_id
        self.path_history.append(next_state_id)

        return next_state_id

    def run_transitions(self, steps: int) -> List[int]:
        """
        指定ステップ数の状態遷移を実行

        Args:
            steps: 実行するステップ数

        Returns:
            状態遷移の履歴（状態IDのリスト）
        """
        for _ in range(steps):
            self.step()

        return self.path_history

    def get_current_state(self) -> State:
        """
        現在の状態オブジェクトを取得

        Returns:
            現在の状態
        """
        return self.states.get(self.current_state_id)


# 元のStateMatrixクラスの一部機能を残して、新しい実装と連携できるようにします
class StateMatrix:
    """状態マトリクスクラス - 連携用"""

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

        # ハッシュからシード値を抽出 (32ビットに制限)
        seed = int.from_bytes(hash_value[:4], byteorder='big')

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
            # 循環インポートを避けるための内部関数
            def get_entropy_bytes(size: int) -> bytes:
                return os.urandom(size)

            # 十分なデータを確保するために増やす
            entropy_size = self.size * self.size
            entropy = get_entropy_bytes(entropy_size)

            # サイズが足りない場合は繰り返して拡張
            while len(entropy) < entropy_size:
                entropy += get_entropy_bytes(entropy_size - len(entropy))

            # NumPyの32ビット制限を回避するため、データタイプを明示的に指定
            entropy_array = np.frombuffer(entropy[:entropy_size], dtype=np.uint8).astype(np.float32)
            entropy_array = entropy_array.reshape(self.size, self.size) / 255.0

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


def create_state_matrix_from_key(key: bytes, salt: Optional[bytes] = None) -> Tuple[Dict[int, State], int, int]:
    """
    鍵から状態遷移マトリクスと初期状態を生成

    Args:
        key: マスター鍵
        salt: ソルト値（省略時はランダム生成）

    Returns:
        (状態辞書, 正規パスの初期状態, 非正規パスの初期状態)
    """
    generator = StateMatrixGenerator(key, salt)
    states = generator.generate_state_matrix()
    true_initial, false_initial = generator.derive_initial_states()

    return states, true_initial, false_initial


def get_biased_random_generator(key: bytes, bias_factor: float) -> Callable[[], float]:
    """
    バイアスのかかった乱数生成器を作成

    鍵に基づいて特定の方向にバイアスされた乱数を生成する関数を返します。
    これにより、実行パスが確率的でありながらも、特定の方向に導かれるようになります。

    Args:
        key: バイアスの基となる鍵
        bias_factor: バイアスの強さ（0.0-1.0）
            0.0: バイアスなし（完全にランダム）
            1.0: 最大バイアス（決定論的）

    Returns:
        バイアスのかかった乱数を生成する関数
    """
    # 鍵からバイアスパターンを生成
    # これにより、同じ鍵では同じバイアスパターンとなる
    hash_val = hashlib.sha256(key).digest()
    # numpy配列ではなく標準のPythonリストとして保持（numpy型の問題を回避）
    pattern = [b / 255.0 for b in hash_val]

    def biased_random() -> float:
        """
        バイアスのかかった0.0-1.0の乱数を生成

        Returns:
            バイアスされた乱数
        """
        # 標準の乱数
        base_random = secrets.randbelow(10000) / 10000.0

        # 現在のインデックスの決定（時間依存でパターンを変化させる）
        time_factor = int.from_bytes(os.urandom(4), byteorder='big')
        index = time_factor % len(pattern)

        # バイアス値の適用
        bias_value = pattern[index]

        # バイアスの適用
        # bias_factor = 0 → 完全にbase_random
        # bias_factor = 1 → 完全にbias_value
        result = base_random * (1 - bias_factor) + bias_value * bias_factor

        # 0-1の範囲を確保
        return max(0.0, min(1.0, result))

    return biased_random


def generate_state_matrix(key: bytes, data: Optional[bytes] = None,
                         salt: Optional[bytes] = None,
                         true_bias: float = 0.5,
                         size: int = STATE_MATRIX_SIZE) -> StateMatrix:
    """
    キーとデータから状態マトリクスを生成 (レガシー互換用)

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


# テスト用の関数
def test_state_matrix():
    """
    状態遷移マトリクスの生成と実行をテスト
    """
    test_key = os.urandom(32)

    # マトリクスの生成
    generator = StateMatrixGenerator(test_key)
    states = generator.generate_state_matrix()
    true_initial, false_initial = generator.derive_initial_states()

    print("状態マトリクス生成完了:")
    print(f"状態数: {len(states)}")
    print(f"正規パスの初期状態: {true_initial}")
    print(f"非正規パスの初期状態: {false_initial}")

    # 正規パスの実行
    print("\n正規パスの実行:")
    true_executor = StateExecutor(states, true_initial)
    true_path = true_executor.run_transitions(STATE_TRANSITIONS)
    print(f"状態遷移: {true_path}")

    # 非正規パスの実行
    print("\n非正規パスの実行:")
    false_executor = StateExecutor(states, false_initial)
    false_path = false_executor.run_transitions(STATE_TRANSITIONS)
    print(f"状態遷移: {false_path}")

    # バイアス乱数のテスト
    print("\nバイアス乱数のテスト:")
    biased_gen = get_biased_random_generator(test_key, 0.7)
    biased_values = [biased_gen() for _ in range(10)]
    print(f"バイアス値: {biased_values}")

    # 元の実装との連携テスト
    print("\n元の実装との連携テスト:")
    old_matrix = generate_state_matrix(test_key)
    old_matrix.perform_transitions(STATE_TRANSITIONS)
    old_signature = old_matrix.get_state_signature()
    print(f"旧実装シグネチャ: {old_signature.hex()[:16]}...")


# メイン関数
if __name__ == "__main__":
    test_state_matrix()
