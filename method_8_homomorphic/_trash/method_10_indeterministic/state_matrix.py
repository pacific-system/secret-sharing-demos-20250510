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
    非決定論的状態機械の各状態を表現するクラス

    各状態は複数の遷移先と、その遷移確率を持ちます。
    """

    def __init__(self, state_id: int):
        """
        状態の初期化

        Args:
            state_id: 状態ID
        """
        if not isinstance(state_id, int) or state_id < 0:
            raise ValueError("状態IDは0以上の整数である必要があります")

        self.state_id = state_id
        self.transitions = {}  # {target_id: probability}
        self._is_frozen = False  # 遷移の追加終了後にフリーズ

    def add_transition(self, target_id: int, probability: float) -> None:
        """
        遷移先の追加

        Args:
            target_id: 遷移先の状態ID
            probability: 遷移確率（0.0-1.0）
        """
        if self._is_frozen:
            raise RuntimeError("遷移の追加が完了した状態には新たな遷移を追加できません")

        if not isinstance(target_id, int) or target_id < 0:
            raise ValueError("遷移先IDは0以上の整数である必要があります")

        if not 0.0 <= probability <= 1.0:
            raise ValueError("遷移確率は0.0から1.0の間である必要があります")

        # 小数点以下6桁に丸める（浮動小数点誤差対策）
        probability = round(probability, 6)

        # 確率0の遷移は追加しない
        if probability > 0.0:
            self.transitions[target_id] = probability

    def normalize_transitions(self) -> None:
        """
        遷移確率の合計が1.0になるよう正規化
        """
        if not self.transitions:
            return

        total = sum(self.transitions.values())
        if total <= 0.0:
            return

        # 確率を正規化
        for target_id in self.transitions:
            self.transitions[target_id] = round(self.transitions[target_id] / total, 6)

        # わずかな丸め誤差を修正
        # 合計が1.0にならない場合、最も大きい遷移の確率を調整
        corrected_total = sum(self.transitions.values())
        if abs(corrected_total - 1.0) > 1e-10:
            max_target = max(self.transitions.items(), key=lambda x: x[1])[0]
            self.transitions[max_target] += round(1.0 - corrected_total, 6)

        # 遷移の追加を完了としてフリーズ
        self._is_frozen = True

    def next_state(self, random_value: float) -> int:
        """
        乱数に基づいて次状態を決定

        Args:
            random_value: 0.0-1.0の乱数

        Returns:
            次の状態ID
        """
        if not 0.0 <= random_value <= 1.0:
            raise ValueError("乱数は0.0から1.0の間である必要があります")

        if not self.transitions:
            raise ValueError(f"状態 {self.state_id} に遷移先が定義されていません")

        # 累積確率で次状態を決定
        cumulative_prob = 0.0
        for target_id, probability in sorted(self.transitions.items()):
            cumulative_prob += probability
            if random_value <= cumulative_prob:
                return target_id

        # 丸め誤差などで全ての確率を超えた場合は最後の遷移先を返す
        return sorted(self.transitions.keys())[-1]

    def get_transition_count(self) -> int:
        """
        遷移先の数を取得

        Returns:
            遷移先の数
        """
        return len(self.transitions)

    def is_terminal(self) -> bool:
        """
        終端状態かどうかを判定

        Returns:
            終端状態の場合True
        """
        # 自己ループのみの場合を終端状態とみなす
        return len(self.transitions) == 1 and self.state_id in self.transitions

    def get_entropy(self) -> float:
        """
        状態のエントロピーを計算

        遷移の不確実性の指標として、確率分布のエントロピーを計算します。
        高いエントロピーは予測困難性を示します。

        Returns:
            エントロピー値
        """
        if not self.transitions:
            return 0.0

        # シャノンエントロピーの計算
        entropy = 0.0
        for prob in self.transitions.values():
            if prob > 0.0:  # log(0)を防止
                entropy -= prob * math.log2(prob)

        return entropy

class StateMatrixGenerator:
    """
    状態遷移マトリクス生成器

    鍵に基づいて、状態遷移マトリクスを生成するジェネレータです。
    同じ鍵からは同じマトリクスが生成され、異なる鍵からは異なるマトリクスが生成されます。
    """

    def __init__(self, key: bytes, size: int = None, min_prob: float = None, max_prob: float = None, steps: int = None):
        """
        ジェネレータの初期化

        Args:
            key: マスター鍵
            size: 状態数（None: configから読み込み）
            min_prob: 最小遷移確率（None: configから読み込み）
            max_prob: 最大遷移確率（None: configから読み込み）
            steps: 確率刻み数（None: configから読み込み）
        """
        # 入力検証
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("鍵はバイト列で、空であってはなりません")

        # キーのハッシュ化（長さを正規化）
        self.key = hashlib.sha256(key).digest()

        # 設定値の読み込み
        self.size = size if size is not None else STATE_MATRIX_SIZE
        self.min_probability = min_prob if min_prob is not None else MIN_PROBABILITY
        self.max_probability = max_prob if max_prob is not None else MAX_PROBABILITY
        self.probability_steps = steps if steps is not None else PROBABILITY_STEPS

        if self.size <= 0:
            raise ValueError("状態数は正の整数である必要があります")

        if not 0.0 <= self.min_probability <= self.max_probability <= 1.0:
            raise ValueError("確率範囲が無効です。0.0 <= min <= max <= 1.0 である必要があります")

        if self.probability_steps <= 0:
            raise ValueError("確率刻み数は正の整数である必要があります")

        # キャッシュの初期化
        self._state_matrix_cache = None
        self._initial_states_cache = None
        self._hmac_cache = {}

    def _get_hmac(self, purpose: bytes) -> bytes:
        """
        特定目的のためのHMACを取得（キャッシュ付き）

        Args:
            purpose: HMAC生成の目的を示すバイト列

        Returns:
            HMACダイジェスト
        """
        # メモリ使用量を制限するためにキャッシュサイズを制限
        if len(self._hmac_cache) > 100:
            # キャッシュをクリア（簡易的なLRU）
            self._hmac_cache.clear()

        cache_key = purpose.hex()
        if cache_key in self._hmac_cache:
            return self._hmac_cache[cache_key]

        # HMAC-SHA256を使用
        h = hmac.new(self.key, purpose, hashlib.sha256)
        digest = h.digest()
        self._hmac_cache[cache_key] = digest
        return digest

    def _generate_random_from_key(self, purpose: bytes, min_val: float, max_val: float) -> float:
        """
        鍵から特定の目的のための乱数を生成

        Args:
            purpose: 乱数の目的を示すバイト列
            min_val: 最小値
            max_val: 最大値

        Returns:
            min_val〜max_valの乱数
        """
        # 目的に応じたHMACを生成
        digest = self._get_hmac(purpose)

        # 0〜0xFFFFFFFFの整数に変換
        value = int.from_bytes(digest[:4], byteorder='big')

        # 0.0〜1.0の範囲に正規化
        normalized = value / 0xFFFFFFFF

        # 指定範囲に変換
        return min_val + normalized * (max_val - min_val)

    def generate_state_matrix(self) -> Dict[int, State]:
        """
        状態遷移マトリクスを生成

        Returns:
            状態辞書 {state_id: State}
        """
        # キャッシュを利用
        if self._state_matrix_cache is not None:
            return self._state_matrix_cache

        states = {}

        # 各状態を生成
        for state_id in range(self.size):
            states[state_id] = State(state_id)

            # 量子化された確率値のリスト（重複を防ぐため）
            available_probs = []
            for i in range(self.probability_steps):
                # 量子化された確率値
                prob = self.min_probability + i * (self.max_probability - self.min_probability) / (self.probability_steps - 1)
                available_probs.append(round(prob, 6))  # 丸めて重複を防止

            # 遷移先候補
            transition_targets = list(range(self.size))

            # この状態から各状態への遷移確率を設定
            remaining_prob = 1.0

            # 最後の状態は残りの確率を割り当てるため、size-1の状態まで処理
            for target in range(self.size - 1):
                # すでに全確率を割り当て終わった場合は終了
                if remaining_prob <= 0.0:
                    break

                # 遷移確率を決定
                # 目的コード生成: "state_{state_id}_to_{target}"
                purpose = f"state_{state_id}_to_{target}".encode()

                # 確率値を量子化
                index = int(self._generate_random_from_key(purpose, 0, len(available_probs) - 0.001))
                prob = min(available_probs[index], remaining_prob)

                # 確率0より大きい場合のみ遷移を追加
                if prob > 0.0:
                    states[state_id].add_transition(target, prob)
                    remaining_prob -= prob

            # 残りの確率を最後の状態に割り当て
            if remaining_prob > 0.0:
                states[state_id].add_transition(self.size - 1, remaining_prob)

            # 確率の正規化
            states[state_id].normalize_transitions()

        # キャッシュに保存
        self._state_matrix_cache = states
        return states

    def derive_initial_states(self) -> Tuple[int, int]:
        """
        初期状態IDを導出

        真/偽情報に対応する初期状態IDを返します。
        この実装では、真/偽で異なる状態から始めることで、
        真/偽情報を含む異なる実行パスを構築します。

        Returns:
            (真情報の初期状態ID, 偽情報の初期状態ID)
        """
        # キャッシュを利用
        if self._initial_states_cache is not None:
            return self._initial_states_cache

        # 真情報の初期状態
        true_purpose = b"initial_state_true"
        true_initial = int(self._generate_random_from_key(true_purpose, 0, self.size - 0.001))

        # 偽情報の初期状態（真と異なるようにする）
        false_purpose = b"initial_state_false"
        false_initial = -1

        # 真と偽で異なる状態になるまで試行
        retry_count = 0
        while false_initial == -1 or false_initial == true_initial:
            # 再試行回数制限をチェック
            retry_count += 1
            if retry_count > 100:
                # どうしても異なる値にならない場合は強制的に別の値にする
                false_initial = (true_initial + 1) % self.size
                break

            # 偽の初期状態を再生成
            false_purpose_retry = false_purpose + str(retry_count).encode()
            false_initial = int(self._generate_random_from_key(false_purpose_retry, 0, self.size - 0.001))

        result = (true_initial, false_initial)
        self._initial_states_cache = result
        return result

    def get_state_visualization(self) -> str:
        """
        状態遷移マトリクスの可視化文字列を取得（デバッグ用）

        Returns:
            マトリクスの文字列表現
        """
        if not self._state_matrix_cache:
            return "状態マトリクスがまだ生成されていません"

        result = "状態遷移マトリクス:\n"
        result += "-" * 50 + "\n"

        for state_id, state in sorted(self._state_matrix_cache.items()):
            result += f"状態 {state_id}:\n"
            result += f"  遷移:\n"

            for next_id, prob in sorted(state.transitions.items()):
                result += f"    → 状態 {next_id}: {prob:.4f}\n"

            result += "-" * 30 + "\n"

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
        if not states:
            raise ValueError("状態辞書が空です")

        if initial_state not in states:
            raise ValueError(f"初期状態ID {initial_state} が状態辞書に存在しません")

        self.states = states
        self.current_state_id = initial_state
        self.path_history = [initial_state]
        self._transition_count = 0
        self._last_random_value = None
        self._secure_mode = True

    def set_secure_mode(self, enabled: bool) -> None:
        """
        セキュアモードの設定

        セキュアモードでは追加のセキュリティチェックが行われ、
        状態遷移の整合性を保証します。

        Args:
            enabled: セキュアモードを有効にするかどうか
        """
        self._secure_mode = enabled

    def step(self, random_value: Optional[float] = None) -> int:
        """
        1ステップ実行して次の状態に移動

        Args:
            random_value: 使用する乱数（指定しない場合はランダム生成）

        Returns:
            次の状態ID
        """
        # 状態を検証
        if self._secure_mode and self.current_state_id not in self.states:
            raise ValueError(f"現在の状態ID {self.current_state_id} が状態辞書に存在しません")

        # 乱数を生成または検証
        if random_value is None:
            random_value = secrets.randbelow(10000) / 10000.0
        elif not (0.0 <= random_value <= 1.0):
            raise ValueError("乱数は0.0から1.0の間である必要があります")

        # 現在の状態を取得
        current_state = self.states.get(self.current_state_id)
        if not current_state:
            raise ValueError(f"状態ID {self.current_state_id} が見つかりません")

        # 遷移が存在しない場合のエラー処理
        if not current_state.transitions:
            if self._secure_mode:
                # セキュアモードでは例外をスロー
                raise ValueError(f"状態 {self.current_state_id} に遷移先が定義されていません")
            else:
                # セキュアモードでなければ現在の状態を維持
                self._last_random_value = random_value
                self._transition_count += 1
                return self.current_state_id

        # 次状態の決定
        next_state_id = current_state.next_state(random_value)

        # 状態の更新
        self.current_state_id = next_state_id
        self.path_history.append(next_state_id)
        self._last_random_value = random_value
        self._transition_count += 1

        return next_state_id

    def run_transitions(self, steps: int) -> List[int]:
        """
        指定ステップ数の状態遷移を実行

        Args:
            steps: 実行するステップ数

        Returns:
            状態遷移の履歴（状態IDのリスト）
        """
        if steps < 0:
            raise ValueError("ステップ数は0以上である必要があります")

        for _ in range(steps):
            try:
                self.step()
            except Exception as e:
                if self._secure_mode:
                    raise RuntimeError(f"状態遷移中にエラーが発生しました: {e}") from e
                # セキュアモードでない場合は例外を無視して続行

        return self.path_history

    def get_current_state(self) -> Optional[State]:
        """
        現在の状態オブジェクトを取得

        Returns:
            現在の状態（存在しない場合はNone）
        """
        return self.states.get(self.current_state_id)

    def get_transition_count(self) -> int:
        """
        実行された遷移の回数を取得

        Returns:
            遷移カウント
        """
        return self._transition_count

    def get_path_statistics(self) -> Dict[str, Any]:
        """
        パス履歴の統計情報を取得

        Returns:
            統計情報を含む辞書
        """
        if not self.path_history:
            return {"error": "パス履歴が空です"}

        # 状態の出現回数を集計
        state_counts = {}
        for state_id in self.path_history:
            state_counts[state_id] = state_counts.get(state_id, 0) + 1

        # 最も頻出した状態
        most_common_state = max(state_counts.items(), key=lambda x: x[1], default=(None, 0))

        # 遷移の繰り返しパターンを検出
        repeated_patterns = self._detect_patterns()

        return {
            "length": len(self.path_history),
            "transitions": self._transition_count,
            "initial_state": self.path_history[0] if self.path_history else None,
            "current_state": self.current_state_id,
            "unique_states": len(state_counts),
            "state_counts": state_counts,
            "most_common_state": most_common_state[0],
            "most_common_count": most_common_state[1],
            "repeated_patterns": repeated_patterns
        }

    def _detect_patterns(self) -> List[Tuple[List[int], int]]:
        """
        繰り返しパターンを検出

        Returns:
            (パターン, 出現回数)のリスト
        """
        # 簡易的なパターン検出（実際の実装ではより高度なアルゴリズムを使用）
        patterns = []
        history = self.path_history

        # パターンの最大長（履歴の半分まで）
        max_pattern_len = min(10, len(history) // 2)

        for pattern_len in range(2, max_pattern_len + 1):
            # 最新の状態からパターンを抽出
            if len(history) >= pattern_len * 2:
                latest_pattern = history[-pattern_len:]
                # 直前のパターンと一致するか確認
                if history[-pattern_len*2:-pattern_len] == latest_pattern:
                    # パターンの出現回数をカウント
                    count = 0
                    for i in range(len(history) - pattern_len, -1, -pattern_len):
                        if i >= pattern_len and history[i-pattern_len:i] == latest_pattern:
                            count += 1
                        else:
                            break

                    if count > 1:  # 複数回出現するパターンのみ記録
                        patterns.append((latest_pattern, count))

        return patterns


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


def create_state_matrix_from_key(key: bytes) -> Tuple[Dict[int, State], int, int]:
    """
    鍵から状態マトリクスと初期状態を生成

    Args:
        key: マスター鍵

    Returns:
        (状態辞書, 真情報の初期状態ID, 偽情報の初期状態ID)
    """
    # 入力検証
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("鍵はバイト列で、空であってはなりません")

    # 生成器の作成
    generator = StateMatrixGenerator(key)

    # 状態マトリクスの生成
    states = generator.generate_state_matrix()

    # 初期状態の導出
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
    # 入力値の検証
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("鍵はバイト列で、空であってはなりません")

    if not 0.0 <= bias_factor <= 1.0:
        raise ValueError("バイアス係数は0.0から1.0の間である必要があります")

    # 鍵からバイアスパターンを生成
    # これにより、同じ鍵では同じバイアスパターンとなる
    hash_val = hashlib.sha256(key).digest()

    # numpy配列ではなく標準のPythonリストとして保持（numpy型の問題を回避）
    pattern = [b / 255.0 for b in hash_val]

    # 使用状況を追跡するカウンタ（予測性を低減）
    counter = [0]

    # 一度のハッシュ計算で複数の乱数値を生成し、キャッシュする
    cached_values = []

    def biased_random() -> float:
        """
        バイアスのかかった0.0-1.0の乱数を生成

        Returns:
            バイアスされた乱数
        """
        nonlocal cached_values

        # キャッシュが空の場合、新しい乱数セットを生成
        if not cached_values:
            # カウンタを使用してユニークなシードを生成
            counter[0] += 1
            seed_material = key + counter[0].to_bytes(4, byteorder='big')

            # 追加のエントロピーを混合
            seed_material += os.urandom(8)

            # 新しいハッシュセットを生成
            new_hash = hashlib.sha512(seed_material).digest()

            # 8バイトごとに区切って乱数値を生成（64個の値）
            for i in range(0, len(new_hash), 8):
                if i + 8 <= len(new_hash):
                    # 8バイトを倍精度浮動小数点数の範囲に変換
                    val = int.from_bytes(new_hash[i:i+8], byteorder='big')
                    normalized = (val % 10000) / 10000.0
                    cached_values.append(normalized)

        # キャッシュから値を取得
        base_random = cached_values.pop(0)

        # バイアスパターンのインデックスを決定
        # カウンターとランダム要素を組み合わせて予測を困難に
        index = (counter[0] + int.from_bytes(os.urandom(2), byteorder='big')) % len(pattern)

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
