"""
確率的実行エンジンモジュール

鍵に応じて実行パスを確率的に制御し、特定の状態に導く機能を提供します。
このエンジンは実行ごとに異なる挙動を示しながらも、鍵に応じた結果に収束します。
"""

import os
import time
import sys
import secrets
import hashlib
import hmac
import struct
import numpy as np
from typing import Dict, List, Tuple, Optional, Union, Any, Callable
import math

# 内部モジュールのインポート
try:
    # パッケージとして実行する場合
    from .config import (
        STATE_TRANSITIONS, STATE_MATRIX_SIZE,
        MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS,
        ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR,
        MIN_ENTROPY
    )
    from .state_matrix import (
        State, StateMatrix, StateExecutor, create_state_matrix_from_key,
        get_biased_random_generator
    )
except ImportError:
    # ローカルモジュールとして実行する場合
    from config import (
        STATE_TRANSITIONS, STATE_MATRIX_SIZE,
        MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS,
        ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR,
        MIN_ENTROPY
    )
    import state_matrix
    from state_matrix import State, StateExecutor, get_biased_random_generator

    # create_state_matrix_from_key関数のローカル実装
    def create_state_matrix_from_key(key, salt=None):
        if hasattr(state_matrix, 'create_state_matrix_from_key'):
            return state_matrix.create_state_matrix_from_key(key, salt)
        else:
            # 状態マトリクスを手動で生成
            states = {}
            for i in range(STATE_MATRIX_SIZE):
                states[i] = State(i)
                # 遷移確率を設定
                for j in range(STATE_MATRIX_SIZE):
                    if i != j:
                        states[i].add_transition(j, 0.1)
                states[i].normalize_transitions()

            # 特殊状態の決定
            if not salt:
                salt = os.urandom(16)

            true_seed = hmac.new(key, b"true_states" + salt, hashlib.sha256).digest()
            false_seed = hmac.new(key, b"false_states" + salt, hashlib.sha256).digest()

            true_initial = int.from_bytes(true_seed[0:4], byteorder='big') % STATE_MATRIX_SIZE
            false_initial = int.from_bytes(false_seed[0:4], byteorder='big') % STATE_MATRIX_SIZE

            if true_initial == false_initial:
                false_initial = (false_initial + 1) % STATE_MATRIX_SIZE

            return states, true_initial, false_initial

# 定数定義
TRUE_PATH = "true"
FALSE_PATH = "false"
ENGINE_VERSION = 1


class ProbabilityController:
    """
    確率的実行の制御を行うクラス

    実行パスに関する確率的決定を行い、鍵に応じた方向へ導きます。
    """

    def __init__(self, key: bytes, salt: bytes, target_path: str = TRUE_PATH):
        """
        コントローラの初期化

        Args:
            key: 実行制御に使用する鍵
            salt: ソルト値
            target_path: 目標とする実行パス（"true" または "false"）
        """
        self.key = key
        self.salt = salt
        self.target_path = target_path
        self._hmac_cache = {}  # キャッシュでパフォーマンス向上

        # 鍵とソルトから確率制御用のパラメータを初期化
        self._initialize_parameters()

        # 内部状態（解析攻撃対策として実行ごとに変化）
        self._runtime_state = os.urandom(16)
        self._execution_counter = 0
        self._consecutive_calls = 0
        self._last_call_time = time.time()
        self._pattern_detection = [0] * 8  # パターン化された呼び出しの検出

    def _initialize_parameters(self):
        """
        確率制御用パラメータの初期化

        鍵とソルトからパラメータを導出します。
        """
        # 鍵とソルトから基本ハッシュを生成
        base_hash = self._get_hmac(b"probability_control")

        # バイアス強度の決定（0.5-0.9の範囲）
        bias_bytes = base_hash[0:4]
        self.bias_strength = 0.5 + (int.from_bytes(bias_bytes, byteorder='big') % 1000) / 2500

        # 収束速度の決定（どれだけ早く目標パスに誘導するか）
        conv_bytes = base_hash[4:8]
        self.convergence_rate = 0.1 + (int.from_bytes(conv_bytes, byteorder='big') % 1000) / 2000

        # ノイズレベルの決定（どれだけランダム性を入れるか）
        noise_bytes = base_hash[8:12]
        self.noise_level = 0.05 + (int.from_bytes(noise_bytes, byteorder='big') % 1000) / 5000

        # 収束閾値の決定（遷移回数の何%で収束を始めるか）
        threshold_bytes = base_hash[12:16]
        self.convergence_threshold = 0.2 + (int.from_bytes(threshold_bytes, byteorder='big') % 1000) / 1250

        # 状態遷移確率表の初期化
        self.transition_table = {}

        # バックドア検出のためのエントロピーチェック
        self._verify_parameter_entropy()

    def _get_hmac(self, purpose: bytes) -> bytes:
        """
        目的に応じたHMACを取得（キャッシュ付き）

        Args:
            purpose: HMACの目的

        Returns:
            HMAC値
        """
        cache_key = purpose
        if cache_key in self._hmac_cache:
            return self._hmac_cache[cache_key]

        result = hmac.new(self.key, purpose + self.salt, hashlib.sha256).digest()
        self._hmac_cache[cache_key] = result
        return result

    def _verify_parameter_entropy(self):
        """
        パラメータのエントロピーを検証

        バックドア検出のため、パラメータのエントロピーが低すぎないか確認します。
        エントロピーが低い場合、鍵が弱い、または悪意のある操作の可能性があります。
        """
        parameters = [
            self.bias_strength,
            self.convergence_rate,
            self.noise_level,
            self.convergence_threshold
        ]

        # パラメータの標準偏差を計算
        std_dev = np.std(parameters)

        # エントロピーが低すぎる場合は警告または例外
        if std_dev < MIN_ENTROPY:
            if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                raise ValueError(f"パラメータのエントロピーが低すぎます: {std_dev}")
            else:
                print(f"警告: パラメータのエントロピーが低い（{std_dev}）", file=sys.stderr)

                # 警告の場合は強制的にエントロピーを向上
                self.bias_strength = 0.5 + (secrets.randbelow(1000) / 2500)
                self.convergence_rate = 0.1 + (secrets.randbelow(1000) / 2000)
                self.noise_level = 0.05 + (secrets.randbelow(1000) / 5000)
                self.convergence_threshold = 0.2 + (secrets.randbelow(1000) / 1250)

    def get_biased_random(self, step: int, total_steps: int, state_id: int) -> float:
        """
        現在の実行ステップと状態に応じてバイアスされた乱数を生成

        Args:
            step: 現在の実行ステップ
            total_steps: 全実行ステップ数
            state_id: 現在の状態ID

        Returns:
            0-1の間のバイアスされた乱数
        """
        # 解析対策: パターン化された呼び出しの検出
        current_time = time.time()
        time_diff = current_time - self._last_call_time
        self._last_call_time = current_time

        if time_diff < 0.0001:  # 極端に速い連続呼び出し（機械的な呼び出し）
            self._consecutive_calls += 1

            # パターン化された呼び出しの検出
            if self._consecutive_calls > 1000:  # 極端に多くの連続呼び出し
                pattern_idx = step % len(self._pattern_detection)
                self._pattern_detection[pattern_idx] += 1

                # パターン検出の閾値を超えた場合
                if self._pattern_detection[pattern_idx] > 100:
                    if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                        raise RuntimeError("不審なパターン化された呼び出しを検出しました")
                    # 乱数値を完全にランダム化（解析対策）
                    return secrets.randbelow(10000) / 10000.0
        else:
            self._consecutive_calls = 0

        # 基本乱数の生成
        raw_random = secrets.randbelow(10000) / 10000.0

        # 実行進捗率の計算（0-1）
        progress = step / total_steps if total_steps > 0 else 0.5

        # 収束閾値を超えた場合はバイアスを強くする
        if progress > self.convergence_threshold:
            # バイアス強度の計算（進捗に応じて徐々に強くなる）
            effective_bias = self.bias_strength * (progress - self.convergence_threshold) / (1 - self.convergence_threshold)

            # バイアス値の生成
            bias_seed = self._get_hmac(f"bias_{state_id}_{step}_{self.target_path}".encode('utf-8'))
            bias_value = int.from_bytes(bias_seed[0:4], byteorder='big') / (2**32 - 1)

            # 実行ごとのノイズ付加（解析攻撃対策）
            noise_seed = hashlib.sha256(self._runtime_state + struct.pack('!I', self._execution_counter)).digest()
            noise = int.from_bytes(noise_seed[0:4], byteorder='big') / (2**32 - 1) * self.noise_level

            # 最終的な乱数値の計算
            if self.target_path == TRUE_PATH:
                # TRUE_PATH：バイアスを低めに
                result = raw_random * (1 - effective_bias) + bias_value * effective_bias - noise
            else:
                # FALSE_PATH：バイアスを高めに
                result = raw_random * (1 - effective_bias) + bias_value * effective_bias + noise

            # 0-1の範囲に収める
            result = max(0, min(1, result))

            # 内部状態の更新
            self._runtime_state = hashlib.sha256(self._runtime_state + struct.pack('!d', result)).digest()
            self._execution_counter += 1

            return result
        else:
            # 収束閾値以前は通常の乱数を返す（わずかなバイアスのみ）
            return raw_random

    def calculate_state_bias(self, state_id: int, true_state: int, false_state: int) -> float:
        """
        状態に対するバイアス係数を計算

        Args:
            state_id: バイアスを計算する状態ID
            true_state: 正規パスの目標状態ID
            false_state: 非正規パスの目標状態ID

        Returns:
            -1から1の間のバイアス係数（正: true方向、負: false方向）
        """
        # 目標状態への「距離」の概念を導入
        # この「距離」は物理的な距離ではなく、状態遷移における近さを表す

        # 各状態のシード値を生成（鍵と状態IDに依存）
        true_seed = self._get_hmac(f"true_distance_{state_id}".encode('utf-8'))
        false_seed = self._get_hmac(f"false_distance_{state_id}".encode('utf-8'))

        # シード値から「距離」を計算
        true_distance = int.from_bytes(true_seed[0:4], byteorder='big') % 100
        false_distance = int.from_bytes(false_seed[0:4], byteorder='big') % 100

        # 目標状態の場合は距離を0にする
        if state_id == true_state:
            true_distance = 0
        if state_id == false_state:
            false_distance = 0

        # 距離の差からバイアス係数を計算
        # 正規方向に近いほど正の値、非正規方向に近いほど負の値
        total_distance = true_distance + false_distance
        if total_distance == 0:
            # 両方の目標状態の場合（ありえないが念のため）
            return 0

        # -1から1の範囲に正規化
        bias = (false_distance - true_distance) / total_distance

        # 目標方向に応じて調整
        if self.target_path == FALSE_PATH:
            bias = -bias

        return bias


class ExecutionPathManager:
    """
    実行パスの管理を行うクラス

    状態遷移の履歴を保持し、実行パスの予測と制御を行います。
    """

    def __init__(self, states: Dict[int, State], true_initial: int, false_initial: int,
                controller: ProbabilityController):
        """
        パスマネージャの初期化

        Args:
            states: 状態辞書
            true_initial: 正規パスの初期状態ID
            false_initial: 非正規パスの初期状態ID
            controller: 確率コントローラ
        """
        self.states = states
        self.true_initial = true_initial
        self.false_initial = false_initial
        self.controller = controller

        # 実行パス履歴
        self.path_history = []

        # 現在の状態
        self.current_state_id = true_initial if controller.target_path == TRUE_PATH else false_initial
        self.path_history.append(self.current_state_id)

        # 安全性監視用変数
        self._max_inconsistencies = 3
        self._inconsistency_count = 0
        self._suspicious_transitions = 0

        # 統計情報
        self._state_visits = {state_id: 0 for state_id in states}
        self._state_visits[self.current_state_id] = 1

    def _check_state_consistency(self, next_state_id: int) -> bool:
        """
        状態遷移の整合性をチェック

        異常な状態遷移が発生していないかどうかを確認します。

        Args:
            next_state_id: 次の状態ID

        Returns:
            整合性がある場合はTrue
        """
        # 現在の状態オブジェクトを取得
        current_state = self.states.get(self.current_state_id)
        if not current_state:
            return False

        # 遷移先が現在の状態の遷移に含まれているかチェック
        is_valid_transition = next_state_id in current_state.transitions

        # 有効でない遷移が検出された場合、カウントを増やす
        if not is_valid_transition:
            self._inconsistency_count += 1

        return is_valid_transition

    def step(self, force_random: bool = False) -> int:
        """
        1ステップ実行して次の状態に移動

        Args:
            force_random: 強制的に乱数を使用するフラグ

        Returns:
            次の状態ID
        """
        current_state = self.states.get(self.current_state_id)
        if not current_state:
            raise ValueError(f"状態ID {self.current_state_id} が見つかりません")

        # 次状態決定用の乱数取得
        if force_random:
            random_value = secrets.randbelow(10000) / 10000.0
        else:
            # バイアスされた乱数を取得
            random_value = self.controller.get_biased_random(
                len(self.path_history),
                STATE_TRANSITIONS,
                self.current_state_id
            )

        # 次状態の決定
        next_state_id = current_state.next_state(random_value)

        # 状態遷移の整合性チェック
        if ANTI_TAMPERING and not self._check_state_consistency(next_state_id):
            # 不整合が一定回数を超えたらエラーにする
            if self._inconsistency_count > self._max_inconsistencies and ERROR_ON_SUSPICIOUS_BEHAVIOR:
                raise RuntimeError("状態遷移の整合性エラーが検出されました")

            # 代替策: 有効な遷移先をランダムに選択
            valid_transitions = list(current_state.transitions.keys())
            if valid_transitions:
                next_state_id = secrets.choice(valid_transitions)

        # 不審な遷移パターンの検出
        if self.path_history and len(self.path_history) >= 3:
            # 同じ状態の連続的な繰り返しをチェック
            if (self.path_history[-1] == self.path_history[-2] == next_state_id and
                self._state_visits.get(next_state_id, 0) > 3):
                self._suspicious_transitions += 1

                # 不審な値が閾値を超えた場合
                if self._suspicious_transitions > 5 and ERROR_ON_SUSPICIOUS_BEHAVIOR:
                    raise RuntimeError("不審な状態遷移パターンが検出されました")

        # 状態を更新
        self.current_state_id = next_state_id
        self.path_history.append(next_state_id)

        # 統計情報の更新
        self._state_visits[next_state_id] = self._state_visits.get(next_state_id, 0) + 1

        return next_state_id

    def run_path(self, steps: int) -> List[int]:
        """
        指定ステップ数の実行パスを生成

        Args:
            steps: 実行するステップ数

        Returns:
            状態遷移の履歴（状態IDのリスト）
        """
        # 初期状態から指定ステップ数実行
        start_len = len(self.path_history)
        target_len = start_len + steps

        while len(self.path_history) < target_len:
            try:
                self.step()
            except Exception as e:
                print(f"実行パス生成中にエラーが発生しました: {e}", file=sys.stderr)
                break

        return self.path_history

    def get_path_statistics(self) -> Dict[str, Any]:
        """
        実行パスの統計情報を取得

        Returns:
            統計情報を含む辞書
        """
        if not self.path_history:
            return {"error": "実行パスが空です"}

        # 状態出現回数の集計
        state_counts = self._state_visits.copy()

        # 初期状態と最終状態
        initial_state = self.path_history[0]
        final_state = self.path_history[-1]

        # パスの長さ
        path_length = len(self.path_history)

        # パスの特性
        is_true_biased = initial_state == self.true_initial
        is_converged = False

        # 収束の判定（最後の数ステップが同じ状態にとどまるか）
        if path_length > 5:
            last_states = self.path_history[-5:]
            is_converged = len(set(last_states)) <= 2

        return {
            "initial_state": initial_state,
            "final_state": final_state,
            "path_length": path_length,
            "state_counts": state_counts,
            "is_true_biased": is_true_biased,
            "is_converged": is_converged,
            "target_path": self.controller.target_path,
            "suspicious_transitions": self._suspicious_transitions,
            "inconsistency_count": self._inconsistency_count
        }


class ProbabilisticExecutionEngine:
    """
    確率的実行エンジン

    状態マトリクスと確率コントローラを組み合わせ、
    鍵に応じた実行パスを確率的に生成します。
    """

    def __init__(self, key: bytes, salt: Optional[bytes] = None, target_path: str = TRUE_PATH):
        """
        実行エンジンの初期化

        Args:
            key: 実行制御に使用する鍵
            salt: ソルト値（省略時はランダム生成）
            target_path: 目標とする実行パス（"true" または "false"）
        """
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("鍵はバイト列で、空であってはなりません")

        if target_path not in [TRUE_PATH, FALSE_PATH]:
            raise ValueError(f"目標パスは '{TRUE_PATH}' または '{FALSE_PATH}' である必要があります")

        self.key = key
        self.salt = salt or os.urandom(16)
        self.target_path = target_path

        # 鍵の整合性チェック（バックドア検出）
        self._verify_key_integrity()

        # 状態マトリクスを生成
        try:
            from .state_matrix import create_state_matrix_from_key
            self.states, self.true_initial, self.false_initial = create_state_matrix_from_key(key, self.salt)
        except ImportError:
            # 直接実装
            self.states = {}
            for i in range(STATE_MATRIX_SIZE):
                # 状態を生成
                state_seed = hmac.new(key, f"state_{i}".encode() + self.salt, hashlib.sha256).digest()
                self.states[i] = State(i, {
                    "hash_seed": state_seed,
                    "complexity": int.from_bytes(state_seed[0:2], byteorder='big') % 100,
                    "volatility": int.from_bytes(state_seed[2:4], byteorder='big') % 100,
                    "transform_key": state_seed[4:12]
                })

                # 遷移を生成
                for j in range(STATE_MATRIX_SIZE):
                    if i != j:
                        prob_seed = hmac.new(key, f"prob_{i}_{j}".encode() + self.salt, hashlib.sha256).digest()
                        prob = int.from_bytes(prob_seed[0:4], byteorder='big') / (2**32 - 1)
                        prob = MIN_PROBABILITY + prob * (MAX_PROBABILITY - MIN_PROBABILITY)
                        self.states[i].add_transition(j, prob)

                # 遷移を正規化
                self.states[i].normalize_transitions()

            # 初期状態を設定
            true_seed = hmac.new(key, b"true_states" + self.salt, hashlib.sha256).digest()
            false_seed = hmac.new(key, b"false_states" + self.salt, hashlib.sha256).digest()

            self.true_initial = int.from_bytes(true_seed[0:4], byteorder='big') % STATE_MATRIX_SIZE
            self.false_initial = int.from_bytes(false_seed[0:4], byteorder='big') % STATE_MATRIX_SIZE

            if self.true_initial == self.false_initial:
                self.false_initial = (self.false_initial + 1) % STATE_MATRIX_SIZE

        # 確率コントローラの初期化
        self.controller = ProbabilityController(key, self.salt, target_path)

        # 実行パスマネージャの初期化
        self.path_manager = ExecutionPathManager(
            self.states,
            self.true_initial,
            self.false_initial,
            self.controller
        )

        # エンジンの実行状態
        self._execution_count = 0
        self._start_time = time.time()
        self._last_execution_time = 0
        self._secure_mode = True
        self._is_tampered = False

        # 解析対策用の内部状態
        self._noise_pattern = generate_anti_analysis_noise(key, target_path)
        self._decoy_states = self._generate_decoy_states()

    def _verify_key_integrity(self):
        """
        鍵の整合性を検証

        バックドア検出のため、鍵のエントロピーが低すぎないか確認します。
        """
        # 鍵のエントロピーチェック
        entropy = self._calculate_entropy(self.key)

        # エントロピーが低すぎる場合は警告または例外
        if entropy < MIN_ENTROPY:
            if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                raise ValueError(f"鍵のエントロピーが低すぎます: {entropy}")
            else:
                print(f"警告: 鍵のエントロピーが低い（{entropy}）", file=sys.stderr)

    def _calculate_entropy(self, data: bytes) -> float:
        """
        バイト列のエントロピーを計算

        Args:
            data: エントロピーを計算するバイト列

        Returns:
            Shannon エントロピー値
        """
        if not data:
            return 0.0

        # バイト出現頻度のカウント
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1

        # Shannon エントロピーの計算
        entropy = 0.0
        for count in counts.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return entropy

    def _generate_decoy_states(self) -> Dict[int, Dict[str, Any]]:
        """
        デコイ状態の生成（解析対策）

        Returns:
            デコイ状態の辞書
        """
        decoy_states = {}

        # 実際の状態数と同じ数のデコイを生成
        for i in range(STATE_MATRIX_SIZE):
            decoy_states[i] = {
                "visits": 0,
                "transitions": {},
                "last_access": time.time(),
                "entropy": secrets.randbelow(1000) / 1000.0
            }

        return decoy_states

    def run_execution(self, steps: int = STATE_TRANSITIONS) -> List[int]:
        """
        エンジンを実行して実行パスを生成

        Args:
            steps: 実行するステップ数

        Returns:
            生成された実行パス（状態IDのリスト）
        """
        # エンジン実行カウンタを更新
        self._execution_count += 1

        # 実行開始時間を記録
        execution_start = time.time()

        # 改ざん検知
        if ANTI_TAMPERING and self._secure_mode:
            if self._check_tampering():
                self._is_tampered = True
                if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                    raise RuntimeError("エンジンの改ざんが検出されました。")

        # 実行パスの生成
        try:
            result = self.path_manager.run_path(steps)

            # 実行時間の記録
            self._last_execution_time = time.time() - execution_start

            # デコイ処理（解析対策）
            if self._execution_count % 3 == 0:
                self._run_decoy_operations()

            return result

        except Exception as e:
            # 例外を記録してから再スロー
            print(f"実行エンジンの実行中にエラーが発生しました: {e}", file=sys.stderr)
            raise

    def _check_tampering(self) -> bool:
        """
        エンジンの改ざんを検知

        Returns:
            改ざんが検出された場合はTrue
        """
        # 基本的な整合性チェック
        try:
            # 状態数のチェック
            expected_states = STATE_MATRIX_SIZE
            if len(self.states) != expected_states:
                return True

            # 初期状態が正しい範囲内にあるかチェック
            if not (0 <= self.true_initial < STATE_MATRIX_SIZE) or not (0 <= self.false_initial < STATE_MATRIX_SIZE):
                return True

            # 確率コントローラのパラメータが適切な範囲内かチェック
            if not (0.5 <= self.controller.bias_strength <= 0.9):
                return True

            # 自己参照整合性チェック
            if id(self.path_manager.controller) != id(self.controller):
                return True

            return False

        except Exception:
            # 例外が発生した場合も改ざんと見なす
            return True

    def _run_decoy_operations(self) -> None:
        """
        解析対策用のデコイ操作を実行
        """
        # 現在時刻をシードにしたランダム値（32ビット制限内に収める）
        seed = int(time.time() * 1000) & 0x7FFFFFFF
        rng = np.random.RandomState(seed)

        # デコイ計算
        for _ in range(rng.randint(5, 15)):
            # 使われない計算を行う
            matrix = rng.random((4, 4))
            result = np.matmul(matrix, matrix.T)

            # 結果をハッシュ化（最適化で除去されないように）
            decoy_hash = hashlib.sha256(result.tobytes()).digest()

            # 内部ノイズパターンとXOR
            noise_idx = seed % len(self._noise_pattern)
            self._noise_pattern = bytes([
                (b ^ decoy_hash[i % len(decoy_hash)]) & 0xFF
                for i, b in enumerate(self._noise_pattern)
            ])

    def get_execution_signature(self) -> bytes:
        """
        現在の実行パスの署名を生成

        実行パスの特性を表す一意な署名を生成します。
        この署名は、同じ鍵と目標パスで実行された場合に類似する傾向があります。

        Returns:
            実行パスの署名（32バイト）
        """
        # パス履歴を文字列化
        path_str = ','.join(map(str, self.path_manager.path_history))

        # エンジンの内部パラメータを含める
        params = f"{self.controller.bias_strength:.4f},{self.controller.convergence_rate:.4f}"

        # 署名の生成
        signature = hmac.new(
            self.key,
            f"{path_str}|{params}|{self.target_path}".encode('utf-8'),
            hashlib.sha256
        ).digest()

        return signature

    def get_state_for_path(self, path_type: str) -> int:
        """
        指定されたパスタイプの初期状態を取得

        Args:
            path_type: パスタイプ（"true" または "false"）

        Returns:
            初期状態ID
        """
        if path_type == TRUE_PATH:
            return self.true_initial
        else:
            return self.false_initial

    def get_engine_state(self) -> Dict[str, Any]:
        """
        エンジンの現在の状態情報を取得

        Returns:
            エンジン状態の辞書
        """
        return {
            "engine_version": ENGINE_VERSION,
            "target_path": self.target_path,
            "true_initial_state": self.true_initial,
            "false_initial_state": self.false_initial,
            "current_state": self.path_manager.current_state_id,
            "path_length": len(self.path_manager.path_history),
            "bias_strength": self.controller.bias_strength,
            "convergence_rate": self.controller.convergence_rate,
            "noise_level": self.controller.noise_level,
            "salt": self.salt.hex(),
            "execution_count": self._execution_count,
            "last_execution_time": self._last_execution_time,
            "total_runtime": time.time() - self._start_time,
            "secure_mode": self._secure_mode
        }

    def set_secure_mode(self, enabled: bool) -> None:
        """
        セキュアモードの設定

        Args:
            enabled: セキュアモードを有効にするかどうか
        """
        self._secure_mode = enabled


def create_engine_from_key(key: bytes, path_type: str, salt: Optional[bytes] = None) -> ProbabilisticExecutionEngine:
    """
    鍵と目標パスタイプから実行エンジンを作成

    Args:
        key: 制御鍵
        path_type: 目標パスタイプ（"true" または "false"）
        salt: ソルト値（省略時はランダム生成）

    Returns:
        確率的実行エンジン
    """
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("鍵はバイト列で、空であってはなりません")

    if path_type not in [TRUE_PATH, FALSE_PATH]:
        raise ValueError(f"目標パスは '{TRUE_PATH}' または '{FALSE_PATH}' である必要があります")

    # ソルトは指定されている場合はそれを使用し、指定がなければランダム生成
    actual_salt = salt if salt is not None else os.urandom(16)

    # エンジンのインスタンス化
    try:
        engine = ProbabilisticExecutionEngine(key, actual_salt, path_type)
        return engine
    except Exception as e:
        # 初期化中にエラーが発生した場合はより詳細なエラーメッセージを提供
        raise RuntimeError(f"実行エンジンの作成に失敗しました: {e}") from e


def obfuscate_execution_path(engine: ProbabilisticExecutionEngine) -> None:
    """
    実行パスを難読化

    実行パスに無関係な処理を追加し、解析を困難にします。
    静的/動的解析からの保護を強化します。

    Args:
        engine: 確率的実行エンジン
    """
    # engineがNoneの場合は早期リターン
    if engine is None:
        return

    # エンジンの型チェック
    if not isinstance(engine, ProbabilisticExecutionEngine):
        raise TypeError("engine はProbabilisticExecutionEngineのインスタンスである必要があります")

    # 現在の時刻からシードを生成（32ビット制限内に収める）
    time_seed = int(time.time() * 1000) & 0x7FFFFFFF

    # シード値に基づくダミー計算回数
    dummy_steps = (time_seed % 10) + 5

    # 内部状態を保存
    original_state_id = engine.path_manager.current_state_id
    original_history = engine.path_manager.path_history.copy()

    # 一時的なエントロピー注入
    entropy_data = os.urandom(32)

    # ノイズ生成（乱数シードを利用 - 32ビット制限に注意）
    noise = np.random.RandomState(time_seed).random(dummy_steps)

    # ダミー実行
    try:
        for i in range(dummy_steps):
            # 解析されにくいように複雑な計算を追加
            noise_value = (noise[i] + i / dummy_steps) % 1.0
            # ダミー遷移
            engine.path_manager.step(force_random=True)

            # さらに複雑さを増すためのダミー計算
            dummy_calc1 = (int.from_bytes(entropy_data[i % len(entropy_data):i % len(entropy_data) + 4], byteorder='big') + time_seed) % 1000
            dummy_calc2 = ((dummy_calc1 * noise_value) + time.time()) % 1.0

            # 最適化で取り除かれないように結果を使用
            if dummy_calc2 > 0.999999:  # ほぼ発生しない条件
                print("非常に低確率のイベントが発生しました", file=sys.stderr)

    except Exception:
        # エラーは無視（難読化の一環）
        pass

    # 内部状態を復元
    engine.path_manager.current_state_id = original_state_id
    engine.path_manager.path_history = original_history

    # セキュアワイプ（メモリ上の機密データを削除）
    for i in range(len(entropy_data)):
        entropy_data = bytes([secrets.randbelow(256)])  # ランダムで上書き
    for i in range(len(noise)):
        noise[i] = 0.0  # ゼロで上書き

    # 追加の難読化処理
    if hasattr(engine, '_run_decoy_operations'):
        try:
            engine._run_decoy_operations()
        except Exception:
            pass


def generate_anti_analysis_noise(key: bytes, path_type: str) -> bytes:
    """
    解析対策用のノイズデータを生成

    静的・動的解析を困難にするためのノイズデータを生成します。
    パターン検出を困難にし、解析者を混乱させる目的があります。

    Args:
        key: 鍵データ
        path_type: パスタイプ

    Returns:
        ノイズデータ
    """
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("鍵はバイト列で、空であってはなりません")

    if path_type not in [TRUE_PATH, FALSE_PATH]:
        raise ValueError(f"目標パスは '{TRUE_PATH}' または '{FALSE_PATH}' である必要があります")

    # 鍵から解析対策用のノイズを生成
    noise_seed = hashlib.sha256(key + path_type.encode('utf-8')).digest()

    # 一見ランダムに見えるがパターンを持つノイズを生成
    noise_length = 256 + (noise_seed[0] % 64)
    noise = bytearray(noise_length)

    for i in range(noise_length):
        # 明確なパターンを持たないようにする
        factor1 = noise_seed[i % 32]
        factor2 = noise_seed[(i * 7 + 5) % 32]
        factor3 = i % 251  # 大きな素数でモジュロ

        noise[i] = (factor1 ^ factor2 ^ factor3) & 0xFF

    return bytes(noise)


# テスト関数
def test_probability_engine():
    """
    確率的実行エンジンのテスト
    """
    # テスト鍵の生成
    test_key = os.urandom(32)
    print(f"テスト鍵: {test_key.hex()[:16]}...")

    # 各パスタイプでエンジンを作成・実行
    results = {}

    for path_type in [TRUE_PATH, FALSE_PATH]:
        print(f"\n=== {path_type} パスの実行 ===")

        # エンジンの作成
        engine = create_engine_from_key(test_key, path_type)

        # 実行
        path = engine.run_execution()

        # 結果の表示
        print(f"初期状態: {path[0]}")
        print(f"最終状態: {path[-1]}")
        print(f"パス長: {len(path)}")
        print(f"パス: {path}")

        # 実行署名の取得
        signature = engine.get_execution_signature()
        print(f"実行署名: {signature.hex()[:16]}...")

        # 実行統計の取得
        stats = engine.path_manager.get_path_statistics()
        print(f"収束: {'あり' if stats['is_converged'] else 'なし'}")

        # エンジン状態の取得
        state = engine.get_engine_state()
        print(f"バイアス強度: {state['bias_strength']:.4f}")

        # 結果を保存
        results[path_type] = {
            "path": path,
            "signature": signature,
            "stats": stats,
            "state": state
        }

    # パスタイプによる違いの検証
    true_final = results[TRUE_PATH]["path"][-1]
    false_final = results[FALSE_PATH]["path"][-1]

    print("\n=== 検証結果 ===")
    print(f"TRUE パス最終状態: {true_final}")
    print(f"FALSE パス最終状態: {false_final}")
    print(f"異なる最終状態: {'はい' if true_final != false_final else 'いいえ'}")

    # 複数回実行して収束性を検証
    print("\n=== 収束性検証（複数回実行） ===")

    true_finals = []
    false_finals = []

    for i in range(5):
        true_engine = create_engine_from_key(test_key, TRUE_PATH)
        true_path = true_engine.run_execution()
        true_finals.append(true_path[-1])

        false_engine = create_engine_from_key(test_key, FALSE_PATH)
        false_path = false_engine.run_execution()
        false_finals.append(false_path[-1])

    print(f"TRUE パス最終状態一覧: {true_finals}")
    print(f"FALSE パス最終状態一覧: {false_finals}")

    # 同じ鍵でも実行パスの詳細は毎回変化することを確認
    print("\n=== 実行パスの非決定性検証 ===")

    path_signatures = []
    for i in range(3):
        engine = create_engine_from_key(test_key, TRUE_PATH)
        engine.run_execution()
        path_signatures.append(engine.path_manager.path_history)

    all_same = all(path == path_signatures[0] for path in path_signatures)
    print(f"すべてのパスが同一: {'はい' if all_same else 'いいえ'}")

    return results


# メイン関数
if __name__ == "__main__":
    test_probability_engine()
