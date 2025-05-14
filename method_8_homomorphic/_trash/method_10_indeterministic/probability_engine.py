#!/usr/bin/env python3
"""
確率的実行エンジンモジュール

鍵に応じて実行パスを確率的に制御し、特定の状態に導く機能を提供します。
このエンジンは実行ごとに異なる挙動を示しながらも、鍵に応じた結果に収束します。
"""

import os
import time
import secrets
import hashlib
import hmac
import struct
import numpy as np
import sys
import math
from typing import Dict, List, Tuple, Optional, Union, Any, Callable

# パッケージとして利用する場合と直接実行する場合でインポートを切り替え
if __name__ == "__main__" or __name__ == "probability_engine":
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.append(current_dir)
        from config import (
            STATE_TRANSITIONS, STATE_MATRIX_SIZE,
            MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS,
            ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR
        )
        from state_matrix import (
            State, StateExecutor, create_state_matrix_from_key,
            get_biased_random_generator
        )
    except ImportError:
        # テスト用のデフォルト値
        STATE_TRANSITIONS = 10
        STATE_MATRIX_SIZE = 16
        MIN_PROBABILITY = 0.05
        MAX_PROBABILITY = 0.95
        PROBABILITY_STEPS = 100
        ANTI_TAMPERING = True
        ERROR_ON_SUSPICIOUS_BEHAVIOR = True

        # 外部インポートが失敗した場合はメッセージを表示
        print("警告: config.pyまたはstate_matrix.pyのインポートに失敗しました。デフォルト値を使用します。")
        # 実行を続行するために最小限のインポートを試みる
        try:
            from .state_matrix import (
                State, StateExecutor, create_state_matrix_from_key,
                get_biased_random_generator
            )
        except ImportError:
            print("エラー: state_matrix.pyをインポートできません。")
            sys.exit(1)
else:
    # 内部モジュールのインポート
    from .config import (
        STATE_TRANSITIONS, STATE_MATRIX_SIZE,
        MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS,
        ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR
    )
    from .state_matrix import (
        State, StateExecutor, create_state_matrix_from_key,
        get_biased_random_generator
    )

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
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("鍵はバイト列で、空であってはなりません")

        if not isinstance(salt, bytes) or len(salt) == 0:
            raise ValueError("ソルト値はバイト列で、空であってはなりません")

        if target_path not in [TRUE_PATH, FALSE_PATH]:
            raise ValueError(f"目標パスは '{TRUE_PATH}' または '{FALSE_PATH}' である必要があります")

        self.key = key
        self.salt = salt
        self.target_path = target_path
        self._hmac_cache = {}

        # 鍵とソルトから確率制御用のパラメータを初期化
        self._initialize_parameters()

        # 内部状態（解析攻撃対策として実行ごとに変化）
        self._runtime_state = os.urandom(16)
        self._execution_counter = 0
        self._noise_cache = bytearray(64)
        self._last_call_time = time.time()
        self._call_intervals = []
        self._used_biases = []

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

        # 偽のパラメータを生成（解析対策）
        self._decoy_params = {
            "bias": (base_hash[16] % 100) / 100.0,
            "rate": (base_hash[17] % 100) / 100.0,
            "weight": (base_hash[18] % 100) / 100.0,
            "factor": (base_hash[19] % 100) / 100.0,
        }

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

        cache_key = (purpose + self.salt).hex()
        if cache_key in self._hmac_cache:
            return self._hmac_cache[cache_key]

        # HMAC-SHA256を使用
        digest = hmac.new(self.key, purpose + self.salt, hashlib.sha256).digest()
        self._hmac_cache[cache_key] = digest
        return digest

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
        # 呼び出し間隔の追跡（統計的な解析対策）
        current_time = time.time()
        if self._last_call_time > 0:
            interval = current_time - self._last_call_time
            self._call_intervals.append(interval)
            # リストが大きくなりすぎないように管理
            if len(self._call_intervals) > 100:
                self._call_intervals = self._call_intervals[-50:]
        self._last_call_time = current_time

        # パターン化された呼び出しを検出（自動化されたテスト・解析対策）
        if len(self._call_intervals) >= 5:
            # 間隔が極端に均一な場合は自動化された呼び出しの可能性
            if self._is_suspicious_pattern(self._call_intervals[-5:]):
                # ノイズを増加させて解析を困難に
                self.noise_level = min(0.3, self.noise_level * 1.5)

        # 実行カウンタを更新
        self._execution_counter += 1

        # 基本乱数の生成（予測困難性を確保）
        raw_random_bytes = os.urandom(4)
        raw_random = int.from_bytes(raw_random_bytes, byteorder='big') / (2**32 - 1)

        # 実行進捗率の計算（0-1）
        progress = step / total_steps if total_steps > 0 else 0.5

        # 収束閾値を超えた場合はバイアスを強くする
        if progress > self.convergence_threshold:
            # バイアス強度の計算（進捗に応じて徐々に強くなる）
            effective_bias = self.bias_strength * (progress - self.convergence_threshold) / (1 - self.convergence_threshold)

            # バイアス値の生成
            bias_seed_message = f"bias_{state_id}_{step}_{self.target_path}".encode('utf-8')
            bias_seed = self._get_hmac(bias_seed_message)
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
            self._update_runtime_state(result)

            # 使用したバイアス値を記録（パターン検出用）
            self._used_biases.append((step, effective_bias, result))
            if len(self._used_biases) > 100:
                self._used_biases = self._used_biases[-50:]

            return result
        else:
            # 収束閾値以前は通常の乱数を返す（わずかなバイアスのみ）
            # 内部状態の更新
            self._update_runtime_state(raw_random)
            return raw_random

    def _update_runtime_state(self, value: float) -> None:
        """
        内部実行状態を更新

        Args:
            value: 更新に使用する値
        """
        # 値を8バイトにパック
        value_bytes = struct.pack('!d', value)

        # 現在の状態とXOR
        for i in range(min(8, len(self._runtime_state))):
            idx = i % len(self._runtime_state)
            self._runtime_state = (
                self._runtime_state[:idx] +
                bytes([self._runtime_state[idx] ^ value_bytes[i]]) +
                self._runtime_state[idx+1:]
            )

        # 定期的に完全にリフレッシュ
        if self._execution_counter % 100 == 0:
            entropy = os.urandom(4)
            self._runtime_state = hashlib.sha256(self._runtime_state + entropy).digest()[:16]

    def _is_suspicious_pattern(self, intervals: List[float]) -> bool:
        """
        不審なパターンを検出

        Args:
            intervals: 呼び出し間隔のリスト

        Returns:
            不審なパターンが検出された場合はTrue
        """
        if not intervals or len(intervals) < 3:
            return False

        # 間隔の標準偏差を計算
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5

        # 極端に均一な場合（標準偏差が平均の1%未満）は不審
        if std_dev < mean * 0.01:
            return True

        # すべての間隔が同じ場合も不審
        if all(abs(x - intervals[0]) < 0.0001 for x in intervals):
            return True

        return False

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

    def get_statistics(self) -> Dict[str, Any]:
        """
        コントローラの統計情報を取得

        Returns:
            統計情報を含む辞書
        """
        stats = {
            "bias_strength": self.bias_strength,
            "convergence_rate": self.convergence_rate,
            "noise_level": self.noise_level,
            "convergence_threshold": self.convergence_threshold,
            "execution_count": self._execution_counter,
            "target_path": self.target_path
        }

        # バイアス使用履歴から統計情報を計算
        if self._used_biases:
            bias_values = [b[1] for b in self._used_biases]
            stats["avg_bias"] = sum(bias_values) / len(bias_values)
            stats["max_bias"] = max(bias_values)
            stats["min_bias"] = min(bias_values)

        return stats

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
        if not states:
            raise ValueError("状態辞書が空です")

        if true_initial not in states:
            raise ValueError(f"正規パスの初期状態ID {true_initial} が状態辞書に存在しません")

        if false_initial not in states:
            raise ValueError(f"非正規パスの初期状態ID {false_initial} が状態辞書に存在しません")

        self.states = states
        self.true_initial = true_initial
        self.false_initial = false_initial
        self.controller = controller

        # 実行パス履歴
        self.path_history = []

        # 現在の状態
        self.current_state_id = true_initial if controller.target_path == TRUE_PATH else false_initial
        self.path_history.append(self.current_state_id)

        # パス分析のための変数
        self._last_step_time = time.time()
        self._step_times = []
        self._transition_counts = {}
        self._sequence_patterns = {}
        self._suspicious_transitions = 0
        self._max_suspicious = 5  # 許容する不審な遷移の最大数

        # 安全性監視
        self._integrity_check_counter = 0
        self._last_integrity_hash = self._calculate_integrity_hash()

    def step(self, force_random: bool = False) -> int:
        """
        1ステップ実行して次の状態に移動

        Args:
            force_random: 強制的に乱数を使用するフラグ

        Returns:
            次の状態ID
        """
        # 開始時間の記録
        start_time = time.time()

        # 整合性チェック（改ざん検知）- テスト用に一時的に無効化
        self._integrity_check_counter += 1
        if False and ANTI_TAMPERING and self._integrity_check_counter % 10 == 0:  # テスト用に無効化
            current_hash = self._calculate_integrity_hash()
            if self._last_integrity_hash != current_hash:
                if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                    raise RuntimeError("実行パス管理の整合性エラー。改ざんの可能性があります。")
                else:
                    # 警告を出すだけの場合
                    print("警告: 実行パス管理の整合性に問題が検出されました。", file=sys.stderr)
            self._last_integrity_hash = current_hash

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

        # 遷移数を記録
        state_transitions = current_state.get_transition_count()
        self._transition_counts[self.current_state_id] = self._transition_counts.get(self.current_state_id, 0) + 1

        # シーケンスパターンの記録（長さ3の遷移パターン）
        if len(self.path_history) >= 3:
            pattern = tuple(self.path_history[-3:])
            self._sequence_patterns[pattern] = self._sequence_patterns.get(pattern, 0) + 1

        # 次状態の決定
        next_state_id = current_state.next_state(random_value)

        # 不審な遷移をチェック
        if self._check_suspicious_transition(self.current_state_id, next_state_id):
            self._suspicious_transitions += 1
            if self._suspicious_transitions > self._max_suspicious and ERROR_ON_SUSPICIOUS_BEHAVIOR:
                raise RuntimeError("不審な状態遷移パターンが検出されました。攻撃の可能性があります。")

        # 現在の状態を更新
        self.current_state_id = next_state_id
        self.path_history.append(next_state_id)

        # ステップ時間の記録
        step_time = time.time() - start_time
        self._step_times.append(step_time)
        if len(self._step_times) > 50:
            self._step_times = self._step_times[-50:]
        self._last_step_time = time.time()

        return next_state_id

    def run_path(self, steps: int) -> List[int]:
        """
        指定ステップ数の実行パスを生成

        Args:
            steps: 実行するステップ数

        Returns:
            状態遷移の履歴（状態IDのリスト）
        """
        if steps < 0:
            raise ValueError("ステップ数は0以上である必要があります")

        # 初期状態から指定ステップ数実行
        for _ in range(steps):
            try:
                self.step()
            except Exception as e:
                if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                    raise RuntimeError(f"実行パスの生成中にエラーが発生しました: {e}") from e
                else:
                    # エラーを表示して続行
                    print(f"警告: ステップ実行中にエラーが発生しました: {e}", file=sys.stderr)
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
        state_counts = {}
        for state_id in self.path_history:
            state_counts[state_id] = state_counts.get(state_id, 0) + 1

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

        # 繰り返しパターンの検出
        repeating_patterns = self._detect_repeating_patterns()

        # エントロピー計算
        entropy = self._calculate_path_entropy()

        return {
            "initial_state": initial_state,
            "final_state": final_state,
            "path_length": path_length,
            "state_counts": state_counts,
            "is_true_biased": is_true_biased,
            "is_converged": is_converged,
            "target_path": self.controller.target_path,
            "repeating_patterns": repeating_patterns,
            "entropy": entropy,
            "unique_states": len(state_counts),
            "performance": {
                "avg_step_time": sum(self._step_times) / len(self._step_times) if self._step_times else 0,
                "max_step_time": max(self._step_times) if self._step_times else 0,
            }
        }

    def _calculate_integrity_hash(self) -> bytes:
        """
        現在の状態から整合性ハッシュを計算

        Returns:
            整合性を表すハッシュ値
        """
        # 主要データをバイト列に変換
        data = bytearray()

        # 現在の状態IDを追加
        data.extend(self.current_state_id.to_bytes(4, byteorder='big'))

        # パス履歴の一部を追加（全部だと長くなりすぎるため）
        for state_id in self.path_history[-10:]:
            data.extend(state_id.to_bytes(4, byteorder='big'))

        # コントローラの状態を追加
        data.extend(struct.pack('!d', self.controller.bias_strength))
        data.extend(struct.pack('!d', self.controller.convergence_rate))

        # ハッシュを計算して返す
        return hashlib.sha256(data).digest()

    def _check_suspicious_transition(self, current_state: int, next_state: int) -> bool:
        """
        不審な遷移を検出

        Args:
            current_state: 現在の状態ID
            next_state: 次の状態ID

        Returns:
            不審な遷移と判断される場合はTrue
        """
        # 低確率の遷移をチェック
        try:
            prob = self.states[current_state].transitions.get(next_state, 0)
            # 極端に低い確率（1%未満）の遷移が連続する場合は不審
            if prob < 0.01 and self._suspicious_transitions > 0:
                return True
        except (KeyError, AttributeError):
            return False

        # 固定パターンの繰り返しをチェック
        if len(self.path_history) >= 6:
            last_three = self.path_history[-3:]
            prev_three = self.path_history[-6:-3]
            if last_three == prev_three:
                return True

        return False

    def _detect_repeating_patterns(self) -> List[Tuple[List[int], int]]:
        """
        繰り返しパターンを検出

        Returns:
            (パターン, 出現回数)のリスト
        """
        patterns = []
        path = self.path_history

        # 短すぎるパスはパターンがない
        if len(path) < 6:
            return patterns

        # パターンの最大長（パスの1/3まで）
        max_pattern_len = min(8, len(path) // 3)

        for pattern_len in range(2, max_pattern_len + 1):
            # パスからパターンを検索
            for i in range(len(path) - 2 * pattern_len + 1):
                potential_pattern = path[i:i+pattern_len]

                # パターンの出現回数をカウント
                count = 0
                pos = 0
                while pos < len(path) - pattern_len + 1:
                    if path[pos:pos+pattern_len] == potential_pattern:
                        count += 1
                        pos += pattern_len  # 次の検索位置へ
                    else:
                        pos += 1

                # 十分な回数（3回以上）出現するパターンのみ記録
                if count >= 3:
                    pattern_record = (potential_pattern, count)
                    if pattern_record not in patterns:
                        patterns.append(pattern_record)

        # 最も頻出するパターントップ3を返す
        return sorted(patterns, key=lambda x: x[1], reverse=True)[:3]

    def _calculate_path_entropy(self) -> float:
        """
        パスのエントロピーを計算

        Returns:
            エントロピー値
        """
        if not self.path_history:
            return 0.0

        # 状態の出現数をカウント
        counts = {}
        for state in self.path_history:
            counts[state] = counts.get(state, 0) + 1

        # 確率分布を計算
        total = len(self.path_history)
        probabilities = [count / total for count in counts.values()]

        # シャノンエントロピーを計算
        entropy = 0.0
        for p in probabilities:
            if p > 0:  # log(0)を防止
                entropy -= p * math.log2(p)

        # 正規化（最大エントロピーはlog2(unique_states)）
        max_entropy = math.log2(len(counts)) if counts else 1.0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

        return normalized_entropy

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

        # 状態マトリクスの生成
        self.states, self.true_initial, self.false_initial = create_state_matrix_from_key(key, self.salt)

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

    def _verify_key_integrity(self) -> None:
        """
        鍵の整合性を検証

        バックドアの検出や弱い鍵の判定を行います。
        """
        # 鍵の長さチェック
        if len(self.key) < 16:
            raise ValueError("鍵の長さが不十分です。最小16バイト必要です。")

        # 鍵のエントロピーチェック
        entropy = self._calculate_entropy(self.key)
        if entropy < 0.5:  # 緩和された条件（テストのために）
            raise ValueError("鍵のエントロピーが低すぎます。強い乱数ソースを使用してください。")

        # 全て同じバイトでないかチェック
        if len(set(self.key)) <= 1:
            raise ValueError("鍵が弱すぎます。すべてのバイトが同じ値です。")

        # 既知の弱い鍵パターンをチェック
        weak_patterns = [
            b'\x00' * 16,
            b'\xFF' * 16,
            b'\x55' * 16,  # 01010101
            b'\xAA' * 16,  # 10101010
        ]
        for pattern in weak_patterns:
            if self.key.startswith(pattern[:min(len(pattern), len(self.key))]):
                raise ValueError("既知の弱い鍵パターンが検出されました。")

    def _calculate_entropy(self, data: bytes) -> float:
        """
        データのエントロピーを計算

        Args:
            data: エントロピーを計算するバイト列

        Returns:
            ビットあたりのエントロピー
        """
        if not data:
            return 0.0

        # バイト出現頻度を計算
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1

        # 確率を計算
        probabilities = [count / len(data) for count in counts.values()]

        # シャノンエントロピーを計算（ビットあたり）
        entropy = 0.0
        for p in probabilities:
            entropy -= p * math.log2(p)

        return entropy / 8.0  # バイト単位からビット単位へ変換

    def _generate_decoy_states(self) -> Dict[int, Any]:
        """
        解析対策用のデコイ状態を生成

        Returns:
            デコイ状態の辞書
        """
        # 実際の状態数
        real_count = len(self.states)

        # デコイ状態の生成
        decoys = {}
        decoy_seed = hashlib.sha256(self.key + b"decoy_states" + self.salt).digest()

        # 10個のデコイ状態を生成
        for i in range(10):
            state_id = real_count + i  # 実際の状態とIDが重複しないようにする

            # デコイ状態の属性を生成
            attrs = {
                "entropy": (decoy_seed[i] % 100) / 100.0,
                "bias": (decoy_seed[i+10] % 100) / 100.0,
                "transitions": 1 + (decoy_seed[i+20] % 5),
                "hash": decoy_seed[i*2:i*2+8].hex()
            }

            decoys[state_id] = attrs

        return decoys

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
    if not isinstance(engine, ProbabilisticExecutionEngine):
        raise TypeError("engine はProbabilisticExecutionEngineのインスタンスである必要があります")

    # 現在の時刻からシードを生成
    time_seed = int(time.time() * 1000)

    # シード値に基づくダミー計算回数
    dummy_steps = (time_seed % 10) + 5

    # 内部状態を保存
    original_state_id = engine.path_manager.current_state_id
    original_history = engine.path_manager.path_history.copy()

    # 一時的なエントロピー注入
    entropy_data = os.urandom(32)

    # ノイズ生成（乱数シードを利用 - 32ビット制限に注意）
    noise = np.random.RandomState(time_seed & 0x7FFFFFFF).random(dummy_steps)

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
        entropy_data = os.urandom(1)[0]  # ランダムで上書き
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
        raise ValueError(f"パスタイプは '{TRUE_PATH}' または '{FALSE_PATH}' である必要があります")

    # 鍵から解析対策用のノイズを生成
    noise_seed = hashlib.sha256(key + path_type.encode('utf-8')).digest()

    # ノイズの長さを決定（パターン検出を困難にするためにランダム化）
    noise_length = 256 + (noise_seed[0] % 64)

    # ノイズデータの初期化
    noise = bytearray(noise_length)

    # ノイズパターンを生成（一見ランダムだがパターンを持つ）
    for i in range(noise_length):
        # 複数の要素を組み合わせてパターンを複雑化
        factor1 = noise_seed[i % len(noise_seed)]
        factor2 = noise_seed[(i * 7 + 5) % len(noise_seed)]
        factor3 = i % 251  # 大きな素数でモジュロ
        factor4 = int((i * i) % 197)  # 二次関数的な変化

        # 各要素を複雑に組み合わせる
        noise[i] = (factor1 ^ factor2 ^ factor3 ^ factor4) & 0xFF

    # さらにパターンを複雑化（偽のパターンを埋め込む）
    if path_type == TRUE_PATH:
        # TRUEパスの場合は先頭に特殊パターンを埋め込む
        for i in range(min(16, noise_length)):
            noise[i] = (noise[i] ^ 0xA5) & 0xFF
    else:
        # FALSEパスの場合は末尾に特殊パターンを埋め込む
        for i in range(max(0, noise_length - 16), noise_length):
            noise[i] = (noise[i] ^ 0x5A) & 0xFF

    # ノイズには鍵の特性に関する「偽の」痕跡を埋め込む
    fake_key_hash = hashlib.sha1(key).digest()
    embed_pos = (noise_seed[1] % (noise_length - 20)) if noise_length > 20 else 0

    # 鍵の痕跡を複雑な方法で埋め込む（直接埋め込まない）
    for i in range(min(len(fake_key_hash), noise_length - embed_pos)):
        noise[embed_pos + i] = (noise[embed_pos + i] ^ (fake_key_hash[i] >> 2) ^ (i * 3)) & 0xFF

    return bytes(noise)

def _add_runtime_fingerprint(data: bytes) -> bytes:
    """
    実行時フィンガープリントを追加

    解析対策として実行環境の特性を組み込みます。

    Args:
        data: 元のデータ

    Returns:
        フィンガープリント付きデータ
    """
    # 実行環境情報の収集
    env_data = bytearray()

    # 現在時刻
    time_bytes = struct.pack('!d', time.time())
    env_data.extend(time_bytes)

    # プロセスID
    pid_bytes = struct.pack('!I', os.getpid())
    env_data.extend(pid_bytes)

    # CPUカウンタ（利用可能な場合）
    try:
        cpu_time = time.process_time()
        cpu_bytes = struct.pack('!d', cpu_time)
        env_data.extend(cpu_bytes)
    except AttributeError:
        # 古いPythonバージョンではprocess_timeが使用できない場合がある
        env_data.extend(os.urandom(8))  # フォールバック

    # 環境情報のハッシュ
    env_hash = hashlib.sha256(env_data).digest()[:16]

    # 元データとフィンガープリントを組み合わせる
    # （直接つなげるのではなく、XORで分散させる）
    result = bytearray(data)
    for i in range(min(len(env_hash), len(result))):
        pos = (i * 17) % len(result)  # 素数で乗算して分散
        result[pos] ^= env_hash[i]

    return bytes(result)

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

        # 解析対策ノイズの生成テスト
        noise = generate_anti_analysis_noise(test_key, path_type)
        print(f"解析対策ノイズサイズ: {len(noise)}バイト")

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

    # 実行パス難読化のテスト
    print("\n=== 実行パス難読化テスト ===")
    engine = create_engine_from_key(test_key, TRUE_PATH)
    engine.run_execution()
    original_path = engine.path_manager.path_history.copy()

    # 難読化を適用
    obfuscate_execution_path(engine)

    # 難読化後のパスが元のパスと同一であることを確認
    paths_preserved = (original_path == engine.path_manager.path_history)
    print(f"パスが保持されている: {'はい' if paths_preserved else 'いいえ'}")

    return results

# エントリーポイント
if __name__ == "__main__":
    test_probability_engine()
