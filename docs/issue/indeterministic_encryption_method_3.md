# 不確定性転写暗号化方式 🎲 実装【子 Issue #3】：確率的実行エンジンの構築

お兄様！不確定性転写暗号化方式の心臓部分、確率的実行エンジンを構築しましょう！この部分が魔法のように毎回異なる実行パスを作り出します ✨

## 📋 タスク概要

不確定性転写暗号化方式の核となる確率的実行エンジンを実装します。このエンジンは、実行パスを確率的に制御し、鍵の種類に応じて特定の状態に導く機能を持ちます。同時に、解析攻撃からの保護メカニズムも実装します。

## 🔧 実装内容

`method_10_indeterministic/probability_engine.py` ファイルに、確率的実行エンジンを実装します。

### 主要な機能：

1. 鍵依存乱数生成
2. 実行パス決定メカニズム
3. 状態バイアス制御
4. 解析攻撃からの保護機能

## 💻 実装手順

### 1. 必要なライブラリのインポート

`probability_engine.py` の先頭に以下を記述します：

```python
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
from typing import Dict, List, Tuple, Optional, Union, Any, Callable

# 内部モジュールのインポート
from .config import (
    STATE_TRANSITIONS, STATE_MATRIX_SIZE,
    MIN_PROBABILITY, MAX_PROBABILITY, PROBABILITY_STEPS
)
from .state_matrix import (
    State, StateExecutor, create_state_matrix_from_key,
    get_biased_random_generator
)

# 定数定義
TRUE_PATH = "true"
FALSE_PATH = "false"
ENGINE_VERSION = 1
```

### 2. 確率的実行コントローラクラスの実装

```python
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

        # 鍵とソルトから確率制御用のパラメータを初期化
        self._initialize_parameters()

        # 内部状態（解析攻撃対策として実行ごとに変化）
        self._runtime_state = os.urandom(16)
        self._execution_counter = 0

    def _initialize_parameters(self):
        """
        確率制御用パラメータの初期化

        鍵とソルトからパラメータを導出します。
        """
        # 鍵とソルトから基本ハッシュを生成
        base_hash = hmac.new(self.key, b"probability_control" + self.salt, hashlib.sha256).digest()

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
        # 基本乱数の生成
        raw_random = secrets.randbelow(10000) / 10000.0

        # 実行進捗率の計算（0-1）
        progress = step / total_steps if total_steps > 0 else 0.5

        # 収束閾値を超えた場合はバイアスを強くする
        if progress > self.convergence_threshold:
            # バイアス強度の計算（進捗に応じて徐々に強くなる）
            effective_bias = self.bias_strength * (progress - self.convergence_threshold) / (1 - self.convergence_threshold)

            # バイアス値の生成
            bias_seed = hmac.new(
                self.key,
                f"bias_{state_id}_{step}_{self.target_path}".encode('utf-8') + self.salt,
                hashlib.sha256
            ).digest()

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
        true_seed = hmac.new(
            self.key,
            f"true_distance_{state_id}".encode('utf-8') + self.salt,
            hashlib.sha256
        ).digest()

        false_seed = hmac.new(
            self.key,
            f"false_distance_{state_id}".encode('utf-8') + self.salt,
            hashlib.sha256
        ).digest()

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
```

### 3. 実行パス管理クラスの実装

```python
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
        self.current_state_id = next_state_id
        self.path_history.append(next_state_id)

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
        for _ in range(steps):
            self.step()

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

        return {
            "initial_state": initial_state,
            "final_state": final_state,
            "path_length": path_length,
            "state_counts": state_counts,
            "is_true_biased": is_true_biased,
            "is_converged": is_converged,
            "target_path": self.controller.target_path
        }
```

### 4. 確率的実行エンジンクラスの実装

```python
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
        self.key = key
        self.salt = salt or os.urandom(16)
        self.target_path = target_path

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

    def run_execution(self, steps: int = STATE_TRANSITIONS) -> List[int]:
        """
        エンジンを実行して実行パスを生成

        Args:
            steps: 実行するステップ数

        Returns:
            生成された実行パス（状態IDのリスト）
        """
        return self.path_manager.run_path(steps)

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
            "salt": self.salt.hex()
        }
```

### 5. ユーティリティ関数と解析保護機能の実装

```python
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
    return ProbabilisticExecutionEngine(key, salt, path_type)


def obfuscate_execution_path(engine: ProbabilisticExecutionEngine) -> None:
    """
    実行パスを難読化

    実行パスに無関係な処理を追加し、解析を困難にします。

    Args:
        engine: 確率的実行エンジン
    """
    # 現在の時刻からシードを生成
    time_seed = int(time.time() * 1000)

    # シード値に基づくダミー計算
    dummy_steps = time_seed % 10 + 5

    # 内部状態を保存
    original_state_id = engine.path_manager.current_state_id
    original_history = engine.path_manager.path_history.copy()

    # ダミー実行
    for _ in range(dummy_steps):
        engine.path_manager.step(force_random=True)

    # 内部状態を復元
    engine.path_manager.current_state_id = original_state_id
    engine.path_manager.path_history = original_history

    # セキュアワイプ（ダミー変数のメモリ内容を上書き）
    dummy_array = bytearray(os.urandom(64))
    for i in range(len(dummy_array)):
        dummy_array[i] = 0


def generate_anti_analysis_noise(key: bytes, path_type: str) -> bytes:
    """
    解析対策用のノイズデータを生成

    静的・動的解析を困難にするためのノイズデータを生成します。

    Args:
        key: 鍵データ
        path_type: パスタイプ

    Returns:
        ノイズデータ
    """
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
```

### 6. テスト用関数の実装

```python
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
```

## ✅ 完了条件

- [ ] 確率的実行コントローラ（ProbabilityController）が実装されている
- [ ] 実行パス管理クラス（ExecutionPathManager）が実装されている
- [ ] 確率的実行エンジン（ProbabilisticExecutionEngine）が実装されている
- [ ] 解析保護機能（obfuscate_execution_path, generate_anti_analysis_noise）が実装されている
- [ ] テスト関数が正常に動作し、以下が確認できる：
  - [ ] TRUE/FALSE パスで異なる結果が得られる
  - [ ] 同じ鍵での実行でも実行パスは毎回変化する
  - [ ] 複数回実行での収束性が確認できる

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# モジュールを単体で実行してテスト
python -m method_10_indeterministic.probability_engine

# 異なる鍵での実行を確認
python -c "import os; from method_10_indeterministic.probability_engine import test_probability_engine; test_probability_engine()"
```

## ⏰ 想定実装時間

約 5 時間

## 📚 参考資料

- [確率的アルゴリズムの設計](https://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-046j-design-and-analysis-of-algorithms-spring-2015/lecture-notes/MIT6_046JS15_lec08.pdf)
- [マルコフ過程入門](https://www.cs.ubc.ca/~murphyk/Papers/intro_gm.pdf)
- [タイミング攻撃対策技術](https://people.eecs.berkeley.edu/~daw/papers/timing-b.pdf)
- [Python の secrets モジュール](https://docs.python.org/3/library/secrets.html)

## 💬 備考

- 確率的実行エンジンは、同じ鍵と目標パスでも毎回異なる実行パスを生成する必要があります
- 同時に、十分な実行ステップ後には目標とする状態に収束する必要があります
- 静的解析や動的解析から保護するための機能を組み込んでください
- エンジンの内部状態や確率パラメータは、外部から解析されないように保護してください
- 特に乱数生成部分は注意深く実装し、予測可能性を排除してください
