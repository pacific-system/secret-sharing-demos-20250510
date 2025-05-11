# 不確定性転写暗号化方式 🎲 実装【子 Issue #8】：テストとデバッグ

お兄様！いよいよ不確定性転写暗号化方式の最終仕上げ、テストとデバッグを行いましょう！すべての魔法が正しく動くか確認するステップです ✨

## 📋 タスク概要

不確定性転写暗号化方式の各モジュールに対する単体テストと統合テスト、およびデバッグ機能を実装します。これにより、システム全体の正確性、安全性、堅牢性を検証します。

## 🔧 実装内容

`method_10_indeterministic/tests/` ディレクトリに、テストスクリプトを実装します。

### 主要な機能：

1. 各モジュールの単体テスト
2. 統合テスト
3. エッジケースの検証
4. パフォーマンス測定
5. デバッグユーティリティ

## 💻 実装手順

### 1. テスト用の共通ユーティリティ実装

`method_10_indeterministic/tests/test_utils.py` ファイルを作成し、テスト用の共通ユーティリティを実装します：

```python
"""
不確定性転写暗号化方式 - テスト用ユーティリティ

テストに必要な共通関数やユーティリティを提供します。
"""

import os
import time
import hashlib
import random
import string
import tempfile
from typing import Dict, List, Tuple, Optional, Any

# パスの設定
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(TEST_DIR))
COMMON_DIR = os.path.join(PROJECT_ROOT, "common")
TRUE_TEXT_PATH = os.path.join(COMMON_DIR, "true-false-text", "true.text")
FALSE_TEXT_PATH = os.path.join(COMMON_DIR, "true-false-text", "false.text")


def ensure_test_files():
    """テストファイルの存在を確認し、ない場合は作成"""
    os.makedirs(os.path.join(COMMON_DIR, "true-false-text"), exist_ok=True)

    if not os.path.exists(TRUE_TEXT_PATH):
        with open(TRUE_TEXT_PATH, "w") as f:
            f.write("これは正規のファイルです。正しい鍵で復号されたことを示します。")

    if not os.path.exists(FALSE_TEXT_PATH):
        with open(FALSE_TEXT_PATH, "w") as f:
            f.write("これは非正規のファイルです。不正な鍵で復号されたことを示します。")


def generate_random_key(size=32):
    """テスト用のランダムな鍵を生成"""
    return os.urandom(size)


def generate_test_data(size=1024):
    """テスト用のランダムデータを生成"""
    return os.urandom(size)


def time_execution(func, *args, **kwargs):
    """関数の実行時間を計測"""
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    return result, end_time - start_time


def verify_data_equality(data1, data2):
    """2つのデータが同一かどうか検証"""
    return data1 == data2


def create_temp_file(data=None):
    """一時ファイルを作成"""
    temp = tempfile.NamedTemporaryFile(delete=False)
    if data:
        if isinstance(data, str):
            temp.write(data.encode('utf-8'))
        else:
            temp.write(data)
    temp.close()
    return temp.name


def cleanup_temp_file(filename):
    """一時ファイルを削除"""
    try:
        os.unlink(filename)
    except:
        pass


class TestResult:
    """テスト結果を保持・表示するクラス"""

    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.results = []

    def add_result(self, test_name, passed, message=None, duration=None):
        """テスト結果を追加"""
        self.total += 1
        if passed:
            self.passed += 1
        else:
            self.failed += 1

        self.results.append({
            "name": test_name,
            "passed": passed,
            "message": message,
            "duration": duration
        })

    def print_summary(self):
        """テスト結果のサマリーを表示"""
        print(f"\n=== テスト結果サマリー ===")
        print(f"合計: {self.total}")
        print(f"成功: {self.passed}")
        print(f"失敗: {self.failed}")

        if self.failed > 0:
            print("\n失敗したテスト:")
            for result in self.results:
                if not result["passed"]:
                    print(f"  - {result['name']}: {result['message']}")

        success_rate = (self.passed / self.total) * 100 if self.total > 0 else 0
        print(f"\n成功率: {success_rate:.2f}%")
```

### 2. 各モジュールの単体テストの実装

#### 状態マトリクスのテスト

`method_10_indeterministic/tests/test_state_matrix.py` ファイルを作成し、以下を実装します：

```python
"""
状態遷移マトリクス生成機構のテスト
"""

import os
import sys
import unittest
import random
from typing import Dict, List, Any

# プロジェクトルートを追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.state_matrix import (
    State, StateMatrixGenerator, StateExecutor,
    create_state_matrix_from_key, get_biased_random_generator
)
from method_10_indeterministic.config import STATE_MATRIX_SIZE, STATE_TRANSITIONS
from method_10_indeterministic.tests.test_utils import generate_random_key, TestResult


def test_state_matrix_generation():
    """状態マトリクス生成機能のテスト"""
    results = TestResult()

    # テスト1: 基本的な状態マトリクス生成
    try:
        key = generate_random_key()
        generator = StateMatrixGenerator(key)
        states = generator.generate_state_matrix()

        # 生成された状態の数を検証
        is_correct_size = len(states) == STATE_MATRIX_SIZE
        results.add_result(
            "状態マトリクスのサイズ検証",
            is_correct_size,
            f"期待値: {STATE_MATRIX_SIZE}, 実際: {len(states)}"
        )

        # 各状態の遷移確率の合計が1になっているか検証
        probabilities_valid = True
        for state_id, state in states.items():
            total_prob = sum(state.transitions.values())
            if abs(total_prob - 1.0) > 0.001:  # 浮動小数点誤差を考慮
                probabilities_valid = False
                break

        results.add_result(
            "遷移確率の正規化検証",
            probabilities_valid,
            "すべての状態の遷移確率合計が1.0であること"
        )

        # 異なる鍵で生成した場合、異なる状態マトリクスになるか検証
        key2 = generate_random_key()
        generator2 = StateMatrixGenerator(key2)
        states2 = generator2.generate_state_matrix()

        # 少なくとも一部の状態が異なるか検証
        is_different = False
        for state_id in states:
            if state_id in states2:
                for next_id in states[state_id].transitions:
                    if next_id in states2[state_id].transitions:
                        if abs(states[state_id].transitions[next_id] - states2[state_id].transitions[next_id]) > 0.001:
                            is_different = True
                            break
            if is_different:
                break

        results.add_result(
            "異なる鍵での状態マトリクス差異検証",
            is_different,
            "異なる鍵で生成した状態マトリクスが異なること"
        )

    except Exception as e:
        results.add_result("状態マトリクス生成基本テスト", False, f"例外発生: {str(e)}")

    # テスト2: 初期状態生成
    try:
        key = generate_random_key()
        generator = StateMatrixGenerator(key)
        states = generator.generate_state_matrix()
        true_initial, false_initial = generator.derive_initial_states()

        # 初期状態が有効範囲内か検証
        is_valid_true = 0 <= true_initial < STATE_MATRIX_SIZE
        is_valid_false = 0 <= false_initial < STATE_MATRIX_SIZE

        results.add_result(
            "正規パス初期状態の有効性",
            is_valid_true,
            f"初期状態: {true_initial}"
        )

        results.add_result(
            "非正規パス初期状態の有効性",
            is_valid_false,
            f"初期状態: {false_initial}"
        )

        # 正規パスと非正規パスの初期状態が異なるか検証
        is_different = true_initial != false_initial
        results.add_result(
            "初期状態の差異",
            is_different,
            f"正規: {true_initial}, 非正規: {false_initial}"
        )

    except Exception as e:
        results.add_result("初期状態生成テスト", False, f"例外発生: {str(e)}")

    # テスト3: 状態実行機能
    try:
        key = generate_random_key()
        states, true_initial, false_initial = create_state_matrix_from_key(key)

        # 正規パスの実行
        true_executor = StateExecutor(states, true_initial)
        true_path = true_executor.run_transitions(STATE_TRANSITIONS)

        # 非正規パスの実行
        false_executor = StateExecutor(states, false_initial)
        false_path = false_executor.run_transitions(STATE_TRANSITIONS)

        # パスが正しい長さになっているか検証
        is_correct_true_len = len(true_path) == STATE_TRANSITIONS + 1  # 初期状態を含む
        is_correct_false_len = len(false_path) == STATE_TRANSITIONS + 1

        results.add_result(
            "正規パス長の検証",
            is_correct_true_len,
            f"期待値: {STATE_TRANSITIONS+1}, 実際: {len(true_path)}"
        )

        results.add_result(
            "非正規パス長の検証",
            is_correct_false_len,
            f"期待値: {STATE_TRANSITIONS+1}, 実際: {len(false_path)}"
        )

        # 正規パスと非正規パスが異なる遷移をするか検証
        is_different_path = true_path != false_path
        results.add_result(
            "パス差異の検証",
            is_different_path,
            "正規パスと非正規パスが異なること"
        )

    except Exception as e:
        results.add_result("状態実行テスト", False, f"例外発生: {str(e)}")

    return results


if __name__ == "__main__":
    results = test_state_matrix_generation()
    results.print_summary()
```

#### 確率的実行エンジンのテスト

`method_10_indeterministic/tests/test_probability_engine.py` ファイルを作成し、以下を実装します：

```python
"""
確率的実行エンジンのテスト
"""

import os
import sys
import unittest
import random
from typing import Dict, List, Any

# プロジェクトルートを追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.probability_engine import (
    ProbabilityController, ExecutionPathManager, ProbabilisticExecutionEngine,
    TRUE_PATH, FALSE_PATH, create_engine_from_key, obfuscate_execution_path
)
from method_10_indeterministic.tests.test_utils import generate_random_key, TestResult


def test_probability_engine():
    """確率的実行エンジンのテスト"""
    results = TestResult()

    # テスト1: エンジン作成と基本動作
    try:
        key = generate_random_key()

        # 正規パスエンジン作成
        true_engine = create_engine_from_key(key, TRUE_PATH)

        # 非正規パスエンジン作成
        false_engine = create_engine_from_key(key, FALSE_PATH)

        # 初期状態が適切に設定されているか検証
        is_valid_true_init = true_engine.path_manager.current_state_id == true_engine.true_initial
        is_valid_false_init = false_engine.path_manager.current_state_id == false_engine.false_initial

        results.add_result(
            "正規パスエンジン初期状態検証",
            is_valid_true_init,
            f"初期状態: {true_engine.path_manager.current_state_id}"
        )

        results.add_result(
            "非正規パスエンジン初期状態検証",
            is_valid_false_init,
            f"初期状態: {false_engine.path_manager.current_state_id}"
        )

    except Exception as e:
        results.add_result("エンジン作成テスト", False, f"例外発生: {str(e)}")

    # テスト2: エンジン実行と収束性
    try:
        key = generate_random_key()

        # 複数回実行して最終状態を収集
        true_finals = []
        false_finals = []

        for i in range(5):
            true_engine = create_engine_from_key(key, TRUE_PATH)
            true_path = true_engine.run_execution()
            true_finals.append(true_path[-1])

            false_engine = create_engine_from_key(key, FALSE_PATH)
            false_path = false_engine.run_execution()
            false_finals.append(false_path[-1])

        # 正規パスの収束性（同じ鍵では最終状態が類似する傾向になるか）
        true_converges = len(set(true_finals)) < 3  # 5回中3種類未満なら収束傾向あり

        # 非正規パスの収束性
        false_converges = len(set(false_finals)) < 3

        # 正規/非正規パスの差異（両者の最終状態が明確に異なるか）
        paths_differ = len(set(true_finals) & set(false_finals)) == 0  # 共通要素がない

        results.add_result(
            "正規パス収束性",
            true_converges,
            f"最終状態集合: {set(true_finals)}"
        )

        results.add_result(
            "非正規パス収束性",
            false_converges,
            f"最終状態集合: {set(false_finals)}"
        )

        results.add_result(
            "正規/非正規パス差異",
            paths_differ,
            f"正規最終状態: {set(true_finals)}, 非正規最終状態: {set(false_finals)}"
        )

    except Exception as e:
        results.add_result("エンジン収束性テスト", False, f"例外発生: {str(e)}")

    # テスト3: 実行パスの非決定性
    try:
        key = generate_random_key()

        # 同じパラメータで複数回実行し、パスの詳細が毎回変化することを確認
        path_histories = []

        for i in range(3):
            engine = create_engine_from_key(key, TRUE_PATH)
            engine.run_execution()
            path_histories.append(engine.path_manager.path_history)

        # 各実行パスが異なることを確認
        all_same = all(path == path_histories[0] for path in path_histories)
        all_different = len(set(tuple(path) for path in path_histories)) == len(path_histories)

        results.add_result(
            "実行パスの非決定性",
            not all_same,
            "同じパラメータでも異なる実行パスになること"
        )

    except Exception as e:
        results.add_result("実行パス非決定性テスト", False, f"例外発生: {str(e)}")

    return results


if __name__ == "__main__":
    results = test_probability_engine()
    results.print_summary()
```

#### 暗号化・復号機能の統合テスト

`method_10_indeterministic/tests/test_integration.py` ファイルを作成し、以下を実装します：

```python
"""
不確定性転写暗号化方式の統合テスト
"""

import os
import sys
import unittest
import hashlib
import tempfile
from typing import Dict, List, Any

# プロジェクトルートを追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.encrypt import encrypt_files
from method_10_indeterministic.decrypt import decrypt_file
from method_10_indeterministic.tests.test_utils import (
    ensure_test_files, generate_random_key, time_execution,
    create_temp_file, cleanup_temp_file, TestResult,
    TRUE_TEXT_PATH, FALSE_TEXT_PATH
)


def test_encrypt_decrypt_cycle():
    """暗号化→復号のサイクルテスト"""
    results = TestResult()
    temp_files = []

    try:
        # テストファイルの存在確認
        ensure_test_files()

        # 一時出力ファイル
        output_file = create_temp_file()
        temp_files.append(output_file)

        # テスト1: 基本的な暗号化→復号サイクル
        key, _ = encrypt_files(TRUE_TEXT_PATH, FALSE_TEXT_PATH, output_file)

        # 正規鍵での復号
        decrypted_true = create_temp_file()
        temp_files.append(decrypted_true)
        decrypt_file(output_file, key, decrypted_true)

        # 非正規鍵（異なる鍵）での復号
        decrypted_false = create_temp_file()
        temp_files.append(decrypted_false)
        false_key = generate_random_key()  # 異なる鍵を生成
        decrypt_file(output_file, false_key, decrypted_false)

        # 復号結果の検証
        with open(TRUE_TEXT_PATH, 'rb') as f:
            true_original = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            false_original = f.read()

        with open(decrypted_true, 'rb') as f:
            true_decrypted = f.read()

        with open(decrypted_false, 'rb') as f:
            false_decrypted = f.read()

        # 正規鍵で復号した結果が正規ファイルと一致するか
        true_match = true_original in true_decrypted
        # 非正規鍵で復号した結果が非正規ファイルと一致するか
        false_match = false_original in false_decrypted

        results.add_result(
            "正規パス復号検証",
            true_match,
            "正規鍵で復号した結果が正規ファイルを含むこと"
        )

        results.add_result(
            "非正規パス復号検証",
            false_match,
            "非正規鍵で復号した結果が非正規ファイルを含むこと"
        )

        # 重要な検証: 正規鍵で非正規ファイルが復号されないこと
        true_doesnt_match_false = false_original not in true_decrypted
        # 非正規鍵で正規ファイルが復号されないこと
        false_doesnt_match_true = true_original not in false_decrypted

        results.add_result(
            "正規/非正規の分離検証(1)",
            true_doesnt_match_false,
            "正規鍵で非正規ファイルが復号されないこと"
        )

        results.add_result(
            "正規/非正規の分離検証(2)",
            false_doesnt_match_true,
            "非正規鍵で正規ファイルが復号されないこと"
        )

    except Exception as e:
        results.add_result("暗号化/復号サイクル", False, f"例外発生: {str(e)}")
    finally:
        # 一時ファイルのクリーンアップ
        for file in temp_files:
            cleanup_temp_file(file)

    return results


def test_performance():
    """パフォーマンステスト"""
    results = TestResult()
    temp_files = []

    try:
        # テストファイルの存在確認
        ensure_test_files()

        # 一時出力ファイル
        output_file = create_temp_file()
        temp_files.append(output_file)

        # 暗号化のパフォーマンス測定
        key, encrypt_time = time_execution(
            encrypt_files, TRUE_TEXT_PATH, FALSE_TEXT_PATH, output_file
        )

        # 復号のパフォーマンス測定
        decrypted_file = create_temp_file()
        temp_files.append(decrypted_file)
        _, decrypt_time = time_execution(
            decrypt_file, output_file, key, decrypted_file
        )

        # ファイルサイズの測定
        original_size = os.path.getsize(TRUE_TEXT_PATH) + os.path.getsize(FALSE_TEXT_PATH)
        encrypted_size = os.path.getsize(output_file)

        # パフォーマンス結果の記録
        results.add_result(
            "暗号化パフォーマンス",
            True,
            f"時間: {encrypt_time:.4f}秒",
            encrypt_time
        )

        results.add_result(
            "復号パフォーマンス",
            True,
            f"時間: {decrypt_time:.4f}秒",
            decrypt_time
        )

        results.add_result(
            "サイズ効率",
            True,
            f"元サイズ: {original_size}バイト, 暗号化後: {encrypted_size}バイト, 比率: {encrypted_size/original_size:.2f}x"
        )

    except Exception as e:
        results.add_result("パフォーマンステスト", False, f"例外発生: {str(e)}")
    finally:
        # 一時ファイルのクリーンアップ
        for file in temp_files:
            cleanup_temp_file(file)

    return results


if __name__ == "__main__":
    print("\n=== 暗号化/復号サイクルテスト ===")
    cycle_results = test_encrypt_decrypt_cycle()
    cycle_results.print_summary()

    print("\n=== パフォーマンステスト ===")
    perf_results = test_performance()
    perf_results.print_summary()
```

### 3. テスト実行スクリプトの実装

`method_10_indeterministic/tests/run_tests.py` ファイルを作成し、以下を実装します：

```python
"""
不確定性転写暗号化方式の全テスト実行
"""

import os
import sys
import time
from typing import Dict, List, Any

# プロジェクトルートを追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テストモジュールをインポート
from method_10_indeterministic.tests.test_utils import TestResult
from method_10_indeterministic.tests.test_state_matrix import test_state_matrix_generation
from method_10_indeterministic.tests.test_probability_engine import test_probability_engine
from method_10_indeterministic.tests.test_integration import test_encrypt_decrypt_cycle, test_performance


def run_all_tests():
    """全テストを実行"""
    # 開始メッセージ
    print("=" * 60)
    print("不確定性転写暗号化方式 全テスト実行")
    print("=" * 60)

    start_time = time.time()

    # 各テストの実行
    print("\n[1/4] 状態マトリクス生成機構のテスト")
    state_matrix_results = test_state_matrix_generation()
    state_matrix_results.print_summary()

    print("\n[2/4] 確率的実行エンジンのテスト")
    probability_engine_results = test_probability_engine()
    probability_engine_results.print_summary()

    print("\n[3/4] 暗号化/復号サイクルテスト")
    cycle_results = test_encrypt_decrypt_cycle()
    cycle_results.print_summary()

    print("\n[4/4] パフォーマンステスト")
    perf_results = test_performance()
    perf_results.print_summary()

    # 総合結果
    total_results = TestResult()
    total_results.total = (state_matrix_results.total + probability_engine_results.total +
                          cycle_results.total + perf_results.total)
    total_results.passed = (state_matrix_results.passed + probability_engine_results.passed +
                           cycle_results.passed + perf_results.passed)
    total_results.failed = (state_matrix_results.failed + probability_engine_results.failed +
                           cycle_results.failed + perf_results.failed)

    # 終了メッセージ
    end_time = time.time()
    print("\n" + "=" * 60)
    print("総合テスト結果")
    print("=" * 60)
    print(f"合計テスト数: {total_results.total}")
    print(f"成功: {total_results.passed}")
    print(f"失敗: {total_results.failed}")

    success_rate = (total_results.passed / total_results.total) * 100 if total_results.total > 0 else 0
    print(f"成功率: {success_rate:.2f}%")
    print(f"総実行時間: {end_time - start_time:.2f}秒")

    # 終了ステータス
    return 0 if total_results.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
```

## ✅ 完了条件

- [ ] テスト用ユーティリティが実装されている
- [ ] 状態マトリクス生成機構のテストが実装されている
- [ ] 確率的実行エンジンのテストが実装されている
- [ ] 暗号化/復号の統合テストが実装されている
- [ ] パフォーマンス測定機能が実装されている
- [ ] 全テストを実行するスクリプトが実装されている
- [ ] すべてのテストが正常に完了し、要件を満たしていることが確認できる

## 🧪 テスト方法

テストを実行するには以下のコマンドを使用します：

```bash
# すべてのテストを実行
python -m method_10_indeterministic.tests.run_tests

# 個別のテストを実行
python -m method_10_indeterministic.tests.test_state_matrix
python -m method_10_indeterministic.tests.test_probability_engine
python -m method_10_indeterministic.tests.test_integration
```

## ⏰ 想定実装時間

約 3 時間

## 📚 参考資料

- [Python の unittest ライブラリ](https://docs.python.org/3/library/unittest.html)
- [テスト駆動開発入門](https://www.amazon.co.jp/dp/4274217884/)
- [暗号システムのテスト方法](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program)

## 💬 備考

- テストは繰り返し実行しても同じ結果になるように設計してください
- 実行環境によって結果が変わる可能性があるため、テスト条件は柔軟に調整してください
- パフォーマンステストは参考値として捉え、絶対的な基準にはしないでください
- テスト結果は明確で読みやすい形式で表示し、問題が発生した場合は原因を特定しやすくしてください
- デバッグしやすいよう、テスト失敗時には十分な情報を出力するようにしてください
