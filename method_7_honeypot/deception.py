"""
スクリプト改変耐性モジュール

ソースコードが解析・改変された場合でも、鍵による真偽判定機能を
維持するための防御機構を提供します。
"""

import os
import sys
import hashlib
import hmac
import secrets
import random
import inspect
import types
import importlib
import binascii
import time
from typing import Dict, List, Tuple, Any, Optional, Union, Callable

# 内部モジュールからのインポート
from .trapdoor import (
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from .config import (
    SYMMETRIC_KEY_SIZE, TOKEN_SIZE, DECISION_THRESHOLD,
    RANDOMIZATION_FACTOR, DECOY_VERIFICATION_ROUNDS
)

# 検証用ハッシュ（実際にはインストール時に生成）
# 注: 実際の実装では、これらの値はもっと複雑で予測不可能な方法で生成・保存される
MODULE_HASHES = {
    'trapdoor': None,  # 実際の実装では有効なハッシュが入る
    'key_verification': None,
    'honeypot_capsule': None,
    'encrypt': None,
    'decrypt': None,
    'deception': None
}

# 分散判定に使用する閾値
DECISION_THRESHOLD = 3


def generate_module_hashes():
    """
    各モジュールのハッシュを生成

    このコードは実際にはインストール時に実行され、ハッシュ値が保存される
    """
    modules = [
        'method_7_honeypot.trapdoor',
        'method_7_honeypot.key_verification',
        'method_7_honeypot.honeypot_capsule',
        'method_7_honeypot.encrypt',
        'method_7_honeypot.decrypt',
        'method_7_honeypot.deception'
    ]

    hashes = {}
    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
            # モジュールのソースコードを取得
            source = inspect.getsource(module)
            # ハッシュを計算
            hashes[module_name.split('.')[-1]] = hashlib.sha256(source.encode('utf-8')).hexdigest()
        except Exception:
            hashes[module_name.split('.')[-1]] = None

    return hashes


def verify_module_integrity(module_name: str) -> bool:
    """
    モジュールの整合性を検証

    Args:
        module_name: 検証するモジュール名（例: 'trapdoor'）

    Returns:
        検証結果（True: 正常、False: 改変あり）
    """
    try:
        # モジュールを動的にインポート
        full_module_name = f'method_7_honeypot.{module_name}'
        module = importlib.import_module(full_module_name)

        # モジュールのソースコードを取得
        source = inspect.getsource(module)

        # ハッシュを計算
        current_hash = hashlib.sha256(source.encode('utf-8')).digest()

        # 保存されたハッシュと比較
        expected_hash = MODULE_HASHES.get(module_name)

        # ハッシュが一致しない場合は改変あり
        if expected_hash is not None and current_hash != expected_hash:
            return False

        return True

    except Exception:
        # 例外が発生した場合も改変と見なす
        return False


# 判定に使用する関数タイプ
FUNCTION_TYPE_DIRECT = 0  # 直接比較
FUNCTION_TYPE_INVERSE = 1  # 反転比較
FUNCTION_TYPE_MIXED = 2    # 混合比較


def create_decision_function(function_type: int, special_value: bytes) -> Callable:
    """
    判定関数を動的に生成

    同じ判定ロジックを複数の形式で実装し、それらの結果を
    集約することで、単一の改変に対する耐性を高めます。

    Args:
        function_type: 関数のタイプ
        special_value: 特殊な判定値

    Returns:
        判定関数
    """
    if function_type == FUNCTION_TYPE_DIRECT:
        # 直接比較関数
        def direct_decision(value: bytes, token: bytes) -> bool:
            return hmac.compare_digest(
                hashlib.sha256(value + token).digest()[:8],
                special_value[:8]
            )
        return direct_decision

    elif function_type == FUNCTION_TYPE_INVERSE:
        # 反転比較関数（結果を否定）
        def inverse_decision(value: bytes, token: bytes) -> bool:
            return not hmac.compare_digest(
                hashlib.sha256(value + token + b'inverse').digest()[:8],
                special_value[:8]
            )
        return inverse_decision

    else:  # FUNCTION_TYPE_MIXED
        # 混合比較関数（複雑な条件）
        def mixed_decision(value: bytes, token: bytes) -> bool:
            h1 = hashlib.sha256(value + token).digest()
            h2 = hashlib.sha256(token + value).digest()
            xor_result = bytes(a ^ b for a, b in zip(h1[:8], h2[:8]))
            return hmac.compare_digest(xor_result, special_value[:8])
        return mixed_decision


def generate_decision_functions(seed: bytes) -> List[Tuple[Callable, int]]:
    """
    複数の判定関数を生成

    Args:
        seed: 判定関数生成用のシード

    Returns:
        (function, weight) のリスト
    """
    functions = []

    # シードから擬似乱数生成器を初期化
    random.seed(int.from_bytes(seed, byteorder='big'))

    # 各タイプの関数を生成
    for i in range(5):  # 5つの関数を生成
        function_type = random.randint(0, 2)  # 0-2のランダムな関数タイプ

        # 特殊値を生成
        special_bytes = bytes([random.randint(0, 255) for _ in range(8)])

        # 重みを生成（1または2）
        weight = random.randint(1, 2)

        # 関数を生成
        function = create_decision_function(function_type, special_bytes)

        # 関数と重みをリストに追加
        functions.append((function, weight))

    return functions


class DynamicPathSelector:
    """
    動的にコード実行経路を選択するクラス

    このクラスは、鍵の種類に基づいて異なる処理経路を選択します。
    """

    def __init__(self, seed: bytes, threshold: int = DECISION_THRESHOLD):
        """
        DynamicPathSelectorを初期化

        Args:
            seed: 初期化シード
            threshold: 判定閾値
        """
        self.seed = seed
        self.threshold = threshold
        self.decision_functions = generate_decision_functions(seed)

    def select_path(self, value: bytes, token: bytes) -> str:
        """
        値とトークンに基づいて実行経路を選択

        Args:
            value: 判定する値（通常は鍵）
            token: 関連するトークン

        Returns:
            選択された経路（"true" または "false"）
        """
        # 各判定関数の結果と重みを集計
        true_score = 0
        total_weight = 0

        for func, weight in self.decision_functions:
            total_weight += weight
            if func(value, token):
                true_score += weight

        # 閾値に基づいて判定
        # 注: この比率計算は攻撃者に予測されにくい形にする
        ratio = true_score / total_weight

        # 閾値との比較でパスを決定
        # 少しランダム性を加えて予測を困難に
        random_factor = (int.from_bytes(hashlib.sha256(value + token).digest()[:4], byteorder='big') % 100) / 1000

        if ratio + random_factor > 0.5:
            return KEY_TYPE_TRUE
        else:
            return KEY_TYPE_FALSE

    def is_authentic(self, value: bytes, token: bytes) -> bool:
        """
        値が本物かどうかを判定

        Args:
            value: 判定する値
            token: 関連するトークン

        Returns:
            本物の場合はTrue、そうでなければFalse
        """
        return self.select_path(value, token) == KEY_TYPE_TRUE


class ObfuscatedVerifier:
    """
    難読化された検証機構

    このクラスは、ソースコード解析や改変に対する耐性を
    持つ検証メカニズムを提供します。
    """

    def __init__(self, master_seed: bytes):
        """
        ObfuscatedVerifierを初期化

        Args:
            master_seed: マスターシード
        """
        # 実際の実装では、これらの値はもっと複雑な方法で生成される
        self.master_seed = master_seed
        self.selector = DynamicPathSelector(
            hashlib.sha256(master_seed + b'selector').digest()
        )

        # 内部状態を分散化
        self._distribute_state(master_seed)

    def _distribute_state(self, seed: bytes) -> None:
        """
        内部状態を分散化

        Args:
            seed: 初期化シード
        """
        # いくつかのダミー状態を作成
        self._state_a = hashlib.sha256(seed + b'a').digest()
        self._state_b = hashlib.sha256(seed + b'b').digest()
        self._state_c = hashlib.sha256(seed + b'c').digest()

        # 実際の状態（他の状態と一見区別がつかない）
        self._real_state = hashlib.sha256(seed + b'verification').digest()

    def verify(self, value: bytes, token: bytes) -> bool:
        """
        値を検証

        Args:
            value: 検証する値
            token: 関連するトークン

        Returns:
            検証結果
        """
        # モジュール整合性の確認
        integrity_ok = all([
            verify_module_integrity('trapdoor'),
            verify_module_integrity('key_verification'),
            verify_module_integrity('deception')
        ])

        # 整合性検証に失敗した場合も正常に動作するように見せかける
        if not integrity_ok:
            # 常にランダムな値を返す代わりに、一見正常な動作に見えるダミー判定
            dummy_result = (int.from_bytes(hashlib.sha256(value + token).digest()[:1], byteorder='big') % 2) == 0
            return dummy_result

        # 通常の判定
        # 3つの異なる方法で判定し、多数決で結果を決定

        # 方法1: 動的パスセレクタ
        result1 = self.selector.is_authentic(value, token)

        # 方法2: HMAC検証
        h = hmac.new(self._real_state, value + token, hashlib.sha256).digest()
        result2 = h[0] < 128  # 単純な閾値判定

        # 方法3: 分散判定関数
        funcs = generate_decision_functions(self._state_b)
        true_count = sum(1 for func, _ in funcs if func(value, token))
        result3 = true_count >= len(funcs) // 2

        # 多数決
        results = [result1, result2, result3]
        return sum(results) >= 2  # 2つ以上がTrue


def create_redundant_verification_pattern(key: bytes, token: bytes, trapdoor_params: Dict[str, Any]) -> str:
    """
    冗長な検証パターンを作成

    この関数は、攻撃者が静的解析から真偽判定ロジックを特定することを
    困難にするために、複数の検証方法を組み合わせます。

    Args:
        key: 検証する鍵
        token: 関連するトークン
        trapdoor_params: トラップドアパラメータ

    Returns:
        検証結果（"true" または "false"）
    """
    # シードの生成
    seed = hashlib.sha256(key + token).digest()

    # 検証器の作成
    verifier = ObfuscatedVerifier(seed)

    # 基本検証
    basic_result = verifier.verify(key, token)

    # 動的パスの選択
    selector = DynamicPathSelector(seed)
    selector_result = selector.select_path(key, token)

    # トラップドアパラメータを使用した検証
    # 注: この部分は実際にはより複雑になる
    n = trapdoor_params.get('n', 1)
    e = trapdoor_params.get('e', 1)
    d = trapdoor_params.get('d', 1)

    # 冗長判定（数学的に等価だが、実装が異なる）
    redundant_result1 = KEY_TYPE_TRUE
    redundant_result2 = KEY_TYPE_TRUE

    # 複数の結果を総合判定
    if basic_result and selector_result == KEY_TYPE_TRUE:
        return KEY_TYPE_TRUE
    else:
        return KEY_TYPE_FALSE


def verify_with_tamper_resistance(key: bytes, token: bytes, trapdoor_params: Dict[str, Any]) -> str:
    """
    改変耐性を備えた検証

    この関数は、verify_key_and_select_path の代替としてより高い
    改変耐性を提供する検証機能です。

    Args:
        key: 検証する鍵
        token: 関連するトークン
        trapdoor_params: トラップドアパラメータ

    Returns:
        検証結果（"true" または "false"）
    """
    # ソースコードの整合性を確認
    integrity_ok = all([
        verify_module_integrity('trapdoor'),
        verify_module_integrity('key_verification'),
        verify_module_integrity('deception')
    ])

    if not integrity_ok:
        # 整合性検証に失敗した場合は、常に安全な値を返す
        # 注: 実際にはもっと巧妙な対応策を実装
        return KEY_TYPE_FALSE

    # 冗長な検証パターンを実行
    return create_redundant_verification_pattern(key, token, trapdoor_params)


def test_tamper_resistance():
    """
    改変耐性のテスト
    """
    from .trapdoor import create_master_key, create_trapdoor_parameters, generate_honey_token

    print("改変耐性機能のテスト実行中...")

    # マスター鍵の生成
    master_key = create_master_key()

    # トラップドアパラメータの生成
    trapdoor_params = create_trapdoor_parameters(master_key)

    # トークンの生成
    true_token = generate_honey_token(KEY_TYPE_TRUE, trapdoor_params)
    false_token = generate_honey_token(KEY_TYPE_FALSE, trapdoor_params)

    # テスト鍵の生成
    true_key = os.urandom(SYMMETRIC_KEY_SIZE)
    false_key = os.urandom(SYMMETRIC_KEY_SIZE)

    print("基本機能テスト:")

    # DynamicPathSelectorのテスト
    selector = DynamicPathSelector(master_key)
    true_path = selector.select_path(true_key, true_token)
    false_path = selector.select_path(false_key, false_token)

    print(f"正規鍵の経路選択: {true_path}")
    print(f"非正規鍵の経路選択: {false_path}")

    # ObfuscatedVerifierのテスト
    verifier = ObfuscatedVerifier(master_key)
    true_verify = verifier.verify(true_key, true_token)
    false_verify = verifier.verify(false_key, false_token)

    print(f"正規鍵の検証結果: {true_verify}")
    print(f"非正規鍵の検証結果: {false_verify}")

    # 完全な検証フローのテスト
    true_result = verify_with_tamper_resistance(true_key, true_token, trapdoor_params)
    false_result = verify_with_tamper_resistance(false_key, false_token, trapdoor_params)

    print(f"改変耐性機能での正規鍵判定: {true_result}")
    print(f"改変耐性機能での非正規鍵判定: {false_result}")

    print("テスト完了")


# メイン関数
if __name__ == "__main__":
    test_tamper_resistance()
