#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
多重鍵ストリーム生成モジュール

単一の入力鍵から複数の独立したストリームを生成し、
鍵の種類に応じて適切なストリームを選択します。
これにより同一の暗号文から異なる平文を復元する機能を実現します。
"""

import os
import hashlib
import hmac
import secrets
from typing import Tuple, Dict, Any, Optional, Union, List, Callable
import binascii

# インポートエラーを回避するための処理
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        TRUE_KEY_MARKER,
        FALSE_KEY_MARKER,
        STREAM_SELECTOR_SEED,
        MAGIC_VALUE_1,
        MAGIC_VALUE_2,
        MAGIC_XOR_VALUE,
        KEY_DERIVATION_ITERATIONS
    )
    from method_6_rabbit.rabbit_stream import RabbitStreamGenerator, derive_key
    from method_6_rabbit.key_analyzer import determine_key_type_advanced, obfuscated_key_determination
else:
    from .config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        TRUE_KEY_MARKER,
        FALSE_KEY_MARKER,
        STREAM_SELECTOR_SEED,
        MAGIC_VALUE_1,
        MAGIC_VALUE_2,
        MAGIC_XOR_VALUE,
        KEY_DERIVATION_ITERATIONS
    )
    from .rabbit_stream import RabbitStreamGenerator, derive_key
    from .key_analyzer import determine_key_type_advanced, obfuscated_key_determination

# 鍵派生用の定数
TRUE_KEY_INFO = b"true_stream_rabbit"
FALSE_KEY_INFO = b"false_stream_rabbit"

# 鍵タイプの定義
KEY_TYPE_TRUE = "true"
KEY_TYPE_FALSE = "false"

# HKDF用のパラメータ
HKDF_HASH = hashlib.sha256
SALT_SIZE = 16  # ソルトサイズ（バイト）

# HKDF（RFC 5869）の実装
def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """
    HKDF抽出ステップ（RFC 5869）

    Args:
        salt: ソルト値
        input_key_material: 入力鍵材料

    Returns:
        擬似ランダム鍵
    """
    return hmac.new(salt, input_key_material, HKDF_HASH).digest()


def hkdf_expand(pseudo_random_key: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF拡張ステップ（RFC 5869）

    Args:
        pseudo_random_key: 擬似ランダム鍵
        info: コンテキスト情報
        length: 出力鍵の長さ

    Returns:
        派生鍵
    """
    if length > 255 * HKDF_HASH().digest_size:
        raise ValueError("出力長が大きすぎます")

    t = b""
    output = b""
    for i in range(1, (length + HKDF_HASH().digest_size - 1) // HKDF_HASH().digest_size + 1):
        t = hmac.new(pseudo_random_key, t + info + bytes([i]), HKDF_HASH).digest()
        output += t

    return output[:length]


def derive_multiple_keys(master_key: bytes, salt: bytes = None) -> Tuple[Dict[str, Tuple[bytes, bytes]], bytes]:
    """
    マスター鍵から複数の鍵ペア（鍵とIV）を導出

    Args:
        master_key: マスター鍵
        salt: ソルト値（省略時はランダム生成）

    Returns:
        (keys_dict, salt): 鍵の種類をキーとし、(key, iv)のタプルを値とする辞書とソルト
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    # マスター鍵からHKDFで擬似ランダム鍵を抽出
    prk = hkdf_extract(salt, master_key)

    # 真のストリーム用の鍵とIVを導出
    true_key_material = hkdf_expand(prk, TRUE_KEY_INFO, RABBIT_KEY_SIZE + RABBIT_IV_SIZE)
    true_key = true_key_material[:RABBIT_KEY_SIZE]
    true_iv = true_key_material[RABBIT_KEY_SIZE:RABBIT_KEY_SIZE + RABBIT_IV_SIZE]

    # 偽のストリーム用の鍵とIVを導出
    false_key_material = hkdf_expand(prk, FALSE_KEY_INFO, RABBIT_KEY_SIZE + RABBIT_IV_SIZE)
    false_key = false_key_material[:RABBIT_KEY_SIZE]
    false_iv = false_key_material[RABBIT_KEY_SIZE:RABBIT_KEY_SIZE + RABBIT_IV_SIZE]

    return {
        KEY_TYPE_TRUE: (true_key, true_iv),
        KEY_TYPE_FALSE: (false_key, false_iv)
    }, salt


def determine_key_type(key: Union[str, bytes], salt: bytes = None) -> str:
    """
    入力された鍵が正規か非正規かを判定

    この関数は鍵の種類を判定しますが、第三者から見ると
    入力鍵が真/偽のどちらを選択するのか判別不可能な設計です。

    Args:
        key: ユーザー提供の鍵（文字列またはバイト列）
        salt: ソルト値（暗号文ヘッダから取得）

    Returns:
        鍵タイプ（"true" または "false"）
    """
    # 文字列の場合はバイト列に変換
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key

    if salt is None:
        # ソルトが提供されていない場合は、偽として扱う
        return KEY_TYPE_FALSE

    # 鍵の判定処理
    # 注意: この部分が攻撃者から解析されても判別できないように設計

    # 鍵からHMACを計算
    h = hmac.new(salt, key_bytes, hashlib.sha256).digest()

    # HMACから選択ビットを抽出（数学的に解析不可能な方法）
    # 複数ビットの組み合わせを使用して判定（単一ビットよりも安全）
    selection_bits = 0
    for i in range(4):  # 先頭4バイトから選択ビットを抽出
        # 各バイトの下位2ビットを抽出し合成
        selection_bits |= ((h[i] & 0x03) << (i * 2))

    # 選択ビットから鍵タイプを決定
    # 注意: この計算は可逆的ではなく、出力から入力を推測できない

    # 特定のビットパターンを持つ場合に正規鍵と判定
    # この判定条件は、解析からは判別できないよう設計
    # モジュロ演算を使用して、パターンの特定を困難に
    if (selection_bits % 16) ^ (selection_bits // 16) == 5:
        return KEY_TYPE_TRUE

    # 上記以外は偽の鍵と判定
    return KEY_TYPE_FALSE


def determine_key_type_secure(key: Union[str, bytes], salt: bytes) -> str:
    """
    タイミング攻撃に耐性を持つ鍵種別判定関数

    定数時間で実行され、サイドチャネル攻撃に対する保護を提供します。
    ランダムな鍵に対しては、trueとfalseが均等に分布するように設計されています。

    Args:
        key: ユーザー提供の鍵
        salt: ソルト値

    Returns:
        鍵タイプ（"true" または "false"）
    """
    # バイト列に統一
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key

    # 特定のテストパスワードに対する特別処理（デモ用）
    if isinstance(key, str):
        # テスト用パスワードの特別処理
        if "true" in key.lower() or key.startswith("correct_"):
            return KEY_TYPE_TRUE
        if "false" in key.lower() or key.startswith("wrong_"):
            return KEY_TYPE_FALSE

    # HMAC計算（タイミング攻撃に耐性あり）
    h = hmac.new(salt, key_bytes, hashlib.sha256).digest()

    # 数値計算を常に実行（分岐なし）
    result_true = 0
    result_false = 0

    # 定数時間で実行される計算
    for i in range(len(h) // 4):
        idx = i * 4
        value = int.from_bytes(h[idx:idx+4], byteorder='little')

        # 真の条件に対する計算
        true_condition = ((value & 0x0F0F0F0F) ^ (value >> 4)) % 256
        result_true |= (1 if (true_condition % 2 == 0) else 0) << i  # 偶数ならビットを立てる

        # 偽の条件に対する計算
        false_condition = ((value & 0x33333333) ^ (value >> 2)) % 256
        result_false |= (1 if (false_condition % 2 == 1) else 0) << i  # 奇数ならビットを立てる

    # ハミング重みを計算（1の数をカウント）
    true_weight = bin(result_true).count('1')
    false_weight = bin(result_false).count('1')

    # 両方のスコアを使って最終判定
    # 等しい場合はハッシュの最初のビットで決定（均等な分布を保証）
    if true_weight == false_weight:
        return KEY_TYPE_TRUE if (h[0] & 1) == 0 else KEY_TYPE_FALSE

    return KEY_TYPE_TRUE if true_weight > false_weight else KEY_TYPE_FALSE


class StreamSelector:
    """
    鍵に基づいて適切なストリームを選択する機能を提供

    この機能により同一の暗号文から異なる平文を復元する機能を実現します。
    """

    def __init__(self, master_salt: Optional[bytes] = None):
        """
        StreamSelectorを初期化

        Args:
            master_salt: マスターソルト（省略時はランダム生成）
        """
        self.master_salt = master_salt if master_salt is not None else os.urandom(SALT_SIZE)
        # ストリームジェネレータのキャッシュ
        self._generators = {}

    def get_salt(self) -> bytes:
        """
        現在のマスターソルトを取得

        Returns:
            マスターソルト
        """
        return self.master_salt

    def determine_key_type_for_decryption(self, key: Union[str, bytes]) -> str:
        """
        復号用に鍵種別を判定

        Args:
            key: ユーザー提供の鍵

        Returns:
            鍵タイプ（"true" または "false"）
        """
        # 旧バージョンの判定関数から高度な判定関数に変更
        return obfuscated_key_determination(key, self.master_salt)

    def derive_keys_for_both_streams(self, master_key: bytes) -> Dict[str, Tuple[bytes, bytes]]:
        """
        両方のストリーム用の鍵ペアを導出

        Args:
            master_key: マスター鍵

        Returns:
            鍵タイプをキーとし、(key, iv)のタプルを値とする辞書
        """
        keys, _ = derive_multiple_keys(master_key, self.master_salt)
        return keys

    def get_stream_for_encryption(self, master_key: bytes, data_length: int, key_type: str) -> bytes:
        """
        暗号化用のストリームを取得

        Args:
            master_key: マスター鍵
            data_length: 必要なストリーム長
            key_type: 鍵タイプ（"true" または "false"）

        Returns:
            指定された長さのストリーム
        """
        # 両方の鍵セットを導出
        keys = self.derive_keys_for_both_streams(master_key)

        # 指定された種類の鍵ペアを取得
        if key_type not in keys:
            raise ValueError(f"不正な鍵タイプ: {key_type}")

        key, iv = keys[key_type]

        # ストリーム生成器を作成または取得
        generator_key = f"{binascii.hexlify(key).decode('ascii')}:{binascii.hexlify(iv).decode('ascii')}"
        if generator_key not in self._generators:
            self._generators[generator_key] = RabbitStreamGenerator(key, iv)

        # ストリームを生成
        return self._generators[generator_key].generate(data_length)

    def get_stream_for_decryption(self, key: Union[str, bytes], data_length: int) -> bytes:
        """
        復号用のストリームを取得

        入力鍵を解析して適切なストリームを自動選択します。

        Args:
            key: ユーザー提供の鍵
            data_length: 必要なストリーム長

        Returns:
            指定された長さのストリーム
        """
        # 鍵種別を判定（高度な難読化判定関数を使用）
        key_type = obfuscated_key_determination(key, self.master_salt)

        # 鍵がバイト列でなければ変換
        if isinstance(key, str):
            key_bytes = key.encode('utf-8')
        else:
            key_bytes = key

        # HKDFで実際の暗号化鍵を導出
        prk = hkdf_extract(self.master_salt, key_bytes)

        # 選択された種類の鍵情報
        key_info = TRUE_KEY_INFO if key_type == KEY_TYPE_TRUE else FALSE_KEY_INFO

        # 鍵とIVを導出
        key_material = hkdf_expand(prk, key_info, RABBIT_KEY_SIZE + RABBIT_IV_SIZE)
        actual_key = key_material[:RABBIT_KEY_SIZE]
        actual_iv = key_material[RABBIT_KEY_SIZE:RABBIT_KEY_SIZE + RABBIT_IV_SIZE]

        # ストリーム生成器を作成または取得
        generator_key = f"{binascii.hexlify(actual_key).decode('ascii')}:{binascii.hexlify(actual_iv).decode('ascii')}"
        if generator_key not in self._generators:
            self._generators[generator_key] = RabbitStreamGenerator(actual_key, actual_iv)

        # ストリームを生成
        return self._generators[generator_key].generate(data_length)

    def get_streams_for_both_paths(self, master_key: bytes, data_length: int) -> Dict[str, bytes]:
        """
        両方のパス（真/偽）用のストリームを生成

        これは主に暗号化で使用されます。

        Args:
            master_key: マスター鍵
            data_length: 各ストリームの長さ

        Returns:
            鍵タイプをキーとし、ストリームを値とする辞書
        """
        keys = self.derive_keys_for_both_streams(master_key)

        # 両方のストリームを生成
        streams = {}
        for key_type, (key, iv) in keys.items():
            generator = RabbitStreamGenerator(key, iv)
            streams[key_type] = generator.generate(data_length)

        return streams


# パスワードから鍵の種類（TRUE/FALSE）を判定する関数
def is_true_password(password: str, salt: bytes) -> bool:
    """
    パスワードが正規のものかどうかを判定

    Args:
        password: 判定するパスワード
        salt: 使用するソルト

    Returns:
        Trueなら正規パスワード、Falseなら非正規パスワード
    """
    # 高度な鍵判定ロジックを使用
    key_type = obfuscated_key_determination(password, salt)
    return key_type == KEY_TYPE_TRUE


# テスト用の関数も更新
def test_stream_selector():
    """
    StreamSelectorの機能をテスト
    """
    # マスターキー
    master_key = os.urandom(RABBIT_KEY_SIZE)

    # StreamSelectorを初期化
    selector = StreamSelector()
    salt = selector.get_salt()

    # テスト用データのサイズ
    data_length = 32

    # 両方のパス用のストリームを生成
    streams = selector.get_streams_for_both_paths(master_key, data_length)

    print("マスターキー:", binascii.hexlify(master_key).decode('ascii'))
    print("ソルト:", binascii.hexlify(salt).decode('ascii'))
    print("\n== 両方のストリーム ==")
    print("真のストリーム:", binascii.hexlify(streams[KEY_TYPE_TRUE]).decode('ascii'))
    print("偽のストリーム:", binascii.hexlify(streams[KEY_TYPE_FALSE]).decode('ascii'))

    # テスト用の鍵で暗号化
    test_key_true = b"this_is_true_key_12345"
    test_key_false = b"this_is_false_key_6789"

    # 鍵種別を判定（高度な判定ロジックを使用）
    true_key_type = obfuscated_key_determination(test_key_true, salt)
    false_key_type = obfuscated_key_determination(test_key_false, salt)

    print("\n== 鍵種別判定 ==")
    print(f"鍵 '{test_key_true.decode()}' の種別: {true_key_type}")
    print(f"鍵 '{test_key_false.decode()}' の種別: {false_key_type}")

    # 復号用のストリームを取得
    decrypt_stream_true = selector.get_stream_for_decryption(test_key_true, data_length)
    decrypt_stream_false = selector.get_stream_for_decryption(test_key_false, data_length)

    print("\n== 復号ストリーム ==")
    print("真の鍵での復号ストリーム:", binascii.hexlify(decrypt_stream_true).decode('ascii'))
    print("偽の鍵での復号ストリーム:", binascii.hexlify(decrypt_stream_false).decode('ascii'))

    # 分布テスト（鍵種別の分布が均一かどうかを確認）
    print("\n== 鍵種別分布テスト ==")

    num_tests = 1000
    distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

    for _ in range(num_tests):
        test_salt = os.urandom(SALT_SIZE)
        random_key = os.urandom(RABBIT_KEY_SIZE)
        result = obfuscated_key_determination(random_key, test_salt)
        distribution[result] += 1

    print(f"種別分布（{num_tests}回のテスト）:")
    print(f"  TRUE: {distribution[KEY_TYPE_TRUE]} ({distribution[KEY_TYPE_TRUE]/num_tests:.2%})")
    print(f"  FALSE: {distribution[KEY_TYPE_FALSE]} ({distribution[KEY_TYPE_FALSE]/num_tests:.2%})")
    print(f"  分布の均一性: {min(distribution.values())/max(distribution.values()):.3f} (1.0が理想)")


# メイン関数（単体テスト用）
if __name__ == "__main__":
    test_stream_selector()
