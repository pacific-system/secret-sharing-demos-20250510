#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ストリーム選択機構

鍵に応じて異なる暗号ストリームを選択する機能を提供します。
"""

import os
import hashlib
import hmac
from typing import Tuple, List, Optional, Union, Callable
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
        MAGIC_XOR_VALUE
    )
    from method_6_rabbit.rabbit_stream import RabbitStreamGenerator, derive_key
else:
    from .config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        TRUE_KEY_MARKER,
        FALSE_KEY_MARKER,
        STREAM_SELECTOR_SEED,
        MAGIC_VALUE_1,
        MAGIC_VALUE_2,
        MAGIC_XOR_VALUE
    )
    from .rabbit_stream import RabbitStreamGenerator, derive_key


class StreamSelector:
    """
    鍵に応じてストリームを選択するクラス

    指定された鍵がTRUE_KYEかFALSE_KEYかを判別し、
    適切なストリームジェネレータを提供します。これにより
    同一の暗号文から異なる平文を復元することができます。
    """

    def __init__(self, key: bytes, iv: bytes):
        """
        StreamSelectorを初期化

        Args:
            key: 16バイトの鍵
            iv: 8バイトのIV
        """
        self.key = key
        self.iv = iv
        self.true_generator = None
        self.false_generator = None

        # 鍵の種類に関する情報を初期化
        self._initialize_key_info()

    def _initialize_key_info(self) -> None:
        """
        鍵の種類（TRUE/FALSE）を判別するロジックを適用

        正規鍵と非正規鍵の判別処理はスクリプト解析から保護されています。
        """
        # 鍵情報から特徴を抽出（解析困難なロジック）
        # このロジックはソースコード解析から保護する必要があります

        # HMAC-SHA256を使用して鍵の特徴を抽出
        h = hmac.new(
            bytes([STREAM_SELECTOR_SEED] * 16),  # シード値
            self.key,  # メッセージは鍵
            hashlib.sha256
        ).digest()

        # 抽出したハッシュと鍵からさらに特徴を計算
        feature = int.from_bytes(h[:8], byteorder='little')

        # マジック値を使用して特徴を変換
        transformed_feature = ((feature ^ MAGIC_XOR_VALUE) * MAGIC_VALUE_1) & 0xFFFFFFFFFFFFFFFF

        # 結果を解析困難な方法で評価
        # この部分はあえて複雑にして、静的解析を困難にしています
        self.is_true_key = self._complex_key_verification(transformed_feature)

    def _complex_key_verification(self, value: int) -> bool:
        """
        鍵検証の複雑なロジック

        値のビットパターンを分析して、TRUE/FALSEを判定します。
        このロジックは解析からの保護のため、あえて複雑にしています。

        Args:
            value: 検証する値

        Returns:
            Trueなら正規鍵、Falseなら非正規鍵
        """
        # ビットパターンを計算
        bit_sum = 0
        temp = value

        # ビットカウント（ポピュレーションカウント）
        for _ in range(64):
            bit_sum += temp & 1
            temp >>= 1

        # 別の特徴も計算
        rotation = (value & 0xFF) % 64
        rotated = ((value >> rotation) | (value << (64 - rotation))) & 0xFFFFFFFFFFFFFFFF

        # 最終計算（マジック値との関係）
        result = (rotated ^ MAGIC_VALUE_2) & MAGIC_VALUE_1

        # 本来ならもっと複雑なロジックにする
        # 実際の実装では、より多くの計算を行うことで解析困難性を高めます
        marker = (bit_sum * result) & 0xFF

        # 実際には、鍵の使用目的に応じてマーカーを計算
        # このデモでは単純化のため、直接比較を行います
        return marker % 2 == 0  # 任意の条件で分岐

    def generate_stream(self, length: int) -> bytes:
        """
        指定された長さのストリームを生成

        鍵の種類に応じて、適切なストリームを生成します。

        Args:
            length: 生成するストリームの長さ（バイト単位）

        Returns:
            生成されたストリーム
        """
        # 実装上は両方のジェネレータを生成（実行時間攻撃対策）
        true_gen = RabbitStreamGenerator(self.key, self.iv)
        false_gen = RabbitStreamGenerator(
            bytes([(b + TRUE_KEY_MARKER) % 256 for b in self.key]),  # 鍵を変化させる
            self.iv
        )

        # 両方のストリームを生成
        true_stream = true_gen.generate(length)
        false_stream = false_gen.generate(length)

        # 鍵の種類に応じて適切なストリームを返す
        if self.is_true_key:
            return true_stream
        else:
            return false_stream

    def get_generator(self) -> RabbitStreamGenerator:
        """
        鍵の種類に応じたRabbitStreamGeneratorを取得

        Returns:
            適切なRabbitStreamGenerator
        """
        # 実装上は両方のジェネレータを生成（実行時間攻撃対策）
        if self.true_generator is None:
            self.true_generator = RabbitStreamGenerator(self.key, self.iv)

        if self.false_generator is None:
            # 非正規鍵用のジェネレータは別の鍵で初期化
            transformed_key = bytes([(b + TRUE_KEY_MARKER) % 256 for b in self.key])
            self.false_generator = RabbitStreamGenerator(transformed_key, self.iv)

        # 鍵の種類に応じて適切なジェネレータを返す
        if self.is_true_key:
            return self.true_generator
        else:
            return self.false_generator


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
    # パスワードから鍵を導出
    key, iv, _ = derive_key(password, salt)

    # StreamSelectorを使って判定
    selector = StreamSelector(key, iv)

    return selector.is_true_key


# メイン関数（単体テスト用）
if __name__ == "__main__":
    # テスト用にランダムな鍵とIVを生成
    test_key = os.urandom(RABBIT_KEY_SIZE)
    test_iv = os.urandom(RABBIT_IV_SIZE)

    print("ストリーム選択機構テスト")
    print(f"テスト鍵: {binascii.hexlify(test_key).decode('ascii')}")
    print(f"テストIV: {binascii.hexlify(test_iv).decode('ascii')}")

    # StreamSelectorを初期化
    selector = StreamSelector(test_key, test_iv)

    # 鍵の種類を表示
    print(f"鍵の種類: {'正規鍵 (TRUE)' if selector.is_true_key else '非正規鍵 (FALSE)'}")

    # 正規鍵と非正規鍵のストリームを比較
    true_gen = RabbitStreamGenerator(test_key, test_iv)
    transformed_key = bytes([(b + TRUE_KEY_MARKER) % 256 for b in test_key])
    false_gen = RabbitStreamGenerator(transformed_key, test_iv)

    true_stream = true_gen.generate(16)
    false_stream = false_gen.generate(16)
    selected_stream = selector.generate_stream(16)

    print(f"正規ストリーム: {binascii.hexlify(true_stream).decode('ascii')}")
    print(f"非正規ストリーム: {binascii.hexlify(false_stream).decode('ascii')}")
    print(f"選択されたストリーム: {binascii.hexlify(selected_stream).decode('ascii')}")

    # 期待される選択と一致しているかを検証
    if selector.is_true_key:
        expected_stream = true_stream
    else:
        expected_stream = false_stream

    print(f"検証: {'成功' if selected_stream == expected_stream else '失敗'}")

    # パスワードテスト
    print("\nパスワードテスト:")
    test_salt = os.urandom(16)
    passwords = ["CorrectPassword123!", "WrongPassword456!", "AnotherPassword789!"]

    for pwd in passwords:
        is_true = is_true_password(pwd, test_salt)
        print(f"パスワード '{pwd}': {'正規 (TRUE)' if is_true else '非正規 (FALSE)'}")
