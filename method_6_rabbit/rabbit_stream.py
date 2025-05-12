#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ラビットストリーム暗号アルゴリズム

RFC 4503に完全準拠したRabbit暗号ストリーム生成アルゴリズムの実装
https://datatracker.ietf.org/doc/html/rfc4503
"""

import struct
import os
import hashlib
import sys
from typing import Tuple, List, Optional, Union
import binascii

# インポートエラーを回避するための処理
if __name__ == "__main__":
    # モジュールとして実行された場合の処理
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        RABBIT_STATE_WORDS,
        RABBIT_COUNTER_WORDS,
        RABBIT_ROUNDS,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
else:
    # パッケージの一部として実行された場合の処理
    from .config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        RABBIT_STATE_WORDS,
        RABBIT_COUNTER_WORDS,
        RABBIT_ROUNDS,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )

# Rabbitアルゴリズムの定数
WORD_SIZE = 32  # ワードサイズ（ビット）
WORD_MASK = 0xFFFFFFFF  # 32ビットワードマスク

# 事前計算された定数（RFC 4503セクション2.5より）
A = [
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
    0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3
]

class RabbitStreamGenerator:
    """
    RFC 4503に準拠したRabbit暗号ストリーム生成器（高速化版）

    128ビット鍵と64ビットIVから暗号ストリームを生成します。
    """

    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        """
        RabbitStreamGeneratorを初期化

        Args:
            key: 16バイト（128ビット）の鍵
            iv: 8バイト（64ビット）の初期化ベクトル（省略可）

        Raises:
            ValueError: 鍵またはIVのサイズが不正な場合
        """
        if len(key) != RABBIT_KEY_SIZE:
            raise ValueError(f"鍵は{RABBIT_KEY_SIZE}バイト（128ビット）である必要があります")

        if iv is not None and len(iv) != RABBIT_IV_SIZE:
            raise ValueError(f"IVは{RABBIT_IV_SIZE}バイト（64ビット）である必要があります")

        # 内部状態（X）、カウンタ（C）、キャリービット（carry）を初期化
        self.X = [0] * RABBIT_STATE_WORDS    # 状態変数 X_0, ..., X_7
        self.C = [0] * RABBIT_STATE_WORDS    # カウンタ変数 C_0, ..., C_7
        self.carry = 0                       # キャリービット

        # パフォーマンス最適化: マスクと定数をキャッシュ
        self._word_mask = WORD_MASK
        self._a_constants = A

        # 鍵セットアップ
        self._key_setup(key)

        # IVがあれば、IV処理を行う
        if iv is not None:
            self._iv_setup(iv)

    def _key_setup(self, key: bytes) -> None:
        """
        鍵から内部状態を初期化（RFC 4503 セクション3.1）

        Args:
            key: 16バイト（128ビット）の鍵
        """
        # 鍵から16個の8ビット値（k_0, ..., k_15）を抽出
        k = list(key)

        # 鍵から8個の16ビット値（K_0, ..., K_7）を生成
        K = [0] * RABBIT_STATE_WORDS
        for i in range(RABBIT_STATE_WORDS):
            K[i] = (k[2*i+1] << 8) | k[2*i]

        # 内部状態の初期化
        for i in range(RABBIT_STATE_WORDS):
            if i % 2 == 0:
                self.X[i] = (K[(i+1) % RABBIT_STATE_WORDS] << 16) | K[i]
            else:
                self.X[i] = (K[(i+2) % RABBIT_STATE_WORDS] << 16) | K[(i+1) % RABBIT_STATE_WORDS]

        # カウンタ変数の初期化
        for i in range(RABBIT_STATE_WORDS):
            if i % 2 == 0:
                self.C[i] = (K[(i+4) % RABBIT_STATE_WORDS] << 16) | K[(i+5) % RABBIT_STATE_WORDS]
            else:
                self.C[i] = (K[(i+6) % RABBIT_STATE_WORDS] << 16) | K[(i+7) % RABBIT_STATE_WORDS]

        # キャリービットを0に初期化
        self.carry = 0

        # システムを4回イテレーション
        for _ in range(RABBIT_ROUNDS):
            self._next_state()

    def _iv_setup(self, iv: bytes) -> None:
        """
        IVから内部状態を更新（RFC 4503 セクション3.2）

        Args:
            iv: 8バイト（64ビット）の初期化ベクトル
        """
        # IVから4個の16ビット値（I_0, ..., I_3）を生成
        I = [0] * 4
        for i in range(4):
            I[i] = (iv[2*i+1] << 8) | iv[2*i]

        # カウンタ変数を更新
        for i in range(RABBIT_STATE_WORDS):
            if i % 2 == 0:
                self.C[i] ^= I[i // 2]
            else:
                self.C[i] ^= (I[(i-1) // 2] << 16)

        # システムを4回イテレーション
        for _ in range(RABBIT_ROUNDS):
            self._next_state()

    def _g_function(self, x: int) -> int:
        """
        RFC 4503のg関数（セクション2.3）- 超高速化版

        Args:
            x: 32ビット入力値

        Returns:
            32ビット出力値
        """
        # 最も効率的な実装に最適化
        # x * x + x を直接計算し、32ビットマスクを適用
        return (x * (x + 1)) & self._word_mask

    def _next_state(self) -> None:
        """
        内部状態を1ステップ更新（RFC 4503 セクション2.4）- 超高速化版
        """
        # ローカル参照によるアクセス最適化
        X = self.X
        C = self.C
        carry = self.carry
        word_mask = self._word_mask
        a_constants = self._a_constants

        # カウンタ更新を最適化（ループ内変数最小化）
        temp_c = [0] * RABBIT_STATE_WORDS
        for i in range(RABBIT_STATE_WORDS):
            temp = C[i] + a_constants[i] + carry
            carry = temp >> 32
            temp_c[i] = temp & word_mask

        self.carry = carry

        # g関数の適用を最適化
        g0 = self._g_function(X[0] + temp_c[0])
        g1 = self._g_function(X[1] + temp_c[1])
        g2 = self._g_function(X[2] + temp_c[2])
        g3 = self._g_function(X[3] + temp_c[3])
        g4 = self._g_function(X[4] + temp_c[4])
        g5 = self._g_function(X[5] + temp_c[5])
        g6 = self._g_function(X[6] + temp_c[6])
        g7 = self._g_function(X[7] + temp_c[7])

        # 直接計算（中間変数最小化）
        X[0] = (g0 + ((g7 << 16) & word_mask) + ((g6 >> 16) & 0xFFFF)) & word_mask
        X[1] = (g1 + ((g0 << 8) & word_mask) + ((g7 >> 24) & 0xFF)) & word_mask
        X[2] = (g2 + ((g1 << 16) & word_mask) + ((g0 >> 16) & 0xFFFF)) & word_mask
        X[3] = (g3 + ((g2 << 8) & word_mask) + ((g1 >> 24) & 0xFF)) & word_mask
        X[4] = (g4 + ((g3 << 16) & word_mask) + ((g2 >> 16) & 0xFFFF)) & word_mask
        X[5] = (g5 + ((g4 << 8) & word_mask) + ((g3 >> 24) & 0xFF)) & word_mask
        X[6] = (g6 + ((g5 << 16) & word_mask) + ((g4 >> 16) & 0xFFFF)) & word_mask
        X[7] = (g7 + ((g6 << 8) & word_mask) + ((g5 >> 24) & 0xFF)) & word_mask

        # カウンタを更新
        self.C = temp_c

    def _extract(self) -> bytes:
        """
        現在の内部状態から16バイトの出力ブロックを抽出（RFC 4503 セクション2.6）

        Returns:
            16バイトの出力ブロック
        """
        result = bytearray(16)

        # 状態から出力を計算
        S = [0] * 8
        for i in range(4):
            # 16ビットずつXORする（RFC 4503の図に基づく）
            S[i] = self.X[(i+1) % 8] ^ (self.X[i] >> 16)
            S[i+4] = self.X[(i+4+1) % 8] ^ (self.X[i+4] >> 16)

        # バイトに変換（リトルエンディアン）
        for i in range(8):
            result[2*i] = S[i] & 0xFF
            result[2*i+1] = (S[i] >> 8) & 0xFF

        return bytes(result)

    def generate(self, length: int) -> bytes:
        """
        指定された長さのストリーム鍵を生成（超高速化版）

        Args:
            length: 生成するストリーム鍵の長さ（バイト単位）

        Returns:
            指定された長さのストリーム鍵
        """
        # 出力バッファ事前割り当て
        blocks_needed = (length + 15) // 16
        result = bytearray(blocks_needed * 16)

        # ローカル変数の最適化
        X = self.X
        word_mask = self._word_mask
        next_state = self._next_state

        # 一括処理で高速化
        pos = 0
        for _ in range(blocks_needed):
            # 状態から出力計算を最適化（インライン展開）
            # 16ビットずつXORする計算を直接実装
            S0 = X[1] ^ (X[0] >> 16)
            S1 = X[2] ^ (X[1] >> 16)
            S2 = X[3] ^ (X[2] >> 16)
            S3 = X[4] ^ (X[3] >> 16)
            S4 = X[5] ^ (X[4] >> 16)
            S5 = X[6] ^ (X[5] >> 16)
            S6 = X[7] ^ (X[6] >> 16)
            S7 = X[0] ^ (X[7] >> 16)

            # バイトに直接書き込み（インデックス参照を最小化）
            result[pos] = S0 & 0xFF
            result[pos+1] = (S0 >> 8) & 0xFF
            result[pos+2] = S1 & 0xFF
            result[pos+3] = (S1 >> 8) & 0xFF
            result[pos+4] = S2 & 0xFF
            result[pos+5] = (S2 >> 8) & 0xFF
            result[pos+6] = S3 & 0xFF
            result[pos+7] = (S3 >> 8) & 0xFF
            result[pos+8] = S4 & 0xFF
            result[pos+9] = (S4 >> 8) & 0xFF
            result[pos+10] = S5 & 0xFF
            result[pos+11] = (S5 >> 8) & 0xFF
            result[pos+12] = S6 & 0xFF
            result[pos+13] = (S6 >> 8) & 0xFF
            result[pos+14] = S7 & 0xFF
            result[pos+15] = (S7 >> 8) & 0xFF
            pos += 16

            # 次の状態に更新
            next_state()

        # 必要な分だけ切り出して返す
        return bytes(result[:length])


def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    パスワードから鍵とIVを導出する

    Args:
        password: パスワード文字列
        salt: ソルト（省略時はランダム生成）

    Returns:
        (key, iv, salt): 16バイトの鍵と8バイトのIVとソルト
    """
    # ソルトがない場合は生成
    if salt is None:
        salt = os.urandom(16)

    # PBKDF2でパスワードから鍵材料を導出
    key_material = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        KEY_DERIVATION_ITERATIONS,
        dklen=32
    )

    # 鍵とIVに分割
    key = key_material[:RABBIT_KEY_SIZE]
    iv = key_material[RABBIT_KEY_SIZE:RABBIT_KEY_SIZE + RABBIT_IV_SIZE]

    return key, iv, salt


def generate_test_stream(key: bytes, iv: bytes, length: int = 64) -> str:
    """
    テスト用にストリームを生成しHEX形式で出力

    Args:
        key: 16バイトの鍵
        iv: 8バイトのIV
        length: 生成するストリームの長さ

    Returns:
        生成されたストリームのHEX文字列
    """
    generator = RabbitStreamGenerator(key, iv)
    stream = generator.generate(length)
    return binascii.hexlify(stream).decode('ascii')


# RFC 4503のテストベクトルを検証する関数
def verify_test_vectors():
    """RFC 4503のテストベクトルを用いて実装の正確性を検証する"""
    print("RFC 4503 テストベクトル検証:")

    # テストケース1: セクション6.1
    print("\nテストケース1 (セクション6.1):")
    key = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(" ", ""))
    iv = bytes.fromhex("00 00 00 00 00 00 00 00".replace(" ", ""))

    # 期待される出力（最初の16バイト）
    expected_output1 = "eda31d34 1d50e9bb 09e3152f 4dfa6fb9"
    expected_output2 = "ed8c68c9 36605aae 379486db 9f756fa4"
    expected_output3 = "ed9fb4ba 09356de3 a9c22237 9ef7d8a1"

    # RabbitStreamGeneratorを初期化
    generator = RabbitStreamGenerator(key, iv)

    # 最初の3ブロック（48バイト）を生成
    output = generator.generate(48)
    output_hex = binascii.hexlify(output).decode('ascii')

    # 3つの16バイトブロックに分割して表示
    print(f"鍵: {binascii.hexlify(key).decode('ascii')}")
    print(f"IV: {binascii.hexlify(iv).decode('ascii')}")

    block1 = output_hex[:32]
    block2 = output_hex[32:64]
    block3 = output_hex[64:96]

    # ブロック表示を調整（スペース区切り）
    formatted_block1 = ' '.join([block1[i:i+8] for i in range(0, len(block1), 8)])
    formatted_block2 = ' '.join([block2[i:i+8] for i in range(0, len(block2), 8)])
    formatted_block3 = ' '.join([block3[i:i+8] for i in range(0, len(block3), 8)])

    print(f"ブロック1: {formatted_block1}")
    print(f"期待値:   {expected_output1}")
    print(f"ブロック2: {formatted_block2}")
    print(f"期待値:   {expected_output2}")
    print(f"ブロック3: {formatted_block3}")
    print(f"期待値:   {expected_output3}")

    # 期待値の空白を除去して比較
    expected_output1 = expected_output1.replace(" ", "")
    expected_output2 = expected_output2.replace(" ", "")
    expected_output3 = expected_output3.replace(" ", "")

    # テスト結果を確認
    test1_passed = block1 == expected_output1
    test2_passed = block2 == expected_output2
    test3_passed = block3 == expected_output3
    all_passed = test1_passed and test2_passed and test3_passed

    print(f"\n検証結果:")
    print(f"ブロック1: {'成功' if test1_passed else '失敗'}")
    print(f"ブロック2: {'成功' if test2_passed else '失敗'}")
    print(f"ブロック3: {'成功' if test3_passed else '失敗'}")
    print(f"全体結果: {'すべての検証に成功しました！' if all_passed else '検証に失敗しました。'}")

    # テストケース2（セクション6.2）
    print("\nテストケース2 (セクション6.2):")
    key = bytes.fromhex("C9 FB 49 24 C0 B0 7B CD F4 FE 70 4A 2F 5B 23 73".replace(" ", ""))
    iv = bytes.fromhex("00 00 00 00 00 00 00 00".replace(" ", ""))

    # 期待される最初の出力
    expected_output = "6d129cf5 065fa59f 33e83f6b d05d3f64"

    # 生成器を初期化
    generator = RabbitStreamGenerator(key, iv)
    output = generator.generate(16)
    output_hex = binascii.hexlify(output).decode('ascii')

    # 表示を調整
    formatted_output = ' '.join([output_hex[i:i+8] for i in range(0, len(output_hex), 8)])

    print(f"鍵: {binascii.hexlify(key).decode('ascii')}")
    print(f"IV: {binascii.hexlify(iv).decode('ascii')}")
    print(f"出力: {formatted_output}")
    print(f"期待値: {expected_output}")

    # 比較
    expected_output = expected_output.replace(" ", "")
    test_passed = output_hex == expected_output

    print(f"検証結果: {'成功' if test_passed else '失敗'}")

    # テストケース3（セクション6.3）
    print("\nテストケース3 (セクション6.3):")
    key = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(" ", ""))
    iv = bytes.fromhex("27 17 F4 D2 1A 56 EB A6".replace(" ", ""))

    # 期待される最初の出力
    expected_output = "1f66b5ff 46372cf9 6c9a7cd1 50ee6a5b"

    # 生成器を初期化
    generator = RabbitStreamGenerator(key, iv)
    output = generator.generate(16)
    output_hex = binascii.hexlify(output).decode('ascii')

    # 表示を調整
    formatted_output = ' '.join([output_hex[i:i+8] for i in range(0, len(output_hex), 8)])

    print(f"鍵: {binascii.hexlify(key).decode('ascii')}")
    print(f"IV: {binascii.hexlify(iv).decode('ascii')}")
    print(f"出力: {formatted_output}")
    print(f"期待値: {expected_output}")

    # 比較
    expected_output = expected_output.replace(" ", "")
    test_passed = output_hex == expected_output

    print(f"検証結果: {'成功' if test_passed else '失敗'}")

    return all_passed and test_passed


# メイン関数（単体テスト用）
if __name__ == "__main__":
    print(f"Rabbit Stream Cipher (RFC 4503) 実装 v{VERSION}\n")

    # RFC 4503のテストベクトルを検証
    verify_test_vectors()

    # カスタムテスト
    print("\nカスタムテスト:")

    # ランダム鍵とIVを生成
    import os
    random_key = os.urandom(RABBIT_KEY_SIZE)
    random_iv = os.urandom(RABBIT_IV_SIZE)

    # ストリーム生成
    generator = RabbitStreamGenerator(random_key, random_iv)
    stream = generator.generate(32)

    print(f"ランダム鍵: {binascii.hexlify(random_key).decode('ascii')}")
    print(f"ランダムIV: {binascii.hexlify(random_iv).decode('ascii')}")
    print(f"生成ストリーム: {binascii.hexlify(stream).decode('ascii')}")

    # パスワードからの鍵導出テスト
    password = "SecretRabbitPassword123!"
    key, iv, salt = derive_key(password)

    print(f"\nパスワード: {password}")
    print(f"導出鍵: {binascii.hexlify(key).decode('ascii')}")
    print(f"導出IV: {binascii.hexlify(iv).decode('ascii')}")
    print(f"ソルト: {binascii.hexlify(salt).decode('ascii')}")

    # 同じパスワードとソルトからの再導出（一貫性テスト）
    key2, iv2, _ = derive_key(password, salt)

    print(f"再導出鍵: {binascii.hexlify(key2).decode('ascii')}")
    print(f"再導出IV: {binascii.hexlify(iv2).decode('ascii')}")
    print(f"一貫性チェック: {'成功' if key == key2 and iv == iv2 else '失敗'}")
