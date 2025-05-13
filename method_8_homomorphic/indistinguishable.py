#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
識別不能性（Indistinguishable）機能

このモジュールは、準同型暗号マスキング方式において、
真のファイルと偽のファイルを計算論的に区別することが不可能となる
識別不能性（Indistinguishability）を提供します。
"""

import os
import hashlib
import random
import time
import binascii
import secrets
import numpy as np
from typing import Dict, List, Tuple, Union, Any, Callable, Optional

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    KDF_ITERATIONS,
    SECURITY_PARAMETER
)
from method_8_homomorphic.homomorphic import PaillierCrypto


class IndistinguishableWrapper:
    """識別不能性を提供するラッパークラス"""

    def __init__(self):
        """初期化"""
        self.seed = None
        self.counter = 0

    def generate_seed(self, key: bytes, salt: bytes) -> bytes:
        """
        識別不能性のためのシードを生成

        Args:
            key: 鍵データ
            salt: ソルト

        Returns:
            シードデータ
        """
        # 鍵とソルトからシードを派生
        kdf_input = key + salt
        self.seed = hashlib.pbkdf2_hmac('sha256', kdf_input, salt, KDF_ITERATIONS, 32)

        # カウンタをリセット
        self.counter = 0

        return self.seed

    def is_true_path(self, key: bytes, salt: bytes) -> bool:
        """
        真偽の判定を行う
        識別不能性を確保するため、計算量的に区別不可能な実装

        Args:
            key: 鍵データ
            salt: ソルト

        Returns:
            True: 真の経路, False: 偽の経路
        """
        if self.seed is None:
            self.generate_seed(key, salt)

        # カウンタを増加
        self.counter += 1

        # 現在のシードとカウンタを組み合わせて一時的なキーを生成
        counter_bytes = self.counter.to_bytes(8, byteorder='big')
        temp_key = hashlib.sha256(self.seed + counter_bytes).digest()

        # 最初のバイトを使用して真偽を決定
        # 単純な偶数/奇数ではなく、計算量的に予測困難な方法を使用

        # 単純なビット操作ではなく、複数のビットにわたる複雑な条件チェック
        bit_count = bin(int.from_bytes(temp_key[:4], byteorder='big')).count('1')
        hamming_weight = bit_count / 32

        # 異なる複数条件の組み合わせによる判定
        condition1 = temp_key[0] % 2 == 0
        condition2 = (temp_key[1] & 0x0F) > (temp_key[1] & 0xF0) >> 4
        condition3 = hamming_weight > 0.5
        condition4 = (temp_key[2] ^ temp_key[3]) % 3 == 0

        # 複数条件の組み合わせで識別不能性を高める
        # 条件の複雑さにより、単純なビットパターン分析では予測不可能
        return (condition1 and condition2) or (condition3 and condition4)

    def obfuscate_data(self, data: bytes, iterations: int = 3) -> bytes:
        """
        データに識別不能性のための難読化を適用

        Args:
            data: 難読化するデータ
            iterations: 難読化の反復回数

        Returns:
            難読化されたデータ
        """
        if self.seed is None:
            raise ValueError("シードが初期化されていません。generate_seed()を先に呼び出してください。")

        # 結果をbytearrayにして各操作を行う
        result = bytearray(data)

        for i in range(iterations):
            # 現在の反復に基づいた一時的なシードを生成
            iter_seed = hashlib.sha256(self.seed + i.to_bytes(4, byteorder='big')).digest()
            random.seed(int.from_bytes(iter_seed, byteorder='big'))

            # データの各バイトに対してXOR操作を実行
            xor_mask = [random.randint(0, 255) for _ in range(len(result))]

            # XOR操作をbytearrayに適用
            for j in range(len(result)):
                result[j] ^= xor_mask[j]

            # バイト順序の入れ替え（置換）
            indices = list(range(len(result)))
            random.shuffle(indices)

            # シャッフルされた順序で新しいバイト列を作成
            shuffled = bytearray(len(result))
            for j, idx in enumerate(indices):
                if idx < len(result):
                    shuffled[j] = result[idx]

            # インデックスマップを生成（復号時に使用）
            index_map = bytearray([indices.index(k) if k in indices else 0 for k in range(len(result))])

            # 結果にインデックスマップを追加して更新
            result = index_map + shuffled

        # 最終的にbytesに変換して返す
        return bytes(result)

    def deobfuscate_data(self, data: bytes, iterations: int = 3) -> bytes:
        """
        識別不能性のために難読化されたデータを復元

        Args:
            data: 難読化されたデータ
            iterations: 適用された難読化の反復回数

        Returns:
            復元されたデータ
        """
        if self.seed is None:
            raise ValueError("シードが初期化されていません。generate_seed()を先に呼び出してください。")

        # データをbytearrayにして操作
        result = bytearray(data)
        original_data_size = len(data)

        # 反復を逆順に処理
        for i in range(iterations - 1, -1, -1):
            # 現在の反復に基づいた一時的なシードを生成
            iter_seed = hashlib.sha256(self.seed + i.to_bytes(4, byteorder='big')).digest()
            random.seed(int.from_bytes(iter_seed, byteorder='big'))

            # 各イテレーションで、データサイズはオリジナルより大きくなる
            # 元のサイズを計算し、インデックスマップとデータを分離
            actual_data_size = len(result) // (i + 2)  # 近似値

            # インデックスマップとデータを分離
            index_map = result[:actual_data_size]
            shuffled_data = result[actual_data_size:]

            # シャッフルを元に戻す
            unshuffled = bytearray(len(shuffled_data))
            for j, idx in enumerate(index_map):
                if j < len(shuffled_data) and idx < len(unshuffled):
                    unshuffled[idx] = shuffled_data[j]

            # データの各バイトに対してXOR操作を元に戻す
            xor_mask = [random.randint(0, 255) for _ in range(len(unshuffled))]

            # 同じXORマスクを適用して元に戻す
            for j in range(len(unshuffled)):
                unshuffled[j] ^= xor_mask[j]

            result = unshuffled

        # 元のデータサイズで切り詰め
        return bytes(result[:original_data_size // (iterations + 1)])

    def time_equalizer(self, func: Callable, *args, **kwargs) -> Any:
        """
        関数実行時間を均等化し、タイミング攻撃への耐性を提供

        Args:
            func: 実行する関数
            *args: 関数に渡す位置引数
            **kwargs: 関数に渡すキーワード引数

        Returns:
            関数の戻り値
        """
        # 実行開始時刻を記録
        start_time = time.time()

        # 関数を実行
        result = func(*args, **kwargs)

        # 実行完了時刻を記録
        end_time = time.time()

        # 最小実行時間（50ms）
        min_execution_time = 0.05

        # 実際の経過時間
        elapsed = end_time - start_time

        # 最小実行時間より早く終わった場合は待機
        if elapsed < min_execution_time:
            time.sleep(min_execution_time - elapsed)

        return result


# 準同型暗号の識別不能性機能
def randomize_ciphertext(paillier: PaillierCrypto, ciphertext: int) -> int:
    """
    暗号文のランダム化（準同型再ランダム化）

    同じ平文を暗号化しても毎回異なる暗号文が生成されるようにします。
    準同型性を維持したまま、暗号文にランダム性を加えます。

    Args:
        paillier: 準同型暗号システムのインスタンス
        ciphertext: ランダム化する暗号文

    Returns:
        ランダム化された暗号文
    """
    if paillier.public_key is None:
        raise ValueError("公開鍵が設定されていません")

    n = paillier.public_key['n']
    n_squared = n * n

    # ランダムな値 r (0 < r < n)
    r = random.randint(1, n - 1)

    # r^n mod n^2
    rn = pow(r, n, n_squared)

    # ランダム化: c' = c * r^n mod n^2
    # これにより平文は変わらず、暗号文だけが変化する
    return (ciphertext * rn) % n_squared


def batch_randomize_ciphertexts(paillier: PaillierCrypto,
                               ciphertexts: List[int]) -> List[int]:
    """
    複数の暗号文をまとめてランダム化

    Args:
        paillier: 準同型暗号システムのインスタンス
        ciphertexts: ランダム化する暗号文のリスト

    Returns:
        ランダム化された暗号文のリスト
    """
    randomized = []
    for ct in ciphertexts:
        randomized.append(randomize_ciphertext(paillier, ct))
    return randomized


def interleave_ciphertexts(true_chunks: List[int],
                          false_chunks: List[int],
                          shuffle_seed: Optional[bytes] = None) -> Tuple[List[int], Dict[str, Any]]:
    """
    正規と非正規の暗号文チャンクを交互に配置し、ランダムに並べ替え

    Args:
        true_chunks: 正規の暗号文チャンク
        false_chunks: 非正規の暗号文チャンク
        shuffle_seed: シャッフルのシード値（省略時はランダム生成）

    Returns:
        (mixed_chunks, metadata): 混合された暗号文チャンクとメタデータ
    """
    # 両方のチャンクリストが同じ長さであることを確認
    if len(true_chunks) != len(false_chunks):
        # 長さが異なる場合は同じ長さにする（短い方を拡張）
        max_len = max(len(true_chunks), len(false_chunks))
        if len(true_chunks) < max_len:
            true_chunks = true_chunks + true_chunks[:max_len - len(true_chunks)]
        if len(false_chunks) < max_len:
            false_chunks = false_chunks + false_chunks[:max_len - len(false_chunks)]

    # インデックスのリストを作成
    indices = list(range(len(true_chunks) * 2))

    # シード値の設定
    if shuffle_seed is None:
        shuffle_seed = secrets.token_bytes(16)

    # シードを使用してインデックスをシャッフル
    rng = random.Random(int.from_bytes(shuffle_seed, 'big'))
    rng.shuffle(indices)

    # チャンクを結合してシャッフル後の順序に並べ替え
    combined = []
    mapping = []

    for idx in indices:
        chunk_type = "true" if idx < len(true_chunks) else "false"
        original_idx = idx if idx < len(true_chunks) else idx - len(true_chunks)

        if chunk_type == "true":
            combined.append(true_chunks[original_idx])
        else:
            combined.append(false_chunks[original_idx])

        mapping.append({"type": chunk_type, "index": original_idx})

    # メタデータ（復号時に必要）
    metadata = {
        "shuffle_seed": shuffle_seed.hex(),
        "mapping": mapping,
        "original_true_length": len(true_chunks),
        "original_false_length": len(false_chunks)
    }

    return combined, metadata


def deinterleave_ciphertexts(mixed_chunks: List[int],
                            metadata: Dict[str, Any],
                            key_type: str) -> List[int]:
    """
    混合された暗号文チャンクから特定の種類のチャンクを抽出

    Args:
        mixed_chunks: 混合された暗号文チャンク
        metadata: interleave_ciphertextsで生成されたメタデータ
        key_type: 取得するチャンクの種類（"true" または "false"）

    Returns:
        抽出されたチャンク
    """
    mapping = metadata["mapping"]

    # 鍵タイプに対応するチャンクだけを抽出
    chunks = []
    for i, entry in enumerate(mapping):
        if entry["type"] == key_type:
            chunks.append((entry["index"], mixed_chunks[i]))

    # 元の順序に戻す
    chunks.sort(key=lambda x: x[0])
    return [chunk[1] for chunk in chunks]


# 実装テスト用コード
def test_indistinguishable():
    """IndistinguishableWrapperのテスト関数"""
    print("識別不能性テスト")

    # インスタンス作成
    indist = IndistinguishableWrapper()

    # 真の鍵と偽の鍵をシミュレート
    true_key = os.urandom(KEY_SIZE_BYTES)
    false_key = os.urandom(KEY_SIZE_BYTES)
    salt = os.urandom(SALT_SIZE)

    # シード生成
    seed = indist.generate_seed(true_key, salt)
    print(f"シード: {binascii.hexlify(seed).decode()}")

    # 真偽判定テスト
    true_result = indist.is_true_path(true_key, salt)
    print(f"真の鍵: {true_result}")

    # シード再生成
    seed = indist.generate_seed(false_key, salt)
    false_result = indist.is_true_path(false_key, salt)
    print(f"偽の鍵: {false_result}")

    # 難読化テスト
    test_data = b"This is a test for indistinguishability!"
    print(f"元データ: {test_data.decode()}")

    # 難読化
    obfuscated = indist.obfuscate_data(test_data)
    print(f"難読化後: {binascii.hexlify(obfuscated).decode()}")

    # 逆難読化
    deobfuscated = indist.deobfuscate_data(obfuscated)
    print(f"復元後: {deobfuscated.decode()}")

    # 検証
    print(f"復元結果一致: {deobfuscated == test_data}")

    # タイミング均等化テスト
    def fast_function():
        return "Fast result"

    def slow_function():
        time.sleep(0.1)
        return "Slow result"

    # 均等化なしで実行時間測定
    start = time.time()
    fast_result = fast_function()
    fast_time = time.time() - start

    start = time.time()
    slow_result = slow_function()
    slow_time = time.time() - start

    print(f"均等化なし - 高速関数: {fast_time:.6f}秒, 低速関数: {slow_time:.6f}秒")

    # 均等化ありで実行時間測定
    start = time.time()
    fast_result = indist.time_equalizer(fast_function)
    fast_eq_time = time.time() - start

    start = time.time()
    slow_result = indist.time_equalizer(slow_function)
    slow_eq_time = time.time() - start

    print(f"均等化あり - 高速関数: {fast_eq_time:.6f}秒, 低速関数: {slow_eq_time:.6f}秒")


if __name__ == "__main__":
    test_indistinguishable()
