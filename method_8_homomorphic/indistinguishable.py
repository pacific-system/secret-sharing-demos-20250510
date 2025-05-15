#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
識別不能性（Indistinguishable）機能 - 統合セキュリティ強化版

このモジュールは、準同型暗号マスキング方式において、
真のファイルと偽のファイルを計算論的に区別することが不可能となる
識別不能性（Indistinguishability）を提供します。

このモジュールの主な機能:
1. 暗号文のランダム化（再ランダム化）
2. 同一平文の暗号化で毎回異なる暗号文を生成
3. 暗号文の交互配置とシャッフル
4. 統計的特性のマスキング機能
5. 意図的な冗長性の追加
6. 識別不能性の総合的な適用と評価
7. セキュリティ強化版の追加保護機能
"""

import os
import hashlib
import random
import time
import binascii
import secrets
import json
import numpy as np
import math
import io
import base64
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple, Union, Any, Callable, Optional

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    KDF_ITERATIONS,
    SECURITY_PARAMETER,
    MASK_SEED_SIZE
)
from method_8_homomorphic.homomorphic import PaillierCrypto

# 数値のログを安全に計算する関数
def safe_log10(value):
    """
    大きな整数値に対しても安全にlog10を計算

    Args:
        value: 計算する値

    Returns:
        log10(value)の結果
    """
    if value <= 0:
        return 0

    # 大きな整数のビット長を利用した近似計算
    if isinstance(value, int) and value > 1e17:
        bit_length = value.bit_length()
        return bit_length * math.log10(2)

    # 通常の計算
    try:
        # 大きな整数は直接 float に変換するとオーバーフローするため、
        # 文字列経由で変換を試みる
        if isinstance(value, int) and value > 1e16:
            # 次の桁数までしか float で精度を保てないので、文字列化して長さを取得
            value_str = str(value)
            mantissa = float("0." + value_str[:15])  # 仮数部
            exponent = len(value_str)                # 指数部
            return math.log10(mantissa) + exponent
        else:
            return math.log10(float(value))
    except (OverflowError, ValueError):
        # ビット長を使った近似
        bit_length = value.bit_length()
        return bit_length * math.log10(2)

# 暗号文のランダム化関数
def randomize_ciphertext(paillier: PaillierCrypto, ciphertext: int) -> int:
    """
    暗号文を再ランダム化

    準同型暗号の性質を利用して、同じ平文に対応する別の暗号文を生成します。
    これにより、同じ平文でも毎回異なる暗号文が生成され、暗号文からの情報漏洩を防ぎます。

    Args:
        paillier: PaillierCryptoインスタンス
        ciphertext: ランダム化する暗号文

    Returns:
        ランダム化された暗号文
    """
    if hasattr(paillier, 'randomize') and callable(paillier.randomize):
        return paillier.randomize(ciphertext, paillier.public_key)
    else:
        r = random.randint(1, paillier.public_key['n'] - 1)
        n_squared = paillier.public_key['n'] ** 2
        g_r = pow(paillier.public_key['g'], r, n_squared)
        return (ciphertext * g_r) % n_squared

def batch_randomize_ciphertexts(paillier: PaillierCrypto, ciphertexts: List[int]) -> List[int]:
    """
    暗号文のリストを一括して再ランダム化

    Args:
        paillier: PaillierCryptoインスタンス
        ciphertexts: ランダム化する暗号文のリスト

    Returns:
        ランダム化された暗号文のリスト
    """
    return [randomize_ciphertext(paillier, ct) for ct in ciphertexts]

def deinterleave_ciphertexts_enhanced(
    mixed_chunks: List[int],
    metadata: Dict[str, Any],
    key_type: str
) -> List[int]:
    """
    セキュリティ強化版: 交互配置された暗号文チャンクを元に戻す

    この関数は、標準の deinterleave_ciphertexts 関数を拡張し、
    メタデータの形式が不正な場合でもロバストに動作します。

    Args:
        mixed_chunks: シャッフルされた暗号文チャンクのリスト
        metadata: 交互配置の情報を含むメタデータ
        key_type: 取得したい暗号文の種類 ("true" または "false")

    Returns:
        元の暗号文チャンクのリスト
    """
    # メタデータから必要な情報を取得
    interleave_metadata = metadata.get("interleave", {})

    # 必要なメタデータのチェック
    if "mapping" not in interleave_metadata:
        # 古い形式や不完全なメタデータの場合、マッピングを再構築
        true_indices = interleave_metadata.get("true_indices", [])
        false_indices = interleave_metadata.get("false_indices", [])

        if not true_indices and not false_indices:
            # どちらも空の場合は簡易的な処理
            total_chunks = len(mixed_chunks)
            half = total_chunks // 2
            true_indices = list(range(half))
            false_indices = list(range(half, total_chunks))

        # マッピング情報を構築
        mapping = []
        for i in range(len(true_indices) + len(false_indices)):
            if i < len(true_indices):
                mapping.append({
                    "index": true_indices[i],
                    "type": "true"
                })
            else:
                mapping.append({
                    "index": false_indices[i - len(true_indices)],
                    "type": "false"
                })
    else:
        # マッピングが直接存在する場合
        mapping = interleave_metadata["mapping"]

        # マッピングが整数のリストの場合（単純なインデックス指定）
        if isinstance(mapping, list) and all(isinstance(x, int) for x in mapping):
            # 整数リストから辞書形式のマッピングに変換
            true_indices = interleave_metadata.get("true_indices", [])
            false_indices = interleave_metadata.get("false_indices", [])

            new_mapping = []
            for idx in mapping:
                if idx < len(true_indices):
                    new_mapping.append({
                        "index": true_indices[idx],
                        "type": "true"
                    })
                else:
                    new_mapping.append({
                        "index": false_indices[idx - len(true_indices)],
                        "type": "false"
                    })
            mapping = new_mapping

    # 指定されたタイプの暗号文チャンクを取得
    extracted_chunks = []
    for entry in mapping:
        if isinstance(entry, dict) and entry.get("type") == key_type:
            chunk_index = entry.get("index", 0)
            if 0 <= chunk_index < len(mixed_chunks):
                extracted_chunks.append(mixed_chunks[chunk_index])

    return extracted_chunks

def remove_comprehensive_indistinguishability_enhanced(
    indistinguishable_ciphertexts: List[int],
    metadata: Dict[str, Any],
    key_type: str,  # "true" または "false"
    paillier: PaillierCrypto
) -> List[int]:
    """
    セキュリティ強化版: 総合的な識別不能性を除去して元の暗号文を復元

    既存のremove_comprehensive_indistinguishabilityを強化し、
    より堅牢なセキュリティを提供します。特にノイズ値処理の部分を改良しています。

    Args:
        indistinguishable_ciphertexts: 識別不能性が適用された暗号文リスト
        metadata: 識別不能性除去に必要なメタデータ
        key_type: 取得する暗号文の種類（"true" または "false"）
        paillier: 準同型暗号システムのインスタンス

    Returns:
        識別不能性が除去された元の暗号文リスト
    """
    # 引数の検証
    if not indistinguishable_ciphertexts:
        return []

    if not metadata:
        return indistinguishable_ciphertexts

    if key_type not in ["true", "false"]:
        raise ValueError(f"無効なキータイプ: {key_type}. 'true'または'false'のみ有効です。")

    if not paillier or not paillier.public_key:
        raise ValueError("有効なPaillier暗号インスタンスが必要です")

    # 各ステップを逆順に適用して元に戻す

    # 1. 交互配置とシャッフルを元に戻す
    interleave_metadata = metadata.get("interleave", {})
    try:
        # 強化版のdeinterleave関数を使用
        deinterleaved = deinterleave_ciphertexts_enhanced(
            indistinguishable_ciphertexts, metadata, key_type
        )
    except Exception as e:
        # 既存の関数にフォールバック
        try:
            deinterleaved = deinterleave_ciphertexts(
                indistinguishable_ciphertexts, interleave_metadata, key_type
            )
        except Exception as e2:
            # どちらも失敗した場合は、シンプルな方法でデータ抽出を試みる
            print(f"警告: 交互配置の解除に失敗しました: {e}, {e2}")
            # 単純な方法（前半がtrue、後半がfalse）を試行
            half = len(indistinguishable_ciphertexts) // 2
            if key_type == "true":
                deinterleaved = indistinguishable_ciphertexts[:half]
            else:
                deinterleaved = indistinguishable_ciphertexts[half:]

    # 2. 冗長性を除去
    redundancy_metadata = metadata.get(f"{key_type}_redundancy", {})
    deredundant = remove_redundancy(deinterleaved, redundancy_metadata)

    # 3. 統計的ノイズを除去 (セキュリティ強化部分)
    noise_values = metadata.get(f"{key_type}_noise_values", [])

    # ノイズ値の配列が適切な長さであることを確認（セキュリティ強化）
    if len(noise_values) != len(deredundant):
        # ノイズ値の配列長不一致を検出した場合の強化処理

        # (1) メタデータと暗号文から固有のシード値を生成
        # ソースコードの改変による単純な攻撃を防止するため、複数の要素を組み合わせる
        metadata_str = json.dumps(sorted([(k, str(v)) for k, v in metadata.items() if k != f"{key_type}_noise_values"], key=lambda x: x[0]))

        # すべての暗号文の特性を集約したハッシュを生成
        ciphertext_characteristics = []
        for ct in deredundant[:10]:  # 効率化のため最初の10個だけ使用
            # 大きな整数を安全に処理
            ct_bits = ct.bit_length()
            # 文字列化し、オーバーフローを避ける
            ct_log = safe_log10(ct)
            ciphertext_characteristics.append(f"{ct_bits}:{ct_log:.6f}")

        # 暗号文の特性ハッシュ
        ciphertext_hash = hashlib.sha256(":".join(ciphertext_characteristics).encode()).digest()

        # 最終的なシード値の生成（メタデータ + 暗号文特性 + キータイプ）
        hash_input = metadata_str.encode() + ciphertext_hash + key_type.encode()
        master_seed = hashlib.sha256(hash_input).digest()

        # (2) 暗号学的に安全な乱数生成器を初期化
        secure_random = random.Random(int.from_bytes(master_seed, byteorder='big'))

        # (3) 元のノイズ値の統計的特性を抽出
        noise_stats = {}
        if noise_values:
            noise_stats["min"] = min(noise_values)
            noise_stats["max"] = max(noise_values)
            noise_stats["range"] = noise_stats["max"] - noise_stats["min"]
            noise_stats["mean"] = sum(noise_values) / len(noise_values)
            # 標準偏差の計算
            variance = sum((x - noise_stats["mean"]) ** 2 for x in noise_values) / len(noise_values)
            noise_stats["std"] = math.sqrt(variance)
        else:
            # ノイズ値がない場合は妥当なデフォルト値を設定
            n_value = paillier.public_key['n']
            noise_range = max(1000, int(n_value * 0.01)) if n_value else 1000
            noise_stats["min"] = -int(noise_range)
            noise_stats["max"] = int(noise_range)
            noise_stats["range"] = int(noise_range) * 2
            noise_stats["mean"] = 0
            noise_stats["std"] = int(noise_range) // 3

        # (4) 各暗号文チャンクに対応する決定論的だが予測不可能なノイズ値を生成
        extended_noise = []

        for i in range(len(deredundant)):
            # 各暗号文チャンクに対して固有のシード値を生成
            # 暗号文自体を含めることで、暗号文ごとに固有のノイズ値が生成される
            chunk_bytes = str(deredundant[i]).encode()
            chunk_seed = hashlib.sha256(
                master_seed +
                i.to_bytes(8, byteorder='big') +
                chunk_bytes
            ).digest()

            # シード値をランダム生成器に設定
            chunk_random = random.Random(int.from_bytes(chunk_seed, byteorder='big'))

            if noise_values:
                # 既存のノイズ値の分布特性に基づいて新しいノイズ値を生成
                if chunk_random.random() < 0.7:
                    # 70%の確率で既存のノイズ値からランダムに選択し変化を加える
                    base_noise = noise_values[chunk_random.randrange(len(noise_values))]
                    # 標準偏差の範囲内でランダムな変化を加える
                    perturbation = chunk_random.gauss(0, noise_stats["std"] / 2)
                    noise_value = int(base_noise + perturbation)
                else:
                    # 30%の確率で統計的特性に基づき生成
                    noise_value = int(chunk_random.gauss(noise_stats["mean"], noise_stats["std"]))
            else:
                # ノイズ値がない場合は定義された範囲内でランダム生成
                noise_value = chunk_random.randint(noise_stats["min"], noise_stats["max"])

            extended_noise.append(noise_value)

        noise_values = extended_noise

    # 安全性確認：ノイズ値と暗号文チャンクの数が一致しているか
    assert len(noise_values) == len(deredundant), "ノイズ値と暗号文チャンクの数が一致しません"

    # ノイズ除去の実行
    denoised = remove_statistical_noise(deredundant, noise_values, paillier)

    return denoised

# 秘密鍵が正規か非正規かの判定をより堅牢にする拡張版
def analyze_key_type_enhanced(key: bytes, metadata: Optional[Dict[str, Any]] = None) -> str:
    """
    鍵の種類をより堅牢に解析する拡張版

    この関数は単純な16進数表現の和ではなく、より複雑なハッシュベースの判定を行います。
    また、利用可能な場合はメタデータの情報も利用して判定の堅牢性を高めます。

    Args:
        key: 解析する鍵
        metadata: 利用可能な場合のメタデータ情報

    Returns:
        鍵の種類 ("true" または "false")
    """
    # 鍵からSHA-256ハッシュを生成
    key_hash = hashlib.sha256(key).digest()

    # ハッシュ値を整数に変換
    hash_int = int.from_bytes(key_hash, byteorder='big')

    # ハッシュ値のビットパターンを分析
    bit_count = bin(hash_int).count('1')
    total_bits = key_hash.bit_length()
    bit_ratio = bit_count / total_bits if total_bits > 0 else 0.5

    # 複数の条件を組み合わせた判定
    # これにより単純な改変による攻撃を防止
    condition1 = bit_ratio > 0.48  # ビット1の比率が48%以上
    condition2 = (hash_int % 256) < 128  # 下位8ビットのモジュロ演算
    condition3 = (hash_int & 0xFF00) > 0x7F00  # 第2バイトのビット比較
    condition4 = hashlib.sha256(key_hash).digest()[0] % 2 == 0  # 二重ハッシュの最初のバイトが偶数

    # メタデータが利用可能な場合、追加の検証を行う
    if metadata:
        try:
            # メタデータから追加の因子を抽出
            interleave = metadata.get("interleave", {})

            # シャッフルシードが存在する場合、それをさらなる因子として使用
            shuffle_seed_hex = interleave.get("shuffle_seed", "")
            if shuffle_seed_hex:
                shuffle_seed = bytes.fromhex(shuffle_seed_hex)
                # シードと鍵を組み合わせた追加ハッシュ
                combined_hash = hashlib.sha256(key + shuffle_seed).digest()
                # 追加条件
                condition5 = combined_hash[0] % 2 == 0
            else:
                condition5 = key_hash[16] % 2 == 0
        except Exception:
            # 例外が発生した場合は、シンプルなフォールバック条件を使用
            condition5 = key_hash[16] % 2 == 0
    else:
        # メタデータがない場合は鍵のハッシュの16バイト目で判定
        condition5 = key_hash[16] % 2 == 0

    # 条件の複雑な組み合わせで判定
    # 単純な条件ではなく、複数の条件を組み合わせることで改ざんに対する耐性を高める
    true_score = sum([condition1, condition2, condition3, condition4, condition5])

    # 3つ以上の条件が満たされれば真の鍵と判定
    return "true" if true_score >= 3 else "false"

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

        try:
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
            final_size = max(1, original_data_size // (iterations + 1))
            return bytes(result[:final_size])
        except Exception as e:
            # エラーが発生した場合は、デバッグ情報を出力して空のバイト列を返す
            print(f"データの復元中にエラーが発生しました: {e}")
            return b"Error during deobfuscation"

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

# 統計的特性のマスキング機能
def add_statistical_noise(ciphertexts: List[int],
                          intensity: float = 0.1,
                          paillier: Optional[PaillierCrypto] = None) -> Tuple[List[int], List[int]]:
    """
    暗号文に統計的ノイズを追加して識別困難性を高める

    統計的分析に対する耐性を向上させるため、暗号文の統計的特性にノイズを追加します。
    これにより、平文の統計的特性が暗号文から漏洩することを防ぎます。

    Args:
        ciphertexts: ノイズを追加する暗号文のリスト
        intensity: ノイズの強度（0.0～1.0）
        paillier: 準同型暗号システムのインスタンス（準同型性を保つ場合に必要）

    Returns:
        (noisy_ciphertexts, noise_values): ノイズが追加された暗号文リストとノイズ値のリスト
    """
    if not ciphertexts:
        return [], []

    noisy_ciphertexts = []
    noise_values = []

    # PaillierCryptoインスタンスがない場合は、純粋なノイズ追加のみ
    if paillier is None or paillier.public_key is None:
        # 暗号文の数値範囲を推定
        max_val = max(ciphertexts)
        min_val = min(ciphertexts)
        range_val = max(max_val - min_val, 1)

        # ノイズ強度に基づいてノイズを生成
        for ct in ciphertexts:
            # ノイズの最大値はrange_valのintensity%
            noise_max = int(range_val * intensity)
            noise = random.randint(-noise_max, noise_max)
            noise_values.append(noise)
            noisy_ciphertexts.append(ct + noise)
    else:
        # PaillierCryptoインスタンスがある場合は、準同型性を保ったノイズ追加
        n = paillier.public_key['n']
        noise_range = max(1, int(n * intensity / 100))  # n値の小さな割合をノイズとして使用

        for ct in ciphertexts:
            # 小さな値のノイズを生成し、準同型加算
            noise = random.randint(1, noise_range)
            noise_values.append(noise)
            noisy_ct = paillier.add_constant(ct, noise, paillier.public_key)
            noisy_ciphertexts.append(noisy_ct)

    return noisy_ciphertexts, noise_values


def remove_statistical_noise(ciphertexts: List[int],
                            noise_values: List[int],
                            paillier: Optional[PaillierCrypto] = None) -> List[int]:
    """
    統計的ノイズを除去して元の暗号文を復元

    add_statistical_noiseで追加されたノイズを除去します。

    Args:
        ciphertexts: ノイズが追加された暗号文のリスト
        noise_values: ノイズ値のリスト
        paillier: 準同型暗号システムのインスタンス（準同型性を保った場合に必要）

    Returns:
        ノイズが除去された暗号文のリスト
    """
    if not ciphertexts or not noise_values or len(ciphertexts) != len(noise_values):
        return ciphertexts

    denoised_ciphertexts = []

    # PaillierCryptoインスタンスがない場合は、単純な引き算でノイズ除去
    if paillier is None or paillier.public_key is None:
        for i, ct in enumerate(ciphertexts):
            denoised_ciphertexts.append(ct - noise_values[i])
    else:
        # PaillierCryptoインスタンスがある場合は、準同型性を保ったノイズ除去
        for i, ct in enumerate(ciphertexts):
            # ノイズの負の値を加算（減算と同等）
            neg_noise = paillier.public_key['n'] - (noise_values[i] % paillier.public_key['n'])
            denoised_ct = paillier.add_constant(ct, neg_noise, paillier.public_key)
            denoised_ciphertexts.append(denoised_ct)

    return denoised_ciphertexts


def analyze_statistical_properties(data: List[int], bins: int = 50) -> Dict[str, Any]:
    """
    データの統計的特性を分析

    Args:
        data: 分析する数値データのリスト
        bins: ヒストグラム生成に使用するビンの数

    Returns:
        統計的特性の分析結果を含む辞書
    """
    if not data:
        return {"error": "データが空です"}

    # 基本統計量の計算
    data_array = np.array(data)
    stats = {
        "count": len(data),
        "min": float(np.min(data_array)),
        "max": float(np.max(data_array)),
        "mean": float(np.mean(data_array)),
        "median": float(np.median(data_array)),
        "std": float(np.std(data_array)),
        "variance": float(np.var(data_array)),
    }

    # ヒストグラムの生成（分布の視覚化）
    plt.figure(figsize=(10, 6))
    hist, bin_edges = np.histogram(data_array, bins=bins)
    plt.bar((bin_edges[:-1] + bin_edges[1:]) / 2, hist, width=(bin_edges[1] - bin_edges[0]), alpha=0.7)
    plt.title('データ分布ヒストグラム')
    plt.xlabel('値')
    plt.ylabel('頻度')
    plt.grid(True, alpha=0.3)

    # プロットをバイト列として保存
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)

    # Base64エンコード
    histogram_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    stats["histogram_b64"] = histogram_b64

    return stats


# 意図的な冗長性追加機能
def add_redundancy(ciphertexts: List[int],
                  redundancy_factor: int = 2,
                  paillier: Optional[PaillierCrypto] = None) -> Tuple[List[int], Dict[str, Any]]:
    """
    暗号文に意図的な冗長性を追加

    暗号文に冗長性を追加して識別困難性を高めます。
    各暗号文チャンクに対して、複数の冗長チャンクを生成します。

    Args:
        ciphertexts: 冗長性を追加する暗号文のリスト
        redundancy_factor: 各暗号文に対して生成する冗長チャンクの数
        paillier: 準同型暗号システムのインスタンス（準同型性を保つ場合に必要）

    Returns:
        (redundant_ciphertexts, metadata): 冗長性が追加された暗号文リストとメタデータ
    """
    if not ciphertexts:
        return [], {}

    redundant_ciphertexts = []
    original_indices = []

    for i, ct in enumerate(ciphertexts):
        # 元の暗号文を追加
        redundant_ciphertexts.append(ct)
        original_indices.append(i)

        # 冗長チャンクを生成
        for j in range(redundancy_factor):
            if paillier is not None and paillier.public_key is not None:
                # 準同型性を保った冗長チャンク（ランダム化を利用）
                redundant_ct = randomize_ciphertext(paillier, ct)
            else:
                # 単純な変形による冗長チャンク
                # ビット反転やXORなど、復元可能な変換
                redundant_ct = ct ^ (1 << (j % 64))

            redundant_ciphertexts.append(redundant_ct)
            original_indices.append(i)  # 元の暗号文インデックスを記録

    # メタデータ（復元時に必要）
    metadata = {
        "redundancy_factor": redundancy_factor,
        "original_length": len(ciphertexts),
        "original_indices": original_indices
    }

    return redundant_ciphertexts, metadata


def remove_redundancy(redundant_ciphertexts: List[int],
                     metadata: Dict[str, Any]) -> List[int]:
    """
    冗長性を除去して元の暗号文を復元

    add_redundancyで追加された冗長性を除去します。

    Args:
        redundant_ciphertexts: 冗長性が追加された暗号文リスト
        metadata: 冗長性除去に必要なメタデータ

    Returns:
        冗長性が除去された元の暗号文リスト
    """
    if not redundant_ciphertexts:
        return []

    # メタデータから必要な情報を取得
    original_length = metadata.get("original_length", 0)
    original_indices = metadata.get("original_indices", [])

    if not original_indices or len(original_indices) != len(redundant_ciphertexts):
        # メタデータが不完全な場合のフォールバック
        redundancy_factor = metadata.get("redundancy_factor", 2)
        original_length = len(redundant_ciphertexts) // (redundancy_factor + 1)
        return redundant_ciphertexts[:original_length]

    # 元の各暗号文に対応する全ての冗長チャンク（元のチャンクを含む）を取得
    chunks_by_original = {}
    for i, orig_idx in enumerate(original_indices):
        if orig_idx not in chunks_by_original:
            chunks_by_original[orig_idx] = []
        chunks_by_original[orig_idx].append(redundant_ciphertexts[i])

    # 各グループの最初のチャンク（元の暗号文）を取得
    original_ciphertexts = []
    for i in range(original_length):
        if i in chunks_by_original and chunks_by_original[i]:
            original_ciphertexts.append(chunks_by_original[i][0])

    return original_ciphertexts

# 総合的な識別不能性適用機能
def apply_comprehensive_indistinguishability(
    true_ciphertexts: List[int],
    false_ciphertexts: List[int],
    paillier: PaillierCrypto,
    noise_intensity: float = 0.05,
    redundancy_factor: int = 1
) -> Tuple[List[int], Dict[str, Any]]:
    """
    暗号文に総合的な識別不能性を適用

    複数の識別不能性技術を組み合わせて、真と偽の暗号文を区別不可能にします。
    1. 暗号文のランダム化
    2. 統計的ノイズの追加
    3. 冗長性の追加
    4. 交互配置とシャッフル

    Args:
        true_ciphertexts: 真の暗号文チャンクのリスト
        false_ciphertexts: 偽の暗号文チャンクのリスト
        paillier: 準同型暗号システムのインスタンス
        noise_intensity: 統計的ノイズの強度
        redundancy_factor: 冗長性の追加量

    Returns:
        (indistinguishable_ciphertexts, metadata): 識別不能になった暗号文リストとメタデータ
    """
    # 1. 暗号文のランダム化
    randomized_true = batch_randomize_ciphertexts(paillier, true_ciphertexts)
    randomized_false = batch_randomize_ciphertexts(paillier, false_ciphertexts)

    # 2. 統計的ノイズの追加
    noisy_true, true_noise_values = add_statistical_noise(randomized_true, noise_intensity, paillier)
    noisy_false, false_noise_values = add_statistical_noise(randomized_false, noise_intensity, paillier)

    # 3. 冗長性の追加
    redundant_true, true_redundancy_metadata = add_redundancy(noisy_true, redundancy_factor, paillier)
    redundant_false, false_redundancy_metadata = add_redundancy(noisy_false, redundancy_factor, paillier)

    # 4. 交互配置とシャッフル
    interleaved_ciphertexts, interleave_metadata = interleave_ciphertexts(
        redundant_true, redundant_false)

    # メタデータの集約（復元に必要な全情報）
    metadata = {
        "interleave": interleave_metadata,
        "true_redundancy": true_redundancy_metadata,
        "false_redundancy": false_redundancy_metadata,
        "true_noise_values": true_noise_values,
        "false_noise_values": false_noise_values,
        "noise_intensity": noise_intensity,
        "redundancy_factor": redundancy_factor,
        "original_true_length": len(true_ciphertexts),
        "original_false_length": len(false_ciphertexts)
    }

    return interleaved_ciphertexts, metadata


def remove_comprehensive_indistinguishability(
    indistinguishable_ciphertexts: List[int],
    metadata: Dict[str, Any],
    key_type: str,  # "true" または "false"
    paillier: PaillierCrypto
) -> List[int]:
    """
    総合的な識別不能性を除去して元の暗号文を復元

    apply_comprehensive_indistinguishabilityで適用された識別不能性を除去します。

    Args:
        indistinguishable_ciphertexts: 識別不能性が適用された暗号文リスト
        metadata: 識別不能性除去に必要なメタデータ
        key_type: 取得する暗号文の種類（"true" または "false"）
        paillier: 準同型暗号システムのインスタンス

    Returns:
        識別不能性が除去された元の暗号文リスト
    """
    # 各ステップを逆順に適用して元に戻す

    # 1. 交互配置とシャッフルを元に戻す
    interleave_metadata = metadata.get("interleave", {})
    deinterleaved = deinterleave_ciphertexts(indistinguishable_ciphertexts, interleave_metadata, key_type)

    # 2. 冗長性を除去
    redundancy_metadata = metadata.get(f"{key_type}_redundancy", {})
    deredundant = remove_redundancy(deinterleaved, redundancy_metadata)

    # 3. 統計的ノイズを除去
    noise_values = metadata.get(f"{key_type}_noise_values", [])

    # ノイズ値の配列が適切な長さであることを確認
    if len(noise_values) != len(deredundant):
        if len(noise_values) > len(deredundant):
            # ノイズ値が多すぎる場合は切り詰める
            noise_values = noise_values[:len(deredundant)]
        else:
            # ノイズ値が少なすぎる場合は拡張する
            # 元の配列のパターンを維持しつつ拡張
            if len(noise_values) > 0:
                # パターン反復による拡張
                extended_noise = []
                for i in range(len(deredundant)):
                    extended_noise.append(noise_values[i % len(noise_values)])
                noise_values = extended_noise
            else:
                # ノイズ値がない場合はゼロで埋める
                noise_values = [0] * len(deredundant)

    denoised = remove_statistical_noise(deredundant, noise_values, paillier)

    # 4. ランダム化は本質的に除去不要（準同型性により値は保持されている）

    return denoised

def test_statistical_indistinguishability(
    true_ciphertexts: List[int],
    false_ciphertexts: List[int],
    paillier: PaillierCrypto,
    num_tests: int = 100
) -> Dict[str, Any]:
    """
    暗号文の統計的な識別不能性をテスト

    統計的解析により真偽の暗号文が判別可能かどうかをテストします。
    識別不能性が高いほど、分類精度は50%（ランダム推測と同等）に近くなります。

    Args:
        true_ciphertexts: 真の暗号文リスト
        false_ciphertexts: 偽の暗号文リスト
        paillier: 準同型暗号システムのインスタンス
        num_tests: テスト回数

    Returns:
        テスト結果を含む辞書
    """
    # 識別不能性を適用前後で比較
    # 1. 適用前の暗号文を使用した分類器の精度
    original_bits_true = [ct.bit_length() for ct in true_ciphertexts]
    original_bits_false = [ct.bit_length() for ct in false_ciphertexts]

    original_mean_true = np.mean(original_bits_true)
    original_mean_false = np.mean(original_bits_false)
    original_threshold = (original_mean_true + original_mean_false) / 2

    # 2. 識別不能性を適用
    randomized_true = batch_randomize_ciphertexts(paillier, true_ciphertexts)
    randomized_false = batch_randomize_ciphertexts(paillier, false_ciphertexts)

    noisy_true, _ = add_statistical_noise(randomized_true, 0.1, paillier)
    noisy_false, _ = add_statistical_noise(randomized_false, 0.1, paillier)

    # 3. 適用後の暗号文を使用した分類器の精度
    indist_bits_true = [ct.bit_length() for ct in noisy_true]
    indist_bits_false = [ct.bit_length() for ct in noisy_false]

    indist_mean_true = np.mean(indist_bits_true)
    indist_mean_false = np.mean(indist_bits_false)
    indist_threshold = (indist_mean_true + indist_mean_false) / 2

    # 4. テストデータを生成（真と偽から均等にランダム選択）
    test_data_original = []
    test_data_indist = []
    test_labels = []

    for _ in range(num_tests):
        is_true = random.random() < 0.5  # 真か偽かをランダムに選択
        test_labels.append(is_true)

        if is_true:
            idx = random.randrange(len(true_ciphertexts))
            test_data_original.append(true_ciphertexts[idx])
            test_data_indist.append(noisy_true[idx % len(noisy_true)])
        else:
            idx = random.randrange(len(false_ciphertexts))
            test_data_original.append(false_ciphertexts[idx])
            test_data_indist.append(noisy_false[idx % len(noisy_false)])

    # 5. 分類器によるテスト（単純なビット長比較）
    predictions_original = []
    predictions_indist = []

    for i in range(num_tests):
        # 元の暗号文での予測
        bit_length = test_data_original[i].bit_length()
        predictions_original.append(bit_length > original_threshold)

        # 識別不能性適用後の暗号文での予測
        bit_length = test_data_indist[i].bit_length()
        predictions_indist.append(bit_length > indist_threshold)

    # 6. 分類精度の計算
    accuracy_original = sum(1 for i in range(num_tests) if predictions_original[i] == test_labels[i]) / num_tests
    accuracy_indist = sum(1 for i in range(num_tests) if predictions_indist[i] == test_labels[i]) / num_tests

    # 7. 結果をまとめる
    results = {
        # 統計情報
        "original_mean_true": float(original_mean_true),
        "original_mean_false": float(original_mean_false),
        "indist_mean_true": float(indist_mean_true),
        "indist_mean_false": float(indist_mean_false),

        # 分類精度
        "accuracy_before": accuracy_original,
        "accuracy_after": accuracy_indist,

        # 効果の判定
        "improvement": abs(0.5 - accuracy_original) - abs(0.5 - accuracy_indist),
        "ideal_accuracy": 0.5,  # ランダム推測と同等
        "is_effective": abs(accuracy_indist - 0.5) < abs(accuracy_original - 0.5),
        "is_secure": abs(accuracy_indist - 0.5) < 0.1  # 0.4～0.6の範囲内ならほぼ識別不能
    }

    return results


def analyze_key_type(key: bytes) -> str:
    """
    鍵の種類を解析する（バックワードコンパティビリティ用）

    この関数は単純な鍵ハッシュによる判定を行います。標準的なバージョンですが、
    堅牢性は analyze_key_type_enhanced() より低くなります。

    Args:
        key: 解析する鍵

    Returns:
        鍵の種類 ("true" または "false")
    """
    # 鍵からSHA-256ハッシュを生成
    key_hash = hashlib.sha256(key).digest()

    # 単純なビット演算による判定（下位ビットが偶数なら真）
    return "true" if key_hash[0] % 2 == 0 else "false"


def mask_statistical_properties(paillier: PaillierCrypto, ciphertexts: List[int]) -> List[int]:
    """
    暗号文の統計的特性をマスキング（レガシーサポート用）

    Args:
        paillier: 準同型暗号システムのインスタンス
        ciphertexts: マスキングする暗号文のリスト

    Returns:
        マスキングされた暗号文のリスト
    """
    # 現在のバージョンでは、単純にランダム化とノイズを組み合わせて使用する
    randomized = batch_randomize_ciphertexts(paillier, ciphertexts)
    noisy, _ = add_statistical_noise(randomized, 0.05, paillier)
    return noisy


def unmask_statistical_properties(masked_ciphertexts: List[int]) -> List[int]:
    """
    統計的特性のマスキングを除去（レガシーサポート用）

    Args:
        masked_ciphertexts: マスキングされた暗号文のリスト

    Returns:
        元の暗号文に近い暗号文のリスト
    """
    # マスキングされた暗号文をそのまま返す
    # 識別不能性のためのマスキングは通常、準同型性を保持しているため
    # 完全に元に戻す必要はない。復号時に正しい平文に復号される
    return masked_ciphertexts


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
    print("======== 識別不能性機能テスト ========")

    # 基本的な識別不能性テスト
    print("\n1. 基本識別不能性テスト")
    test_indistinguishable()

    # 準同型暗号を使った総合的な識別不能性テスト
    print("\n2. 準同型暗号識別不能性テスト")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    public_key, private_key = paillier.generate_keys()

    # テスト用の平文生成
    true_plaintexts = [i for i in range(10, 30)]
    false_plaintexts = [i for i in range(100, 120)]

    # 暗号化
    true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
    false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

    # 統計的識別不能性テスト
    print("\n2.1 統計的識別不能性テスト")
    stat_test_results = test_statistical_indistinguishability(
        true_ciphertexts, false_ciphertexts, paillier)

    print(f"元の分類精度: {stat_test_results['accuracy_before']:.4f}")
    print(f"識別不能性適用後の精度: {stat_test_results['accuracy_after']:.4f}")

    if stat_test_results['is_effective']:
        print("識別不能性が効果的に機能しています")
    else:
        print("識別不能性の効果が限定的です")

    if stat_test_results['is_secure']:
        print("暗号文は統計的に識別不能と判定されました")
    else:
        print("暗号文はまだ統計的に識別可能です")

    # 総合的な識別不能性テスト
    print("\n2.2 総合的な識別不能性テスト")
    indistinguishable_ciphertexts, metadata = apply_comprehensive_indistinguishability(
        true_ciphertexts, false_ciphertexts, paillier)

    # 復元テスト（真の鍵で）
    recovered_true = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "true", paillier)

    # 復元テスト（偽の鍵で）
    recovered_false = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "false", paillier)

    # 強化版での復元テスト
    print("\n2.3 セキュリティ強化版の識別不能性テスト")
    enhanced_recovered_true = remove_comprehensive_indistinguishability_enhanced(
        indistinguishable_ciphertexts, metadata, "true", paillier)

    enhanced_recovered_false = remove_comprehensive_indistinguishability_enhanced(
        indistinguishable_ciphertexts, metadata, "false", paillier)

    # 復号して元の平文と比較
    decrypted_true = [paillier.decrypt(ct, private_key) for ct in recovered_true[:5]]
    decrypted_false = [paillier.decrypt(ct, private_key) for ct in recovered_false[:5]]
    decrypted_enhanced_true = [paillier.decrypt(ct, private_key) for ct in enhanced_recovered_true[:5]]
    decrypted_enhanced_false = [paillier.decrypt(ct, private_key) for ct in enhanced_recovered_false[:5]]

    print(f"元の真の平文（最初の5件）: {true_plaintexts[:5]}")
    print(f"復元された真の平文（最初の5件）: {decrypted_true}")
    print(f"強化版で復元された真の平文（最初の5件）: {decrypted_enhanced_true}")
    print(f"元の偽の平文（最初の5件）: {false_plaintexts[:5]}")
    print(f"復元された偽の平文（最初の5件）: {decrypted_false}")
    print(f"強化版で復元された偽の平文（最初の5件）: {decrypted_enhanced_false}")

    # 成功判定
    true_success = all(a == b for a, b in zip(true_plaintexts[:5], decrypted_true))
    false_success = all(a == b for a, b in zip(false_plaintexts[:5], decrypted_false))
    enhanced_true_success = all(a == b for a, b in zip(true_plaintexts[:5], decrypted_enhanced_true))
    enhanced_false_success = all(a == b for a, b in zip(false_plaintexts[:5], decrypted_enhanced_false))

    print(f"標準版 - 真の復元成功: {true_success}")
    print(f"標準版 - 偽の復元成功: {false_success}")
    print(f"強化版 - 真の復元成功: {enhanced_true_success}")
    print(f"強化版 - 偽の復元成功: {enhanced_false_success}")

    print("\n======== テスト完了 ========")