#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の鍵解析モジュール - セキュリティ強化版

このモジュールは、与えられた鍵を解析し、その鍵が「真の鍵」か「偽の鍵」かを
より堅牢に判定する機能を提供します。単一の単純な条件ではなく、複数の特性を
組み合わせて判断することでソースコードの改変に対する耐性を高めています。
"""

import os
import hashlib
import hmac
import base64
import random
import time
import secrets
import math
from typing import Dict, Any, Tuple, List, Optional

from method_8_homomorphic.config import (
    KDF_ITERATIONS,
    MASK_SEED_SIZE,
    KEY_SIZE_BYTES,
    SECURITY_PARAMETER
)


def derive_key_identifier(key: bytes) -> bytes:
    """
    鍵から識別子を導出

    Args:
        key: 解析する鍵

    Returns:
        鍵の識別子
    """
    # 鍵からハッシュ値を生成
    key_hash = hashlib.sha256(key).digest()

    # 識別子として最初の8バイトを使用
    return key_hash[:8]


def analyze_key_type_robust(key: bytes, salt: Optional[bytes] = None) -> str:
    """
    セキュリティ強化版の鍵種類判定アルゴリズム

    複数の独立した条件を組み合わせることで、単純なコード改変では
    鍵判定ロジックを覆せないようにします。

    Args:
        key: 解析する鍵
        salt: ソルト値（ある場合）

    Returns:
        鍵の種類 ("true" または "false")
    """
    # 1. 基本的な鍵ハッシュを生成
    key_hash = hashlib.sha256(key).digest()

    # 2. ハッシュ値のハッシュ（二重ハッシュ）
    double_hash = hashlib.sha256(key_hash).digest()

    # 3. ソルトがある場合はソルトを使用したハッシュも生成
    if salt:
        salted_hash = hashlib.pbkdf2_hmac('sha256', key, salt, KDF_ITERATIONS, 32)
    else:
        # ソルトがない場合は疑似ソルトを使用
        pseudo_salt = b"analyze_key_type_robust_salt"
        salted_hash = hashlib.pbkdf2_hmac('sha256', key, pseudo_salt, KDF_ITERATIONS, 32)

    # 各ハッシュからの条件生成
    conditions = []

    # 4. 条件セット1: ハミング重み（ビット1の数）に基づく条件
    bit_count = bin(int.from_bytes(key_hash, 'big')).count('1')
    bit_ratio = bit_count / (len(key_hash) * 8)
    conditions.append(bit_ratio > 0.48)  # ビット1の割合が48%以上

    # 5. 条件セット2: バイトパターン分析
    # 異なるバイト位置での値を組み合わせる
    byte_sum = sum(key_hash[i] for i in [0, 8, 16, 24])
    conditions.append(byte_sum % 2 == 0)  # 特定バイトの合計が偶数

    # 6. 条件セット3: ハッシュ値の特定部分の数学的特性
    hash_int = int.from_bytes(key_hash[:4], 'big')
    conditions.append(hash_int % 3 == 0)  # 最初の4バイトを3で割った余りが0

    # 7. 条件セット4: 二重ハッシュの特性
    double_hash_int = int.from_bytes(double_hash[:4], 'big')
    conditions.append(double_hash_int % 5 < 3)  # 二重ハッシュの最初の4バイトを5で割った余りが3未満

    # 8. 条件セット5: ソルトハッシュの特性
    salted_hash_int = int.from_bytes(salted_hash[:4], 'big')
    conditions.append(salted_hash_int % 7 < 4)  # ソルトハッシュの最初の4バイトを7で割った余りが4未満

    # 9. 条件セット6: 鍵の直接的特性（長さなど）
    if len(key) >= KEY_SIZE_BYTES:
        key_sample = key[:KEY_SIZE_BYTES]
    else:
        key_sample = key.ljust(KEY_SIZE_BYTES, b'\0')
    conditions.append(sum(key_sample) % 11 < 6)  # 鍵バイト和を11で割った余りが6未満

    # 10. 条件セット7: 時間依存性を持たない擬似ランダム性
    # 現在時刻や実行環境に依存せず、鍵自体から決定的に生成される特性
    rand_seed = int.from_bytes(key_hash[-4:], 'big')
    rand_gen = random.Random(rand_seed)
    conditions.append(rand_gen.random() < 0.5)  # 鍵から決定的に生成されるランダム値が0.5未満

    # 11. 多数決方式で真偽判定（過半数の条件が満たされていれば真の鍵と判定）
    true_count = sum(conditions)
    threshold = len(conditions) / 2

    # より強力な真偽判定: 多数決方式 + 特定条件の重み付け
    # 最初の条件（ビット比率）と最後の条件（擬似ランダム性）に特別な重みを与える
    if true_count > threshold:
        # 過半数の条件が満たされた場合
        return "true"
    elif true_count < threshold:
        # 過半数の条件が満たされなかった場合
        return "false"
    else:
        # 同数の場合はタイブレーカーとして重み付け条件を使用
        # 最初と最後の条件で判断
        if conditions[0] and conditions[-1]:
            return "true"
        else:
            return "false"


def analyze_key_type(key: bytes) -> str:
    """
    既存の互換性のための鍵種類判定関数
    内部的には堅牢な実装を使用

    Args:
        key: 解析する鍵

    Returns:
        鍵の種類 ("true" または "false")
    """
    # 堅牢な判定アルゴリズムを使用
    return analyze_key_type_robust(key)


def derive_key_hmac(key: bytes, salt: bytes, label: str) -> bytes:
    """
    鍵とラベルからHMACを導出

    Args:
        key: マスター鍵
        salt: ソルト
        label: ラベル ("true" または "false")

    Returns:
        導出されたHMAC
    """
    # 鍵とラベルからHMACを計算
    h = hmac.new(key, salt + label.encode(), hashlib.sha256)
    return h.digest()


def verify_key_pair(true_key: bytes, false_key: bytes) -> bool:
    """
    真の鍵と偽の鍵のペアが適切かどうかを検証

    Args:
        true_key: 真の鍵
        false_key: 偽の鍵

    Returns:
        ペアが有効であればTrue
    """
    # 真の鍵と偽の鍵が異なることを確認
    if true_key == false_key:
        return False

    # 真の鍵を解析
    true_type = analyze_key_type_robust(true_key)
    if true_type != "true":
        return False

    # 偽の鍵を解析
    false_type = analyze_key_type_robust(false_key)
    if false_type != "false":
        return False

    return True


def generate_key_pair() -> Tuple[bytes, bytes]:
    """
    真と偽の鍵ペアを生成

    Returns:
        (真の鍵, 偽の鍵)
    """
    # ランダムな真の鍵を生成
    max_attempts = 100  # 最大試行回数を設定
    attempts = 0

    while attempts < max_attempts:
        candidate_key = secrets.token_bytes(KEY_SIZE_BYTES)  # より強力なランダム生成
        if analyze_key_type_robust(candidate_key) == "true":
            true_key = candidate_key
            break
        attempts += 1

    # 最大試行回数に達しても見つからなかった場合
    if attempts >= max_attempts:
        # フォールバック: 強制的に条件を満たす鍵を生成
        base_key = secrets.token_bytes(KEY_SIZE_BYTES - 4)
        # 最後の4バイトを調整して条件を満たすようにする
        for i in range(256):
            test_key = base_key + i.to_bytes(4, 'big')
            if analyze_key_type_robust(test_key) == "true":
                true_key = test_key
                break
        else:
            # それでも見つからない場合はデフォルト値
            true_key = hashlib.sha256(b"default_true_key").digest()

    # ランダムな偽の鍵を生成
    attempts = 0
    while attempts < max_attempts:
        candidate_key = secrets.token_bytes(KEY_SIZE_BYTES)
        if analyze_key_type_robust(candidate_key) == "false":
            false_key = candidate_key
            break
        attempts += 1

    # 最大試行回数に達しても見つからなかった場合
    if attempts >= max_attempts:
        # フォールバック: 強制的に条件を満たす鍵を生成
        base_key = secrets.token_bytes(KEY_SIZE_BYTES - 4)
        for i in range(256):
            test_key = base_key + i.to_bytes(4, 'big')
            if analyze_key_type_robust(test_key) == "false":
                false_key = test_key
                break
        else:
            # それでも見つからない場合はデフォルト値
            false_key = hashlib.sha256(b"default_false_key").digest()

    return true_key, false_key


def extract_seed_from_key(key: bytes, salt: bytes = None) -> bytes:
    """
    鍵からマスク関数生成用のシードを抽出

    Args:
        key: マスター鍵
        salt: ソルト（デフォルトはNone）

    Returns:
        マスク関数生成用のシード
    """
    if salt is None:
        # ソルトがない場合は鍵自体からハッシュを生成
        # 直接ハッシュではなく、より強力なキー導出を使用
        pseudo_salt = b"extract_seed_from_key_salt"
        return hashlib.pbkdf2_hmac(
            'sha256',
            key,
            pseudo_salt,
            KDF_ITERATIONS,
            MASK_SEED_SIZE
        )

    # PBKDF2を使用してシードを導出
    return hashlib.pbkdf2_hmac(
        'sha256',
        key,
        salt,
        KDF_ITERATIONS,
        MASK_SEED_SIZE
    )


def get_key_security_score(key: bytes) -> float:
    """
    鍵のセキュリティスコアを計算

    鍵の強度を0.0〜1.0のスコアで評価します。
    このスコアは鍵のエントロピーや予測困難性を示します。

    Args:
        key: 評価する鍵

    Returns:
        セキュリティスコア（0.0〜1.0）
    """
    # 短すぎる鍵は低いスコア
    if len(key) < 16:
        return 0.2

    # 基本スコアは長さに比例（最大32バイト = 256ビットまで）
    length_score = min(1.0, len(key) / 32)

    # エントロピー計算（ユニークバイト数とその分布）
    byte_counts = {}
    for b in key:
        byte_counts[b] = byte_counts.get(b, 0) + 1

    # シャノンエントロピーの計算
    entropy = 0
    for count in byte_counts.values():
        p = count / len(key)
        entropy -= p * math.log2(p)

    # 理論的最大エントロピー（全バイト値が均等に分布）
    max_entropy = 8  # 8ビット = 1バイト
    entropy_score = entropy / max_entropy

    # バイト分布のスコア（理想的には全256バイト値が使われる）
    distribution_score = len(byte_counts) / 256

    # 重み付け平均
    security_score = (
        length_score * 0.3 +
        entropy_score * 0.5 +
        distribution_score * 0.2
    )

    return security_score


def identify_key_characteristics(key: bytes) -> Dict[str, Any]:
    """
    鍵の特性を詳細に分析

    Args:
        key: 分析する鍵

    Returns:
        鍵の特性を含む辞書
    """
    result = {
        "type": analyze_key_type_robust(key),
        "length": len(key),
        "security_score": get_key_security_score(key),
        "identifier": derive_key_identifier(key).hex(),
        "hash": hashlib.sha256(key).hexdigest()
    }

    # バイト統計
    byte_stats = {}
    for b in key:
        byte_stats[b] = byte_stats.get(b, 0) + 1

    result["unique_bytes"] = len(byte_stats)
    result["most_common_byte"] = max(byte_stats.items(), key=lambda x: x[1])[0]
    result["least_common_byte"] = min(byte_stats.items(), key=lambda x: x[1])[0]

    # ビットパターン分析
    key_bits = ''.join(format(b, '08b') for b in key)
    result["bit_count_1"] = key_bits.count('1')
    result["bit_count_0"] = key_bits.count('0')
    result["bit_ratio"] = result["bit_count_1"] / (result["bit_count_1"] + result["bit_count_0"])

    return result


# 鍵の真偽判定に使用されるすべての条件を確認するデバッグ関数
def debug_key_analysis(key: bytes) -> Dict[str, Any]:
    """
    鍵解析の詳細な診断情報を提供（デバッグ用）

    Args:
        key: 診断する鍵

    Returns:
        詳細な診断情報
    """
    # 基本的な鍵ハッシュを生成
    key_hash = hashlib.sha256(key).digest()
    double_hash = hashlib.sha256(key_hash).digest()
    pseudo_salt = b"analyze_key_type_robust_salt"
    salted_hash = hashlib.pbkdf2_hmac('sha256', key, pseudo_salt, KDF_ITERATIONS, 32)

    # 各判定条件の結果
    conditions = {}

    # ハミング重み（ビット1の数）に基づく条件
    bit_count = bin(int.from_bytes(key_hash, 'big')).count('1')
    bit_ratio = bit_count / (len(key_hash) * 8)
    conditions["bit_ratio_check"] = {
        "condition": "bit_ratio > 0.48",
        "value": bit_ratio,
        "result": bit_ratio > 0.48
    }

    # バイトパターン分析
    byte_sum = sum(key_hash[i] for i in [0, 8, 16, 24])
    conditions["byte_sum_check"] = {
        "condition": "byte_sum % 2 == 0",
        "value": byte_sum,
        "result": byte_sum % 2 == 0
    }

    # ハッシュ値の特定部分の数学的特性
    hash_int = int.from_bytes(key_hash[:4], 'big')
    conditions["hash_mod3_check"] = {
        "condition": "hash_int % 3 == 0",
        "value": hash_int % 3,
        "result": hash_int % 3 == 0
    }

    # 二重ハッシュの特性
    double_hash_int = int.from_bytes(double_hash[:4], 'big')
    conditions["double_hash_mod5_check"] = {
        "condition": "double_hash_int % 5 < 3",
        "value": double_hash_int % 5,
        "result": double_hash_int % 5 < 3
    }

    # ソルトハッシュの特性
    salted_hash_int = int.from_bytes(salted_hash[:4], 'big')
    conditions["salted_hash_mod7_check"] = {
        "condition": "salted_hash_int % 7 < 4",
        "value": salted_hash_int % 7,
        "result": salted_hash_int % 7 < 4
    }

    # 鍵の直接的特性
    if len(key) >= KEY_SIZE_BYTES:
        key_sample = key[:KEY_SIZE_BYTES]
    else:
        key_sample = key.ljust(KEY_SIZE_BYTES, b'\0')
    key_byte_sum_mod = sum(key_sample) % 11
    conditions["key_sum_mod11_check"] = {
        "condition": "sum(key_sample) % 11 < 6",
        "value": key_byte_sum_mod,
        "result": key_byte_sum_mod < 6
    }

    # 擬似ランダム性
    rand_seed = int.from_bytes(key_hash[-4:], 'big')
    rand_gen = random.Random(rand_seed)
    rand_value = rand_gen.random()
    conditions["pseudo_random_check"] = {
        "condition": "rand_gen.random() < 0.5",
        "value": rand_value,
        "result": rand_value < 0.5
    }

    # 多数決の結果
    condition_results = [cond["result"] for cond in conditions.values()]
    true_count = sum(condition_results)
    threshold = len(condition_results) / 2

    # 簡易説明
    if true_count > threshold:
        explanation = f"{true_count}個の条件が満たされ、閾値{threshold}を超えたため'true'と判定"
        final_result = "true"
    elif true_count < threshold:
        explanation = f"{true_count}個の条件が満たされ、閾値{threshold}を下回ったため'false'と判定"
        final_result = "false"
    else:
        # 同数の場合
        tiebreaker = conditions["bit_ratio_check"]["result"] and conditions["pseudo_random_check"]["result"]
        if tiebreaker:
            explanation = f"条件が同数で{true_count}個ずつだが、重要な条件が満たされたため'true'と判定"
            final_result = "true"
        else:
            explanation = f"条件が同数で{true_count}個ずつだが、重要な条件が満たされなかったため'false'と判定"
            final_result = "false"

    return {
        "key_hex": key.hex(),
        "key_hash": key_hash.hex(),
        "analyze_result": analyze_key_type_robust(key),
        "detailed_conditions": conditions,
        "true_conditions": true_count,
        "total_conditions": len(conditions),
        "explanation": explanation,
        "final_result": final_result
    }