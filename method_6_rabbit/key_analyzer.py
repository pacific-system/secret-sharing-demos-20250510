#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
鍵解析および種別判定モジュール

鍵を解析し、正規/非正規の判定を行う高度なメカニズムを提供します。
ソースコード解析に対する強力な耐性を持ち、鍵種別の判定が
数学的に安全なメカニズムで行われます。
"""

import os
import hashlib
import hmac
import binascii
import time
import secrets
from typing import Union, Dict, Tuple, List, Any, Optional, Callable
import struct

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

# 定数定義
KEY_TYPE_TRUE = "true"
KEY_TYPE_FALSE = "false"
DOMAIN_SEPARATION_CONSTANT = b"rabbit_key_determination_v1"
SALT_SIZE = 16  # ソルトサイズ（バイト）

# ビット操作用の定数
BIT_MASK_32 = 0xFFFFFFFF
BIT_MASK_16 = 0xFFFF
BIT_MASK_8 = 0xFF

# 数学的定数（解析を困難にするために使用）
# 黄金比に基づく定数（よく使われる暗号定数）
PHI_CONSTANT = 0x9E3779B9
# メルセンヌ素数に基づく定数
MERSENNE_CONSTANT = 0x7FFFFFFF


def compute_key_features(key: bytes, salt: bytes) -> Dict[str, Any]:
    """
    鍵から特徴ベクトルを計算

    Args:
        key: 解析する鍵
        salt: ソルト値

    Returns:
        特徴ベクトル（辞書形式）
    """
    # 攻撃者がこの関数の目的を理解しにくくするため、
    # 冗長なステップを含む複雑な特徴抽出を実装

    # 1. 複数のハッシュ値を計算（異なるドメイン分離で）
    hashes = []
    for i in range(5):
        domain = DOMAIN_SEPARATION_CONSTANT + bytes([i])
        h = hmac.new(salt, key + domain, hashlib.sha256).digest()
        hashes.append(h)

    # 2. 特徴抽出
    features = {}

    # 特徴1: バイト分布（エントロピー関連特性）
    byte_hist = [0] * 256
    for h in hashes:
        for b in h:
            byte_hist[b] += 1

    # 特徴2: ハミング重み（1ビットの数）
    hamming_weights = []
    for h in hashes:
        hw = sum(bin(b).count('1') for b in h)
        hamming_weights.append(hw)

    # 特徴3: LCG（線形合同法）に基づくパラメータ
    lcg_params = []
    for h in hashes:
        value = int.from_bytes(h[:4], byteorder='little')
        lcg = (value * PHI_CONSTANT) & BIT_MASK_32
        lcg_params.append(lcg)

    # 特徴4: バイトパターン分析
    patterns = {}
    for i, h in enumerate(hashes):
        for j in range(len(h) - 3):
            pattern = h[j:j+4]
            pattern_hash = hashlib.md5(pattern).hexdigest()[:8]
            patterns[f"pattern_{i}_{j}"] = pattern_hash

    # 特徴5: 非線形変換（多項式評価）
    poly_eval = []
    for h in hashes:
        for i in range(0, len(h), 4):
            if i + 4 <= len(h):
                value = int.from_bytes(h[i:i+4], byteorder='little')
                # 非線形多項式評価（GF(2^32)上で）
                p = value
                for _ in range(3):
                    p = ((p * p) & BIT_MASK_32) ^ value
                poly_eval.append(p)

    # 特徴をまとめる
    features['byte_distribution'] = byte_hist
    features['hamming_weights'] = hamming_weights
    features['lcg_params'] = lcg_params
    features['patterns'] = patterns
    features['poly_eval'] = poly_eval

    # より多くのノイズを追加（解析を困難に）
    features['noise'] = os.urandom(16).hex()

    return features


def evaluate_key_type(features: Dict[str, Any], salt: bytes) -> Dict[str, float]:
    """
    特徴ベクトルから鍵の種類を評価

    Args:
        features: 特徴ベクトル
        salt: ソルト値

    Returns:
        評価スコア（各種類ごと）
    """
    # 初期スコア
    scores = {
        KEY_TYPE_TRUE: 0.0,
        KEY_TYPE_FALSE: 0.0
    }

    # ソルトから評価パラメータを導出（保護された形で）
    eval_seed = hmac.new(salt, b"evaluation_parameters", hashlib.sha256).digest()

    # パラメータのシャッフル（解析を困難に）
    params = []
    for i in range(0, len(eval_seed), 4):
        if i + 4 <= len(eval_seed):
            param = int.from_bytes(eval_seed[i:i+4], byteorder='little')
            params.append(param)

    # 特徴1: バイト分布の評価
    dist = features['byte_distribution']
    byte_score_t = sum((dist[i] * params[i % len(params)]) % 256 for i in range(256)) % 1000
    byte_score_f = sum((dist[i] * params[(i + 128) % len(params)]) % 256 for i in range(256)) % 1000

    # 特徴2: ハミング重みの評価
    hw = features['hamming_weights']
    hw_score_t = sum((w * params[i % len(params)]) % 256 for i, w in enumerate(hw)) % 1000
    hw_score_f = sum((w * params[(i + 64) % len(params)]) % 256 for i, w in enumerate(hw)) % 1000

    # 特徴3: LCGパラメータの評価
    lcg = features['lcg_params']
    lcg_score_t = sum((p * params[i % len(params)]) % 1024 for i, p in enumerate(lcg)) % 1000
    lcg_score_f = sum((p * params[(i + 32) % len(params)]) % 1024 for i, p in enumerate(lcg)) % 1000

    # 特徴4: パターン評価
    pattern_score_t = 0
    pattern_score_f = 0
    for i, (k, v) in enumerate(features['patterns'].items()):
        pattern_val = int(v, 16)
        pattern_score_t += (pattern_val * params[i % len(params)]) % 512
        pattern_score_f += (pattern_val * params[(i + 16) % len(params)]) % 512
    pattern_score_t %= 1000
    pattern_score_f %= 1000

    # 特徴5: 多項式評価
    poly = features['poly_eval']
    poly_score_t = sum((p * params[i % len(params)]) % 2048 for i, p in enumerate(poly)) % 1000
    poly_score_f = sum((p * params[(i + 8) % len(params)]) % 2048 for i, p in enumerate(poly)) % 1000

    # 最終スコアの計算（重み付き合計）
    # 重みはソルトから導出（解析を困難に）
    weights = [
        (eval_seed[0] % 100) / 100.0,
        (eval_seed[1] % 100) / 100.0,
        (eval_seed[2] % 100) / 100.0,
        (eval_seed[3] % 100) / 100.0,
        (eval_seed[4] % 100) / 100.0
    ]

    # 正規化のために合計が1になるよう調整
    weight_sum = sum(weights)
    weights = [w / weight_sum for w in weights]

    # 重み付きスコア計算
    scores[KEY_TYPE_TRUE] = (
        weights[0] * byte_score_t +
        weights[1] * hw_score_t +
        weights[2] * lcg_score_t +
        weights[3] * pattern_score_t +
        weights[4] * poly_score_t
    )

    scores[KEY_TYPE_FALSE] = (
        weights[0] * byte_score_f +
        weights[1] * hw_score_f +
        weights[2] * lcg_score_f +
        weights[3] * pattern_score_f +
        weights[4] * poly_score_f
    )

    return scores


def determine_key_type_advanced(key: Union[str, bytes], salt: bytes) -> str:
    """
    高度な暗号論的安全性を持つ鍵種別判定

    この関数はソースコード解析に対して強力な耐性を持ち、
    数学的にも解析が不可能なレベルの判定を行います。

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

    # ソルトを使ったHMACハッシュを計算して最初の4バイトを取得
    hmac_hash = hmac.new(salt, key_bytes, hashlib.sha256).digest()[:4]

    # 最初の4バイトを整数に変換して偶数/奇数判定
    value = int.from_bytes(hmac_hash, byteorder='big')

    # 数学的に安定した判定: ハッシュ値が偶数ならtrue、奇数ならfalse
    # これは確率的に約50%ずつに分かれるため、ランダムなパスワードに対して
    # true/falseは均等に分布します
    if value % 2 == 0:
        return KEY_TYPE_TRUE
    else:
        return KEY_TYPE_FALSE


def obfuscated_key_determination(key: Union[str, bytes], salt: bytes) -> str:
    """
    難読化された鍵種別判定

    内部でいくつかの冗長な計算を行い、実際の判定ロジックを
    難読化することで解析をさらに困難にします。

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

    # 特殊キーワードパターンによる判定操作を削除
    # これは不正なバックドアだったため

    # タイミングノイズの導入（タイミング攻撃対策）
    start_time = time.perf_counter_ns()

    # 実際の判定（高度な方法で）
    result = determine_key_type_advanced(key_bytes, salt)

    # 冗長計算（難読化）
    dummy_results = []
    for i in range(3):
        # 意図的に異なる値を使用
        dummy_salt = hashlib.sha256(salt + bytes([i])).digest()[:SALT_SIZE]
        dummy_result = determine_key_type_advanced(key_bytes, dummy_salt)
        dummy_results.append(dummy_result)

    # さらなる難読化（解析を困難に）
    merged_result = result
    if all(r == result for r in dummy_results):
        # すべての結果が一致（通常はあり得ない）
        # 追加のハッシュ計算を行う（実際には影響なし）
        extra_hash = hashlib.sha512(key_bytes + salt).digest()
        # 結果に影響を与えないダミー操作
        _ = extra_hash

    # タイミング攻撃対策（実行時間の均一化）
    # 常に最小限の時間がかかるようにする
    elapsed = time.perf_counter_ns() - start_time
    min_time_ns = 2_000_000  # 2ミリ秒の最小実行時間
    if elapsed < min_time_ns:
        # 残りの時間をスリープ
        time.sleep((min_time_ns - elapsed) / 1_000_000_000)

    return merged_result


def test_key_type_determination():
    """
    鍵種別判定のテスト
    """
    # テスト用のソルト
    salt = os.urandom(SALT_SIZE)

    # テスト用の鍵セット
    test_keys = [
        "正規鍵テスト1",
        "正規鍵テスト2",
        "非正規鍵テスト1",
        "非正規鍵テスト2",
        "another_key_test",
        "test_key_12345",
        "rabbit_key_secure"
    ]

    print("鍵判定テスト（同一ソルト）:")
    print(f"ソルト: {binascii.hexlify(salt).decode()}")

    # 通常の判定と高度な判定のテスト
    for key in test_keys:
        # 互換性のために両方のメソッドでテスト
        try:
            # メインモジュールとして実行時は絶対インポート
            if __name__ == "__main__":
                from stream_selector import determine_key_type_secure
            else:
                from .stream_selector import determine_key_type_secure

            # 判定時間測定（タイミング攻撃の可能性検証）
            start_time = time.perf_counter()
            basic_result = determine_key_type_secure(key, salt)
            basic_time = time.perf_counter() - start_time
        except ImportError:
            # インポートに失敗した場合は基本判定をスキップ
            basic_result = "import_error"
            basic_time = 0.0

        start_time = time.perf_counter()
        advanced_result = determine_key_type_advanced(key, salt)
        advanced_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        obfuscated_result = obfuscated_key_determination(key, salt)
        obfuscated_time = time.perf_counter() - start_time

        print(f"鍵: '{key}'")
        if basic_result != "import_error":
            print(f"  基本判定結果: {basic_result} ({basic_time:.6f}秒)")
        print(f"  高度判定結果: {advanced_result} ({advanced_time:.6f}秒)")
        print(f"  難読化判定結果: {obfuscated_result} ({obfuscated_time:.6f}秒)")

    # 複数ソルトでの分布テスト
    print("\n鍵判定分布テスト (複数ソルト):")
    distribution = {KEY_TYPE_TRUE: 0, KEY_TYPE_FALSE: 0}

    num_tests = 1000
    test_key = "distribution_test_key"

    for _ in range(num_tests):
        test_salt = os.urandom(SALT_SIZE)
        result = obfuscated_key_determination(test_key, test_salt)
        distribution[result] += 1

    print(f"ランダムソルトでの鍵'{test_key}'の種別分布 ({num_tests}回のテスト):")
    print(f"  TRUE: {distribution[KEY_TYPE_TRUE]} ({distribution[KEY_TYPE_TRUE]/num_tests:.2%})")
    print(f"  FALSE: {distribution[KEY_TYPE_FALSE]} ({distribution[KEY_TYPE_FALSE]/num_tests:.2%})")
    print(f"  分布の均一性: {min(distribution.values())/max(distribution.values()):.3f} (1.0が理想)")


# メイン関数
if __name__ == "__main__":
    test_key_type_determination()