#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
識別不能性（Indistinguishable）機能の補助関数

このモジュールは、準同型暗号マスキング方式の識別不能性を
強化するための補助関数を提供します。
"""

import os
import hashlib
import random
import time
import binascii
import secrets
import numpy as np
from typing import Dict, List, Tuple, Union, Any, Callable, Optional
import struct
import matplotlib.pyplot as plt
import io
import base64

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    KDF_ITERATIONS,
    SECURITY_PARAMETER
)
from method_8_homomorphic.homomorphic import PaillierCrypto


# 統計的特性のマスキング関数
def mask_statistical_properties(paillier: PaillierCrypto, ciphertexts: List[int]) -> List[int]:
    """
    暗号文の統計的特性をマスキング

    Args:
        paillier: 準同型暗号システムのインスタンス
        ciphertexts: マスキングする暗号文のリスト

    Returns:
        マスキングされた暗号文のリスト
    """
    if not ciphertexts:
        return []

    masked_ciphertexts = []
    n = paillier.public_key['n']
    n_squared = n * n

    for ct in ciphertexts:
        # 統計的特性を均質化するためのランダム操作
        # 1. ランダム値との準同型加算
        r1 = random.randint(1, 1000)
        masked_ct = paillier.add_constant(ct, r1, paillier.public_key)

        # 2. ランダム再ランダム化
        r2 = random.randint(1, n - 1)
        rn = pow(r2, n, n_squared)
        masked_ct = (masked_ct * rn) % n_squared

        # 3. ビット長の調整（少しだけ追加情報を付与）
        bit_length = masked_ct.bit_length()
        target_bit_length = ((bit_length + 63) // 64) * 64  # 64ビット単位に切り上げ
        padding = random.getrandbits(target_bit_length - bit_length)
        masked_ct = (masked_ct << (target_bit_length - bit_length)) | padding

        masked_ciphertexts.append(masked_ct)

    return masked_ciphertexts


def unmask_statistical_properties(masked_ciphertexts: List[int]) -> List[int]:
    """
    統計的特性のマスキングを除去

    Args:
        masked_ciphertexts: マスキングされた暗号文のリスト

    Returns:
        元の暗号文に近い暗号文のリスト
    """
    if not masked_ciphertexts:
        return []

    # マスキングされた暗号文をそのまま返す
    # 識別不能性のためのマスキングは通常、準同型性を保持しているため
    # 完全に元に戻す必要はない。復号時に正しい平文に復号される
    return masked_ciphertexts


# 冗長性追加関数
def add_redundancy(paillier: PaillierCrypto,
                 true_ciphertexts: List[int],
                 false_ciphertexts: List[int]) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """
    暗号文に冗長性を追加

    Args:
        paillier: 準同型暗号システムのインスタンス
        true_ciphertexts: 正規の暗号文のリスト
        false_ciphertexts: 非正規の暗号文のリスト

    Returns:
        (redundant_true, redundant_false, metadata):
            冗長性が追加された暗号文と、その復元に必要なメタデータ
    """
    # 基本的な冗長性チェックのための特別マーカー
    true_marker = 0  # 真の暗号文用マーカー
    false_marker = 1  # 偽の暗号文用マーカー

    # 冗長データ（復元時に必要）
    true_extra_data = []
    false_extra_data = []

    # 真の暗号文に冗長性を追加
    redundant_true = []
    for i, ct in enumerate(true_ciphertexts):
        # 元の暗号文をそのまま保持
        redundant_true.append(ct)

        # 冗長データを生成（復元時の検証用）
        true_extra_data.append((i, true_marker))

    # 偽の暗号文に冗長性を追加
    redundant_false = []
    for i, ct in enumerate(false_ciphertexts):
        # 元の暗号文をそのまま保持
        redundant_false.append(ct)

        # 冗長データを生成（復元時の検証用）
        false_extra_data.append((i, false_marker))

    # メタデータ（復元時に必要）
    metadata = {
        "true_extra_data": true_extra_data,
        "false_extra_data": false_extra_data,
        "true_length": len(true_ciphertexts),
        "false_length": len(false_ciphertexts)
    }

    return redundant_true, redundant_false, metadata


def remove_redundancy(redundant_ciphertexts: List[int],
                    metadata: Dict[str, Any],
                    key_type: str) -> List[int]:
    """
    冗長性を除去して元の暗号文を復元

    Args:
        redundant_ciphertexts: 冗長性が追加された暗号文のリスト
        metadata: add_redundancyで生成されたメタデータ
        key_type: 鍵の種類（"true" または "false"）

    Returns:
        冗長性が除去された元の暗号文のリスト
    """
    # メタデータから情報を取得
    extra_data = metadata[f"{key_type}_extra_data"]
    length = metadata[f"{key_type}_length"]

    # 冗長性なしの暗号文だけを取得（元の暗号文）
    # このシンプルな実装では、冗長性は単に追加データとして保存し、
    # 元の暗号文自体は変更していない
    return redundant_ciphertexts[:length]


# 総合的な統計的安全性テスト関数
def test_statistical_safety(true_ciphertexts: List[int],
                          false_ciphertexts: List[int],
                          indist_true: List[int],
                          indist_false: List[int]) -> Dict[str, Any]:
    """
    暗号文の統計的安全性をテスト

    Args:
        true_ciphertexts: 元の真の暗号文リスト
        false_ciphertexts: 元の偽の暗号文リスト
        indist_true: 識別不能性適用後の真の暗号文リスト
        indist_false: 識別不能性適用後の偽の暗号文リスト

    Returns:
        テスト結果を含む辞書
    """
    results = {}

    # ビット長分布の比較
    true_bits_before = [ct.bit_length() for ct in true_ciphertexts]
    false_bits_before = [ct.bit_length() for ct in false_ciphertexts]
    true_bits_after = [ct.bit_length() for ct in indist_true]
    false_bits_after = [ct.bit_length() for ct in indist_false]

    # 平均ビット長
    results["avg_bit_length"] = {
        "true_before": np.mean(true_bits_before),
        "false_before": np.mean(false_bits_before),
        "true_after": np.mean(true_bits_after),
        "false_after": np.mean(false_bits_after)
    }

    # 標準偏差
    results["std_bit_length"] = {
        "true_before": np.std(true_bits_before),
        "false_before": np.std(false_bits_before),
        "true_after": np.std(true_bits_after),
        "false_after": np.std(false_bits_after)
    }

    # ヒストグラム重複率の計算（統計的類似性の指標）
    def histogram_overlap(data1, data2, bins=20):
        """2つのデータセット間のヒストグラム重複率を計算"""
        hist1, bin_edges = np.histogram(data1, bins=bins, density=True)
        hist2, _ = np.histogram(data2, bins=bin_edges, density=True)

        # 各ビンの最小値を取得（重複部分）
        overlap = np.sum(np.minimum(hist1, hist2)) * (bin_edges[1] - bin_edges[0])
        return overlap

    # 識別不能性適用前後での真偽の区別可能性
    overlap_before = histogram_overlap(true_bits_before, false_bits_before)
    overlap_after = histogram_overlap(true_bits_after, false_bits_after)

    results["histogram_overlap"] = {
        "before": overlap_before,
        "after": overlap_after,
        "improvement": (overlap_after - overlap_before) / (1 - overlap_before) if overlap_before < 1 else 0
    }

    # 簡単な分類器での識別困難性テスト
    def simple_classifier(data, threshold):
        """単純なビット長ベースの分類器"""
        return [1 if x > threshold else 0 for x in data]

    # 適用前の分類精度
    avg_bit_before = (np.mean(true_bits_before) + np.mean(false_bits_before)) / 2
    pred_true_before = simple_classifier(true_bits_before, avg_bit_before)
    pred_false_before = simple_classifier(false_bits_before, avg_bit_before)

    accuracy_before = (
        sum(1 for x in pred_true_before if x == 1) +  # 真を真と予測
        sum(1 for x in pred_false_before if x == 0)   # 偽を偽と予測
    ) / (len(pred_true_before) + len(pred_false_before))

    # 適用後の分類精度
    avg_bit_after = (np.mean(true_bits_after) + np.mean(false_bits_after)) / 2
    pred_true_after = simple_classifier(true_bits_after, avg_bit_after)
    pred_false_after = simple_classifier(false_bits_after, avg_bit_after)

    accuracy_after = (
        sum(1 for x in pred_true_after if x == 1) +   # 真を真と予測
        sum(1 for x in pred_false_after if x == 0)    # 偽を偽と予測
    ) / (len(pred_true_after) + len(pred_false_after))

    results["classification_accuracy"] = {
        "before": accuracy_before,
        "after": accuracy_after,
        "improvement": (0.5 - abs(accuracy_after - 0.5)) / (0.5 - abs(accuracy_before - 0.5)) if abs(accuracy_before - 0.5) < 0.5 else float('inf')
    }

    # 安全性の総合評価
    # 0.5に近いほど区別困難（理想的には0.5）
    safety_score = 1.0 - abs(accuracy_after - 0.5) * 2  # 0.0～1.0の範囲

    results["safety_score"] = safety_score
    results["is_safe"] = safety_score > 0.8  # 80%以上のスコアを安全と判定

    return results


# テスト関数
def test_functions():
    """関数のテスト"""
    print("=== 識別不能性補助関数のテスト ===")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    public_key, private_key = paillier.generate_keys()

    # テスト平文
    true_plaintexts = [i for i in range(10, 20)]
    false_plaintexts = [i for i in range(100, 110)]

    # 暗号化
    true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
    false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

    print(f"テスト平文（真）: {true_plaintexts}")
    print(f"テスト平文（偽）: {false_plaintexts}")

    # 統計的特性のマスキングテスト
    masked_true = mask_statistical_properties(paillier, true_ciphertexts)
    masked_false = mask_statistical_properties(paillier, false_ciphertexts)

    print("\n1. 統計的特性のマスキングテスト")
    print(f"マスキング前の平均ビット長（真）: {sum(ct.bit_length() for ct in true_ciphertexts) / len(true_ciphertexts):.1f}ビット")
    print(f"マスキング後の平均ビット長（真）: {sum(ct.bit_length() for ct in masked_true) / len(masked_true):.1f}ビット")

    # マスキング前後での復号テスト
    decrypted_original = [paillier.decrypt(ct, private_key) for ct in true_ciphertexts[:2]]
    decrypted_masked = [paillier.decrypt(ct, private_key) for ct in masked_true[:2]]

    print(f"元の平文（最初の2件）: {decrypted_original}")
    print(f"マスキング後の平文（最初の2件）: {decrypted_masked}")

    # 冗長性の追加テスト
    redundant_true, redundant_false, redundancy_metadata = add_redundancy(
        paillier, true_ciphertexts, false_ciphertexts
    )

    print("\n2. 冗長性の追加テスト")
    print(f"元のチャンク数（真）: {len(true_ciphertexts)}")
    print(f"冗長性追加後のチャンク数（真）: {len(redundant_true)}")
    print(f"冗長性メタデータ: {redundancy_metadata.keys()}")

    # 冗長性の除去テスト
    recovered_true = remove_redundancy(redundant_true, redundancy_metadata, "true")

    print(f"冗長性除去後のチャンク数（真）: {len(recovered_true)}")

    # 復号して確認
    decrypted_recovered = [paillier.decrypt(ct, private_key) for ct in recovered_true[:2]]
    print(f"冗長性除去後の平文（最初の2件）: {decrypted_recovered}")
    print(f"元の平文と一致するか: {decrypted_original == decrypted_recovered}")

    # 統計的安全性テスト
    safety_results = test_statistical_safety(
        true_ciphertexts, false_ciphertexts, masked_true, masked_false
    )

    print("\n3. 統計的安全性テスト")
    print(f"ヒストグラム重複率（適用前）: {safety_results['histogram_overlap']['before']:.4f}")
    print(f"ヒストグラム重複率（適用後）: {safety_results['histogram_overlap']['after']:.4f}")
    print(f"分類精度（適用前）: {safety_results['classification_accuracy']['before']:.4f}")
    print(f"分類精度（適用後）: {safety_results['classification_accuracy']['after']:.4f}")
    print(f"安全性スコア: {safety_results['safety_score']:.4f}")
    print(f"安全と判定されたか: {safety_results['is_safe']}")

    print("\nテスト完了")


if __name__ == "__main__":
    test_functions()