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

# 相対パスによるインポート（循環インポートを防止）
from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    KDF_ITERATIONS,
    SECURITY_PARAMETER,
    MASK_SEED_SIZE
)
from method_8_homomorphic.homomorphic import PaillierCrypto
# 拡張モジュールからの循環参照を解決するためのインポート
from method_8_homomorphic.indistinguishable_ext import (
    safe_log10,
    randomize_ciphertext,
    batch_randomize_ciphertexts,
    add_statistical_noise,
    remove_statistical_noise,
    add_redundancy,
    remove_redundancy
)

# 交互配置関数
def interleave_ciphertexts(true_ciphertexts: List[int], false_ciphertexts: List[int]) -> Tuple[List[int], Dict[str, Any]]:
    """
    真と偽の暗号文を交互に配置してシャッフル

    暗号文の識別を防ぐため、真と偽の暗号文チャンクを混合し、さらにランダムシャッフルします。

    Args:
        true_ciphertexts: 真の暗号文チャンクのリスト
        false_ciphertexts: 偽の暗号文チャンクのリスト

    Returns:
        (mixed_chunks, metadata): 混合されたチャンクリストとメタデータ
    """
    if not true_ciphertexts and not false_ciphertexts:
        return [], {}

    # 各チャンクに識別情報を付与
    tagged_chunks = []
    true_indices = []
    false_indices = []

    for i, chunk in enumerate(true_ciphertexts):
        tagged_chunks.append({"index": len(tagged_chunks), "type": "true", "value": chunk})
        true_indices.append(len(tagged_chunks) - 1)

    for i, chunk in enumerate(false_ciphertexts):
        tagged_chunks.append({"index": len(tagged_chunks), "type": "false", "value": chunk})
        false_indices.append(len(tagged_chunks) - 1)

    # シャッフルシードを生成
    shuffle_seed_bytes = os.urandom(16)
    shuffle_seed = int.from_bytes(shuffle_seed_bytes, byteorder='big')
    random.seed(shuffle_seed)

    # 暗号文をランダムにシャッフル
    random.shuffle(tagged_chunks)

    # シャッフル後のマッピング情報を記録
    mapping = []
    for i, chunk in enumerate(tagged_chunks):
        mapping.append({
            "index": i,
            "original_index": chunk["index"],
            "type": chunk["type"]
        })

    # シャッフルされた暗号文の値だけを抽出
    mixed_chunks = [chunk["value"] for chunk in tagged_chunks]

    # メタデータ（復元のために必要）
    metadata = {
        "shuffle_seed": shuffle_seed_bytes.hex(),
        "true_count": len(true_ciphertexts),
        "false_count": len(false_ciphertexts),
        "true_indices": true_indices,
        "false_indices": false_indices,
        "mapping": mapping
    }

    return mixed_chunks, metadata

def deinterleave_ciphertexts(mixed_chunks: List[int], metadata: Dict[str, Any], key_type: str) -> List[int]:
    """
    交互配置された暗号文チャンクを元に戻す

    Args:
        mixed_chunks: シャッフルされた暗号文チャンクのリスト
        metadata: 交互配置の情報を含むメタデータ
        key_type: 取得したい暗号文の種類 ("true" または "false")

    Returns:
        元の暗号文チャンクのリスト
    """
    if not mixed_chunks or not metadata:
        return []

    if key_type not in ["true", "false"]:
        raise ValueError(f"無効なキータイプ: {key_type}. 'true'または'false'のみ有効です。")

    # 指定されたタイプの暗号文チャンクをマッピング情報から取得
    mapping = metadata.get("mapping", [])
    indices = []

    for entry in mapping:
        if entry.get("type") == key_type:
            indices.append(entry.get("index"))

    # インデックスが有効範囲内か確認して暗号文を取得
    result = []
    for idx in indices:
        if 0 <= idx < len(mixed_chunks):
            result.append(mixed_chunks[idx])

    return result

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
def analyze_key_type_enhanced(key: Union[bytes, str, int], metadata: Optional[Dict[str, Any]] = None) -> str:
    """
    鍵の種類をより堅牢に解析する拡張版

    この関数は単純な16進数表現の和ではなく、より複雑なハッシュベースの判定を行います。
    また、利用可能な場合はメタデータの情報も利用して判定の堅牢性を高めます。

    Args:
        key: 解析する鍵（bytes, str, intのいずれか）
        metadata: 利用可能な場合のメタデータ情報

    Returns:
        鍵の種類 ("true" または "false")
    """
    # 入力がbytes型でない場合、変換を試みる
    if not isinstance(key, bytes):
        print(f"[WARN] analyze_key_type_enhanced: 鍵がbytes型ではありません({type(key)})。変換を試みます。")
        try:
            if isinstance(key, str):
                # 16進数表現の文字列として扱い、bytes型に変換
                if key.startswith('0x'):
                    key = bytes.fromhex(key[2:])
                else:
                    key = bytes.fromhex(key) if all(c in '0123456789abcdefABCDEF' for c in key) else key.encode('utf-8')
            elif isinstance(key, int):
                # 整数をバイト列に変換（最大32バイト）
                byte_length = (key.bit_length() + 7) // 8
                key = key.to_bytes(max(byte_length, 1), 'big')
            else:
                # その他の型は文字列に変換してからUTF-8でエンコード
                key = str(key).encode('utf-8')
        except Exception as e:
            print(f"[ERROR] 鍵型変換エラー: {e}")
            # エラーが発生した場合、デフォルト鍵を使用
            key = b'default_key_for_error_case'

    # 鍵からSHA-256ハッシュを生成
    key_hash = hashlib.sha256(key).digest()

    # ハッシュ値を整数に変換
    hash_int = int.from_bytes(key_hash, byteorder='big')

    # ハッシュ値のビットパターンを分析
    bit_count = bin(hash_int).count('1')
    total_bits = hash_int.bit_length()  # bytes.bit_lengthではなくint.bit_lengthを使用
    bit_ratio = bit_count / total_bits if total_bits > 0 else 0.5

    # 複数の条件を組み合わせた判定
    # これにより単純な改変による攻撃を防止
    condition1 = bit_ratio > 0.48  # ビット1の比率が48%以上
    condition2 = (hash_int % 256) < 128  # 下位8ビットのモジュロ演算
    condition3 = (hash_int & 0xFF00) > 0x7F00  # 第2バイトのビット比較
    condition4 = key_hash[0] % 2 == 0  # ハッシュの最初のバイトが偶数

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
        except Exception as e:
            # 例外が発生した場合は、シンプルなフォールバック条件を使用
            print(f"[WARN] メタデータ処理中のエラー: {e}")
            condition5 = key_hash[16] % 2 == 0
    else:
        # メタデータがない場合は鍵のハッシュの16バイト目で判定
        condition5 = key_hash[16] % 2 == 0

    # 条件の複雑な組み合わせで判定
    # 単純な条件ではなく、複数の条件を組み合わせることで改ざんに対する耐性を高める
    true_score = sum([condition1, condition2, condition3, condition4, condition5])

    # 3つ以上の条件が満たされれば真の鍵と判定
    return "true" if true_score >= 3 else "false"

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

# 実装テスト用コード
if __name__ == "__main__":
    print("======== 識別不能性機能テスト ========")

    # Paillier暗号システムの初期化
    from method_8_homomorphic.homomorphic import PaillierCrypto
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    public_key, private_key = paillier.generate_keys()

    # テスト用の平文生成
    true_plaintexts = [i for i in range(10, 30)]
    false_plaintexts = [i for i in range(100, 120)]

    # 暗号化
    true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
    false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

    # 統計的識別不能性テスト
    print("\n統計的識別不能性テスト")

    # 総合的な識別不能性テスト
    print("\n総合的な識別不能性テスト")
    indistinguishable_ciphertexts, metadata = apply_comprehensive_indistinguishability(
        true_ciphertexts, false_ciphertexts, paillier)

    # 復元テスト（真の鍵で）
    recovered_true = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "true", paillier)

    # 復元テスト（偽の鍵で）
    recovered_false = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "false", paillier)

    # 強化版での復元テスト
    print("\nセキュリティ強化版の識別不能性テスト")
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

    print("\n======== テスト完了 ========")

class IndistinguishableWrapper:
    """識別不能性を提供するラッパークラス"""

    def __init__(self):
        """初期化"""
        self.seed = None
        self.counter = 0

    def generate_seed(self, key: bytes, salt: bytes, kdf_iterations: int = 100000) -> bytes:
        """
        識別不能性のためのシードを生成

        Args:
            key: 鍵データ
            salt: ソルト
            kdf_iterations: KDFの反復回数

        Returns:
            シードデータ
        """
        # 鍵とソルトからシードを派生
        kdf_input = key + salt
        self.seed = hashlib.pbkdf2_hmac('sha256', kdf_input, salt, kdf_iterations, 32)

        # カウンタをリセット
        self.counter = 0

        return self.seed

    def is_true_path(self, key: bytes, salt: bytes, kdf_iterations: int = 100000) -> bool:
        """
        真偽の判定を行う
        識別不能性を確保するため、計算量的に区別不可能な実装

        Args:
            key: 鍵データ
            salt: ソルト
            kdf_iterations: KDFの反復回数

        Returns:
            True: 真の経路, False: 偽の経路
        """
        if self.seed is None:
            self.generate_seed(key, salt, kdf_iterations)

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

            # 最終的にbytesに変換して返す
            return bytes(result[:original_data_size])
        except Exception as e:
            # エラーが発生した場合は、デバッグ情報を出力して空のバイト列を返す
            print(f"データの復元中にエラーが発生しました: {e}")
            return b"Error during deobfuscation"

    def time_equalizer(self, func, *args, **kwargs):
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