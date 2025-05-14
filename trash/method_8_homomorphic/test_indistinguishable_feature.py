#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式 - 識別不能性機能のスタンドアロンテスト

このスクリプトは各ファイルを直接インポートせず、関数を個別にコピーしてテストします。
"""

import os
import random
import hashlib
import math
import secrets
import json
import base64
import time
from typing import Tuple, Dict, List, Any, Optional, Union, Callable
import numpy as np
import sympy
from sympy import mod_inverse

# 設定定数
PAILLIER_KEY_BITS = 1024  # テスト用に小さくする
PAILLIER_PRECISION = 1024
KDF_ITERATIONS = 10000
SALT_SIZE = 16
KEY_SIZE_BYTES = 32
SECURITY_PARAMETER = 128

# シンプルなPaillier暗号実装
class PaillierCrypto:
    """Paillier暗号の簡易実装（加法準同型）"""

    def __init__(self, bits: int = PAILLIER_KEY_BITS):
        self.bits = bits
        self.precision = PAILLIER_PRECISION
        self.n = 0
        self.g = 0
        self.lambda_val = 0
        self.mu = 0
        self.public_key = None
        self.private_key = None

    def generate_keys(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        # 2つの素数を生成
        p = sympy.randprime(2**(self.bits//2-1), 2**(self.bits//2))
        q = sympy.randprime(2**(self.bits//2-1), 2**(self.bits//2))

        n = p * q
        lambda_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        g = n + 1

        # μ計算
        g_lambda = pow(g, lambda_val, n * n)
        l_g_lambda = (g_lambda - 1) // n
        mu = mod_inverse(l_g_lambda, n)

        # 鍵を設定
        self.n = n
        self.g = g
        self.lambda_val = lambda_val
        self.mu = mu

        public_key = {'n': n, 'g': g}
        private_key = {'lambda': lambda_val, 'mu': mu, 'p': p, 'q': q, 'n': n}

        self.public_key = public_key
        self.private_key = private_key

        return public_key, private_key

    def encrypt(self, m: int, public_key: Dict[str, int] = None) -> int:
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = public_key['n']
        g = public_key['g']
        m = m % n
        r = random.randint(1, n - 1)
        n_squared = n * n
        g_m = pow(g, m, n_squared)
        r_n = pow(r, n, n_squared)
        c = (g_m * r_n) % n_squared
        return c

    def decrypt(self, c: int, private_key: Dict[str, int] = None) -> int:
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        n = private_key['n']
        lambda_val = private_key['lambda']
        mu = private_key['mu']
        n_squared = n * n
        c_lambda = pow(c, lambda_val, n_squared)
        l_c_lambda = (c_lambda - 1) // n
        m = (l_c_lambda * mu) % n
        return m

    def add_constant(self, c: int, k: int, public_key: Dict[str, int] = None) -> int:
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = public_key['n']
        g = public_key['g']
        n_squared = n * n
        k = k % n
        g_k = pow(g, k, n_squared)
        return (c * g_k) % n_squared


# 識別不能性機能
def randomize_ciphertext(paillier: PaillierCrypto, ciphertext: int) -> int:
    """暗号文の再ランダム化"""
    if paillier.public_key is None:
        raise ValueError("公開鍵が設定されていません")

    n = paillier.public_key['n']
    n_squared = n * n
    r = random.randint(1, n - 1)
    rn = pow(r, n, n_squared)
    return (ciphertext * rn) % n_squared


def batch_randomize_ciphertexts(paillier: PaillierCrypto, ciphertexts: List[int]) -> List[int]:
    """複数の暗号文をまとめてランダム化"""
    return [randomize_ciphertext(paillier, ct) for ct in ciphertexts]


def add_statistical_noise(ciphertexts: List[int], intensity: float = 0.1,
                         paillier: Optional[PaillierCrypto] = None) -> Tuple[List[int], List[int]]:
    """暗号文に統計的ノイズを追加"""
    if not ciphertexts:
        return [], []

    noisy_ciphertexts = []
    noise_values = []

    if paillier is None or paillier.public_key is None:
        # 非準同型ノイズ
        max_val = max(ciphertexts)
        min_val = min(ciphertexts)
        range_val = max(max_val - min_val, 1)

        for ct in ciphertexts:
            noise_max = int(range_val * intensity)
            noise = random.randint(-noise_max, noise_max)
            noise_values.append(noise)
            noisy_ciphertexts.append(ct + noise)
    else:
        # 準同型ノイズ
        n = paillier.public_key['n']
        noise_range = max(1, int(n * intensity / 100))

        for ct in ciphertexts:
            noise = random.randint(1, noise_range)
            noise_values.append(noise)
            noisy_ct = paillier.add_constant(ct, noise, paillier.public_key)
            noisy_ciphertexts.append(noisy_ct)

    return noisy_ciphertexts, noise_values


def remove_statistical_noise(ciphertexts: List[int], noise_values: List[int],
                            paillier: Optional[PaillierCrypto] = None) -> List[int]:
    """統計的ノイズを除去"""
    if not ciphertexts or not noise_values or len(ciphertexts) != len(noise_values):
        return ciphertexts

    denoised_ciphertexts = []

    if paillier is None or paillier.public_key is None:
        # 非準同型ノイズ除去
        for i, ct in enumerate(ciphertexts):
            denoised_ciphertexts.append(ct - noise_values[i])
    else:
        # 準同型ノイズ除去
        for i, ct in enumerate(ciphertexts):
            neg_noise = paillier.public_key['n'] - (noise_values[i] % paillier.public_key['n'])
            denoised_ct = paillier.add_constant(ct, neg_noise, paillier.public_key)
            denoised_ciphertexts.append(denoised_ct)

    return denoised_ciphertexts


def interleave_ciphertexts(true_chunks: List[int], false_chunks: List[int],
                         shuffle_seed: Optional[bytes] = None) -> Tuple[List[int], Dict[str, Any]]:
    """真偽の暗号文を交互配置してシャッフル"""
    # 長さを揃える
    if len(true_chunks) != len(false_chunks):
        max_len = max(len(true_chunks), len(false_chunks))
        if len(true_chunks) < max_len:
            true_chunks = true_chunks + true_chunks[:max_len - len(true_chunks)]
        if len(false_chunks) < max_len:
            false_chunks = false_chunks + false_chunks[:max_len - len(false_chunks)]

    # シャッフル用インデックスを準備
    indices = list(range(len(true_chunks) * 2))
    if shuffle_seed is None:
        shuffle_seed = secrets.token_bytes(16)

    # シャッフル
    rng = random.Random(int.from_bytes(shuffle_seed, 'big'))
    rng.shuffle(indices)

    # チャンク結合とマッピング生成
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

    metadata = {
        "shuffle_seed": shuffle_seed.hex(),
        "mapping": mapping,
        "original_true_length": len(true_chunks),
        "original_false_length": len(false_chunks)
    }

    return combined, metadata


def deinterleave_ciphertexts(mixed_chunks: List[int], metadata: Dict[str, Any],
                            key_type: str) -> List[int]:
    """混合された暗号文から特定タイプのチャンクを抽出"""
    mapping = metadata["mapping"]
    chunks = []

    for i, entry in enumerate(mapping):
        if entry["type"] == key_type:
            chunks.append((entry["index"], mixed_chunks[i]))

    # 元の順序に戻す
    chunks.sort(key=lambda x: x[0])
    return [chunk[1] for chunk in chunks]


def add_redundancy(ciphertexts: List[int], redundancy_factor: int = 2,
                  paillier: Optional[PaillierCrypto] = None) -> Tuple[List[int], Dict[str, Any]]:
    """暗号文に冗長性を追加"""
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
                # 準同型性を保った冗長チャンク
                redundant_ct = randomize_ciphertext(paillier, ct)
            else:
                # 単純な変形による冗長チャンク
                redundant_ct = ct ^ (1 << (j % 64))

            redundant_ciphertexts.append(redundant_ct)
            original_indices.append(i)  # 元の暗号文インデックスを記録

    metadata = {
        "redundancy_factor": redundancy_factor,
        "original_length": len(ciphertexts),
        "original_indices": original_indices
    }

    return redundant_ciphertexts, metadata


def remove_redundancy(redundant_ciphertexts: List[int], metadata: Dict[str, Any]) -> List[int]:
    """冗長性を除去"""
    if not redundant_ciphertexts:
        return []

    original_length = metadata.get("original_length", 0)
    original_indices = metadata.get("original_indices", [])

    if not original_indices or len(original_indices) != len(redundant_ciphertexts):
        # メタデータが不完全な場合のフォールバック
        redundancy_factor = metadata.get("redundancy_factor", 2)
        original_length = len(redundant_ciphertexts) // (redundancy_factor + 1)
        return redundant_ciphertexts[:original_length]

    # 元の各暗号文に対応する全ての冗長チャンクを取得
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


def apply_comprehensive_indistinguishability(true_ciphertexts: List[int],
                                           false_ciphertexts: List[int],
                                           paillier: PaillierCrypto,
                                           noise_intensity: float = 0.05,
                                           redundancy_factor: int = 1) -> Tuple[List[int], Dict[str, Any]]:
    """総合的な識別不能性を適用"""
    # 1. 暗号文ランダム化
    randomized_true = batch_randomize_ciphertexts(paillier, true_ciphertexts)
    randomized_false = batch_randomize_ciphertexts(paillier, false_ciphertexts)

    # 2. 統計的ノイズ追加
    noisy_true, true_noise_values = add_statistical_noise(randomized_true, noise_intensity, paillier)
    noisy_false, false_noise_values = add_statistical_noise(randomized_false, noise_intensity, paillier)

    # 3. 冗長性追加
    redundant_true, true_redundancy_metadata = add_redundancy(noisy_true, redundancy_factor, paillier)
    redundant_false, false_redundancy_metadata = add_redundancy(noisy_false, redundancy_factor, paillier)

    # 4. 交互配置とシャッフル
    interleaved_ciphertexts, interleave_metadata = interleave_ciphertexts(
        redundant_true, redundant_false)

    # メタデータ集約
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


def remove_comprehensive_indistinguishability(indistinguishable_ciphertexts: List[int],
                                            metadata: Dict[str, Any],
                                            key_type: str,
                                            paillier: PaillierCrypto) -> List[int]:
    """総合的な識別不能性を除去"""
    # 1. 交互配置とシャッフルを元に戻す
    interleave_metadata = metadata.get("interleave", {})
    deinterleaved = deinterleave_ciphertexts(indistinguishable_ciphertexts, interleave_metadata, key_type)

    # 2. 冗長性除去
    redundancy_metadata = metadata.get(f"{key_type}_redundancy", {})
    deredundant = remove_redundancy(deinterleaved, redundancy_metadata)

    # 3. 統計的ノイズ除去
    noise_values = metadata.get(f"{key_type}_noise_values", [])
    denoised = remove_statistical_noise(deredundant, noise_values, paillier)

    # 4. ランダム化は本質的に除去不要
    return denoised


def test_statistical_indistinguishability(true_ciphertexts: List[int],
                                         false_ciphertexts: List[int],
                                         paillier: PaillierCrypto,
                                         num_tests: int = 100) -> Dict[str, Any]:
    """暗号文の統計的識別不能性をテスト"""
    # 1. 適用前の暗号文の分析
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

    # 3. 適用後の暗号文の分析
    indist_bits_true = [ct.bit_length() for ct in noisy_true]
    indist_bits_false = [ct.bit_length() for ct in noisy_false]

    indist_mean_true = np.mean(indist_bits_true)
    indist_mean_false = np.mean(indist_bits_false)
    indist_threshold = (indist_mean_true + indist_mean_false) / 2

    # 4. テストデータ生成
    test_data_original = []
    test_data_indist = []
    test_labels = []

    for _ in range(num_tests):
        is_true = random.random() < 0.5
        test_labels.append(is_true)

        if is_true:
            idx = random.randrange(len(true_ciphertexts))
            test_data_original.append(true_ciphertexts[idx])
            test_data_indist.append(noisy_true[idx % len(noisy_true)])
        else:
            idx = random.randrange(len(false_ciphertexts))
            test_data_original.append(false_ciphertexts[idx])
            test_data_indist.append(noisy_false[idx % len(noisy_false)])

    # 5. 分類器テスト
    predictions_original = []
    predictions_indist = []

    for i in range(num_tests):
        # 元の暗号文での予測
        bit_length = test_data_original[i].bit_length()
        predictions_original.append(bit_length > original_threshold)

        # 識別不能性適用後の予測
        bit_length = test_data_indist[i].bit_length()
        predictions_indist.append(bit_length > indist_threshold)

    # 6. 精度計算
    accuracy_original = sum(1 for i in range(num_tests) if predictions_original[i] == test_labels[i]) / num_tests
    accuracy_indist = sum(1 for i in range(num_tests) if predictions_indist[i] == test_labels[i]) / num_tests

    # 7. 結果集約
    return {
        "original_mean_true": float(original_mean_true),
        "original_mean_false": float(original_mean_false),
        "indist_mean_true": float(indist_mean_true),
        "indist_mean_false": float(indist_mean_false),
        "accuracy_before": accuracy_original,
        "accuracy_after": accuracy_indist,
        "improvement": abs(0.5 - accuracy_original) - abs(0.5 - accuracy_indist),
        "ideal_accuracy": 0.5,
        "is_effective": abs(accuracy_indist - 0.5) < abs(accuracy_original - 0.5),
        "is_secure": abs(accuracy_indist - 0.5) < 0.1
    }


def main():
    """メイン関数"""
    print("====== 識別不能性機能テスト ======")

    # 暗号化パラメータ
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    public_key, private_key = paillier.generate_keys()

    # 1. 暗号文ランダム化テスト
    print("\n1. 暗号文ランダム化テスト")
    plaintext = 42
    ciphertext = paillier.encrypt(plaintext, public_key)
    randomized = randomize_ciphertext(paillier, ciphertext)

    print(f"元の暗号文: {ciphertext}")
    print(f"ランダム化後: {randomized}")
    print(f"同じ暗号文か: {ciphertext == randomized}")

    decrypted_original = paillier.decrypt(ciphertext, private_key)
    decrypted_randomized = paillier.decrypt(randomized, private_key)

    print(f"元の平文: {decrypted_original}")
    print(f"ランダム化後の平文: {decrypted_randomized}")
    print(f"同じ平文か: {decrypted_original == decrypted_randomized}")

    # 2. 統計的ノイズテスト
    print("\n2. 統計的ノイズテスト")
    plaintexts = [10, 20, 30, 40, 50]
    ciphertexts = [paillier.encrypt(pt, public_key) for pt in plaintexts]

    noisy_ciphertexts, noise_values = add_statistical_noise(ciphertexts, 0.1, paillier)

    print(f"ノイズ追加後の復号値: {[paillier.decrypt(ct, private_key) for ct in noisy_ciphertexts]}")
    print(f"追加されたノイズ値: {noise_values}")

    denoised = remove_statistical_noise(noisy_ciphertexts, noise_values, paillier)
    decrypted_denoised = [paillier.decrypt(ct, private_key) for ct in denoised]

    print(f"ノイズ除去後の復号値: {decrypted_denoised}")
    print(f"元の平文と一致するか: {plaintexts == decrypted_denoised}")

    # 3. 総合的な識別不能性テスト
    print("\n3. 総合的な識別不能性テスト")
    true_plaintexts = [i for i in range(10, 20)]
    false_plaintexts = [i for i in range(100, 110)]

    true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
    false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

    # 統計的識別不能性テスト
    indist_results = test_statistical_indistinguishability(
        true_ciphertexts, false_ciphertexts, paillier)

    print(f"元の分類精度: {indist_results['accuracy_before']:.4f}")
    print(f"識別不能性適用後の精度: {indist_results['accuracy_after']:.4f}")
    print(f"改善度: {indist_results['improvement']:.4f}")
    print(f"識別不能と判定されるか: {indist_results['is_secure']}")

    # 総合的識別不能性の適用
    indistinguishable_ciphertexts, metadata = apply_comprehensive_indistinguishability(
        true_ciphertexts, false_ciphertexts, paillier)

    print(f"識別不能性適用後の暗号文数: {len(indistinguishable_ciphertexts)}")

    # 真の鍵での復元
    recovered_true = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "true", paillier)

    # 偽の鍵での復元
    recovered_false = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "false", paillier)

    # 復号と検証
    decrypted_true = [paillier.decrypt(ct, private_key) for ct in recovered_true[:5]]
    decrypted_false = [paillier.decrypt(ct, private_key) for ct in recovered_false[:5]]

    print(f"元の真の平文（最初の5件）: {true_plaintexts[:5]}")
    print(f"復元された真の平文（最初の5件）: {decrypted_true}")
    print(f"元の偽の平文（最初の5件）: {false_plaintexts[:5]}")
    print(f"復元された偽の平文（最初の5件）: {decrypted_false}")

    # 成功判定
    true_success = all(a == b for a, b in zip(true_plaintexts[:5], decrypted_true))
    false_success = all(a == b for a, b in zip(false_plaintexts[:5], decrypted_false))

    print(f"真の復元成功: {true_success}")
    print(f"偽の復元成功: {false_success}")

    print("\n====== テスト完了 ======")


if __name__ == "__main__":
    main()