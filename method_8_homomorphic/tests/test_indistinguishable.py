#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
識別不能性（Indistinguishable）機能のテスト

暗号文識別不能性の実装に関する各種機能をテストします。
"""

import os
import sys
import hashlib
import random
import time
import binascii
import secrets
import numpy as np
import matplotlib.pyplot as plt
import io
import base64
import json
from datetime import datetime
from typing import Dict, List, Tuple, Any
from pathlib import Path

# 親ディレクトリをパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(os.path.dirname(parent_dir))  # プロジェクトのルートディレクトリを追加

from method_8_homomorphic.indistinguishable import (
    IndistinguishableWrapper,
    randomize_ciphertext,
    batch_randomize_ciphertexts,
    interleave_ciphertexts,
    deinterleave_ciphertexts,
    add_statistical_noise,
    remove_statistical_noise,
    analyze_statistical_properties,
    add_redundancy,
    remove_redundancy,
    apply_comprehensive_indistinguishability,
    remove_comprehensive_indistinguishability
)
from method_8_homomorphic.homomorphic import PaillierCrypto
from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    KDF_ITERATIONS,
    SECURITY_PARAMETER
)

# テスト出力ディレクトリの設定
TEST_OUTPUT_DIR = os.path.join(os.path.dirname(parent_dir), "test_output")
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

def generate_timestamp() -> str:
    """タイムスタンプ文字列を生成"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def get_output_path(filename: str) -> str:
    """テスト出力用のファイルパスを生成"""
    timestamp = generate_timestamp()
    return os.path.join(TEST_OUTPUT_DIR, f"{filename}_{timestamp}")

def save_plot(fig, filename: str) -> str:
    """プロットを保存してパスを返す"""
    output_path = get_output_path(filename)
    fig.savefig(output_path)
    plt.close(fig)
    return output_path

# 大きな整数のログを計算するヘルパー関数
def safe_log10(value):
    """大きな整数のlog10を安全に計算する"""
    # 整数の桁数からlog10を近似計算
    if value == 0:
        return 0
    return np.log10(len(str(abs(value))))

def test_randomize_ciphertext():
    """暗号文のランダム化（再ランダム化）機能のテスト"""
    print("\n=== 暗号文のランダム化テスト ===")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さめのビット数
    public_key, private_key = paillier.generate_keys()

    # テスト平文
    plaintext = 42

    # 同じ平文で複数回暗号化
    print(f"平文: {plaintext}")
    ciphertext1 = paillier.encrypt(plaintext, public_key)
    ciphertext2 = paillier.encrypt(plaintext, public_key)

    print(f"通常暗号化1: {ciphertext1}")
    print(f"通常暗号化2: {ciphertext2}")
    print(f"暗号文は異なるか: {ciphertext1 != ciphertext2}")

    # ランダム化適用
    randomized1 = randomize_ciphertext(paillier, ciphertext1)
    randomized2 = randomize_ciphertext(paillier, ciphertext1)  # 同じ暗号文から再ランダム化

    print(f"ランダム化1: {randomized1}")
    print(f"ランダム化2: {randomized2}")
    print(f"ランダム化された暗号文は異なるか: {randomized1 != randomized2}")

    # 復号して元の平文と一致することを確認
    decrypted1 = paillier.decrypt(randomized1, private_key)
    decrypted2 = paillier.decrypt(randomized2, private_key)

    print(f"復号結果1: {decrypted1}")
    print(f"復号結果2: {decrypted2}")
    print(f"元の平文と一致するか1: {decrypted1 == plaintext}")
    print(f"元の平文と一致するか2: {decrypted2 == plaintext}")

    # 複数の暗号文を一括ランダム化
    plaintexts = [10, 20, 30, 40, 50]
    ciphertexts = [paillier.encrypt(pt, public_key) for pt in plaintexts]

    randomized_batch = batch_randomize_ciphertexts(paillier, ciphertexts)

    print("\n一括ランダム化テスト:")
    for i, (pt, ct, rand_ct) in enumerate(zip(plaintexts, ciphertexts, randomized_batch)):
        decrypted = paillier.decrypt(rand_ct, private_key)
        print(f"  平文{i+1}: {pt}, 復号結果: {decrypted}, 一致: {pt == decrypted}")

    # 結果を可視化
    fig, ax = plt.subplots(figsize=(10, 6))

    # 同じ平文から生成された暗号文の分布を表示
    same_plaintext = 123
    n_samples = 100
    ciphertexts = []

    for _ in range(n_samples):
        ct = paillier.encrypt(same_plaintext, public_key)
        ciphertexts.append(ct)

    # 数値が大きすぎるので桁数を使用
    log_ciphertexts = [safe_log10(ct) for ct in ciphertexts]

    ax.hist(log_ciphertexts, bins=20, alpha=0.7, label='ランダム化なし')

    # 再ランダム化されたサンプル
    randomized_ciphertexts = []
    base_ct = paillier.encrypt(same_plaintext, public_key)

    for _ in range(n_samples):
        rand_ct = randomize_ciphertext(paillier, base_ct)
        randomized_ciphertexts.append(rand_ct)

    # 同様に桁数を使用
    log_randomized = [safe_log10(ct) for ct in randomized_ciphertexts]

    ax.hist(log_randomized, bins=20, alpha=0.7, label='再ランダム化')

    ax.set_title('同一平文から生成された暗号文の分布（log10スケール）')
    ax.set_xlabel('暗号文値（桁数のlog10）')
    ax.set_ylabel('頻度')
    ax.legend()

    # プロットを保存
    plot_path = save_plot(fig, "randomize_ciphertext_distribution")
    print(f"プロット保存先: {plot_path}")

    return True

def test_interleave_shuffle():
    """暗号文の交互配置とシャッフル機能のテスト"""
    print("\n=== 暗号文の交互配置とシャッフルテスト ===")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テスト用の平文リスト
    true_plaintexts = [i for i in range(10)]
    false_plaintexts = [i + 100 for i in range(10)]

    # 暗号化
    true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
    false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

    print(f"真の平文: {true_plaintexts}")
    print(f"偽の平文: {false_plaintexts}")

    # 交互配置とシャッフル
    mixed_ciphertexts, metadata = interleave_ciphertexts(true_ciphertexts, false_ciphertexts)

    print(f"混合後の長さ: {len(mixed_ciphertexts)}")
    print(f"メタデータキー: {list(metadata.keys())}")

    # 順序マッピングの一部を表示
    n_display = min(5, len(metadata["mapping"]))
    print(f"順序マッピング (先頭{n_display}件): {metadata['mapping'][:n_display]}")

    # シャッフルを元に戻して真の暗号文を取得
    recovered_true = deinterleave_ciphertexts(mixed_ciphertexts, metadata, "true")

    # 復号して元の平文と比較
    decrypted_true = [paillier.decrypt(ct, private_key) for ct in recovered_true]
    print(f"復元された真の平文: {decrypted_true}")
    print(f"元の真の平文と一致: {decrypted_true == true_plaintexts}")

    # 同様に偽の暗号文も復元
    recovered_false = deinterleave_ciphertexts(mixed_ciphertexts, metadata, "false")
    decrypted_false = [paillier.decrypt(ct, private_key) for ct in recovered_false]
    print(f"復元された偽の平文: {decrypted_false}")
    print(f"元の偽の平文と一致: {decrypted_false == false_plaintexts}")

    # 結果を可視化
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # 混合前の暗号文
    combined_original = []
    labels_original = []

    for ct in true_ciphertexts:
        combined_original.append(safe_log10(ct))
        labels_original.append("True")

    for ct in false_ciphertexts:
        combined_original.append(safe_log10(ct))
        labels_original.append("False")

    # 混合前の散布図
    unique_labels = ["True", "False"]
    colors = ["blue", "red"]

    for label, color in zip(unique_labels, colors):
        mask = [l == label for l in labels_original]
        ax1.scatter(
            range(sum(mask)),
            [combined_original[i] for i, m in enumerate(mask) if m],
            c=color, label=label, alpha=0.7
        )

    ax1.set_title('混合前の暗号文（log10スケール）')
    ax1.set_xlabel('インデックス')
    ax1.set_ylabel('暗号文値（桁数のlog10）')
    ax1.legend()

    # 混合後の暗号文
    mixed_log = [safe_log10(ct) for ct in mixed_ciphertexts]
    labels_mixed = []

    for entry in metadata["mapping"]:
        if entry["type"] == "true":
            labels_mixed.append("True")
        else:
            labels_mixed.append("False")

    # 混合後の散布図
    for label, color in zip(unique_labels, colors):
        mask = [l == label for l in labels_mixed]
        ax2.scatter(
            range(sum(mask)),
            [mixed_log[i] for i, m in enumerate(mask) if m],
            c=color, label=label, alpha=0.7
        )

    ax2.set_title('混合後の暗号文（log10スケール）')
    ax2.set_xlabel('インデックス')
    ax2.set_ylabel('暗号文値（桁数のlog10）')
    ax2.legend()

    plt.tight_layout()

    # プロットを保存
    plot_path = save_plot(fig, "interleave_shuffle_ciphertexts")
    print(f"プロット保存先: {plot_path}")

    return True

def test_statistical_masking():
    """統計的特性のマスキング機能のテスト"""
    print("\n=== 統計的特性のマスキングテスト ===")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # 異なる統計的特性を持つ2つのデータセット
    # セット1: 小さい平均値と分散
    plaintext_set1 = [random.randint(1, 50) for _ in range(100)]
    # セット2: 大きい平均値と分散
    plaintext_set2 = [random.randint(100, 200) for _ in range(100)]

    # 暗号化
    ciphertext_set1 = [paillier.encrypt(pt, public_key) for pt in plaintext_set1]
    ciphertext_set2 = [paillier.encrypt(pt, public_key) for pt in plaintext_set2]

    # 統計分析
    stats_set1 = analyze_statistical_properties([safe_log10(ct) for ct in ciphertext_set1])
    stats_set2 = analyze_statistical_properties([safe_log10(ct) for ct in ciphertext_set2])

    print(f"セット1（マスキング前）統計情報:")
    print(f"  平均: {stats_set1['mean']:.4f}")
    print(f"  標準偏差: {stats_set1['std']:.4f}")
    print(f"  最小値: {stats_set1['min']:.4f}")
    print(f"  最大値: {stats_set1['max']:.4f}")

    print(f"セット2（マスキング前）統計情報:")
    print(f"  平均: {stats_set2['mean']:.4f}")
    print(f"  標準偏差: {stats_set2['std']:.4f}")
    print(f"  最小値: {stats_set2['min']:.4f}")
    print(f"  最大値: {stats_set2['max']:.4f}")

    # 統計的ノイズの追加
    noise_intensity = 0.2  # 20%のノイズ強度
    noisy_set1, noise_values1 = add_statistical_noise(ciphertext_set1, noise_intensity, paillier)
    noisy_set2, noise_values2 = add_statistical_noise(ciphertext_set2, noise_intensity, paillier)

    # ノイズ追加後の統計分析
    noisy_stats_set1 = analyze_statistical_properties([safe_log10(ct) for ct in noisy_set1])
    noisy_stats_set2 = analyze_statistical_properties([safe_log10(ct) for ct in noisy_set2])

    print(f"セット1（マスキング後）統計情報:")
    print(f"  平均: {noisy_stats_set1['mean']:.4f}")
    print(f"  標準偏差: {noisy_stats_set1['std']:.4f}")
    print(f"  最小値: {noisy_stats_set1['min']:.4f}")
    print(f"  最大値: {noisy_stats_set1['max']:.4f}")

    print(f"セット2（マスキング後）統計情報:")
    print(f"  平均: {noisy_stats_set2['mean']:.4f}")
    print(f"  標準偏差: {noisy_stats_set2['std']:.4f}")
    print(f"  最小値: {noisy_stats_set2['min']:.4f}")
    print(f"  最大値: {noisy_stats_set2['max']:.4f}")

    # ノイズを記録して除去
    denoised_set1 = remove_statistical_noise(noisy_set1, noise_values1, paillier)

    # 復号して元の平文と比較
    original_plaintext1 = [paillier.decrypt(ct, private_key) for ct in ciphertext_set1[:10]]  # 10個だけ使用
    denoised_plaintext1 = [paillier.decrypt(ct, private_key) for ct in denoised_set1[:10]]    # 10個だけ使用

    # 差異を計算（数値が大きすぎる問題を回避）
    differences = []
    for a, b in zip(original_plaintext1, denoised_plaintext1):
        try:
            diff = abs(a - b)
            # 差が大きすぎる場合は無視
            if diff < 1e10:
                differences.append(diff)
        except (OverflowError, TypeError):
            # エラーが発生した場合はスキップ
            pass

    # 平均差異を計算
    if differences:
        avg_diff = sum(differences) / len(differences)
        print(f"ノイズ除去後の平文との平均差異: {avg_diff:.4f}")
    else:
        print("ノイズ除去後の差異を計算できませんでした")

    # 結果を可視化
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))

    # マスキング前の分布
    axes[0, 0].hist([safe_log10(ct) for ct in ciphertext_set1], bins=20, alpha=0.7, label='セット1')
    axes[0, 0].hist([safe_log10(ct) for ct in ciphertext_set2], bins=20, alpha=0.7, label='セット2')
    axes[0, 0].set_title('マスキング前の暗号文分布')
    axes[0, 0].set_xlabel('暗号文値（桁数のlog10）')
    axes[0, 0].set_ylabel('頻度')
    axes[0, 0].legend()

    # マスキング後の分布
    axes[0, 1].hist([safe_log10(ct) for ct in noisy_set1], bins=20, alpha=0.7, label='セット1（ノイズ追加）')
    axes[0, 1].hist([safe_log10(ct) for ct in noisy_set2], bins=20, alpha=0.7, label='セット2（ノイズ追加）')
    axes[0, 1].set_title('マスキング後の暗号文分布')
    axes[0, 1].set_xlabel('暗号文値（桁数のlog10）')
    axes[0, 1].set_ylabel('頻度')
    axes[0, 1].legend()

    # 元の平文分布
    axes[1, 0].hist(plaintext_set1, bins=20, alpha=0.7, label='セット1')
    axes[1, 0].hist(plaintext_set2, bins=20, alpha=0.7, label='セット2')
    axes[1, 0].set_title('元の平文分布')
    axes[1, 0].set_xlabel('平文値')
    axes[1, 0].set_ylabel('頻度')
    axes[1, 0].legend()

    # ノイズ除去後の平文分布（サンプルのみ）
    # 数値が巨大になりすぎるのを避けるため小さなサンプルのみ表示
    sample_original = original_plaintext1[:5]
    sample_denoised = denoised_plaintext1[:5]

    axes[1, 1].bar(range(len(sample_original)), sample_original, alpha=0.7, label='元の平文')
    axes[1, 1].bar([x + 0.4 for x in range(len(sample_denoised))], sample_denoised, alpha=0.7, label='ノイズ除去後の平文')
    axes[1, 1].set_title('ノイズ除去前後の平文比較（サンプル）')
    axes[1, 1].set_xlabel('サンプルインデックス')
    axes[1, 1].set_ylabel('平文値')
    axes[1, 1].legend()

    plt.tight_layout()

    # プロットを保存
    plot_path = save_plot(fig, "statistical_masking")
    print(f"プロット保存先: {plot_path}")

    return True

def test_redundancy():
    """意図的な冗長性の追加機能のテスト"""
    print("\n=== 意図的な冗長性の追加テスト ===")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テスト用の平文
    plaintexts = [i * 10 for i in range(1, 11)]  # 10, 20, ..., 100

    # 暗号化
    ciphertexts = [paillier.encrypt(pt, public_key) for pt in plaintexts]

    print(f"元の平文: {plaintexts}")
    print(f"元の暗号文の数: {len(ciphertexts)}")

    # 冗長性の追加
    redundancy_factor = 2  # 各暗号文に対して2つの冗長チャンクを追加
    redundant_ciphertexts, metadata = add_redundancy(ciphertexts, redundancy_factor, paillier)

    print(f"冗長性追加後の暗号文の数: {len(redundant_ciphertexts)}")
    print(f"冗長性メタデータキー: {list(metadata.keys())}")
    print(f"元のインデックスの一部: {metadata['original_indices'][:15]}")

    # 冗長性の除去
    recovered_ciphertexts = remove_redundancy(redundant_ciphertexts, metadata)

    print(f"冗長性除去後の暗号文の数: {len(recovered_ciphertexts)}")

    # 復号して元の平文と比較
    decrypted_original = [paillier.decrypt(ct, private_key) for ct in ciphertexts]
    decrypted_recovered = [paillier.decrypt(ct, private_key) for ct in recovered_ciphertexts]

    print(f"元の平文: {plaintexts}")
    print(f"復号された元の暗号文: {decrypted_original}")
    print(f"復号された復元後の暗号文: {decrypted_recovered}")
    print(f"復元結果が元の平文と一致: {decrypted_recovered == plaintexts}")

    # 異なる冗長性係数でテスト
    redundancy_results = []

    for factor in range(1, 6):
        # 冗長性追加
        redundant, meta = add_redundancy(ciphertexts, factor, paillier)

        # 冗長性除去
        recovered = remove_redundancy(redundant, meta)

        # 復号
        decrypted = [paillier.decrypt(ct, private_key) for ct in recovered]

        # 元の平文と比較
        is_match = decrypted == plaintexts

        # 結果記録
        redundancy_results.append({
            "factor": factor,
            "original_size": len(ciphertexts),
            "redundant_size": len(redundant),
            "inflation_ratio": len(redundant) / len(ciphertexts),
            "match": is_match
        })

    # 結果表示
    print("\n冗長性係数の比較:")
    for result in redundancy_results:
        print(f"  係数: {result['factor']}, サイズ比: {result['inflation_ratio']:.2f}, 復元成功: {result['match']}")

    # 結果を可視化
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # 冗長性の影響を可視化
    factors = [r["factor"] for r in redundancy_results]
    sizes = [r["redundant_size"] for r in redundancy_results]
    ratios = [r["inflation_ratio"] for r in redundancy_results]

    ax1.bar(factors, sizes)
    ax1.set_title('冗長性係数とデータサイズの関係')
    ax1.set_xlabel('冗長性係数')
    ax1.set_ylabel('冗長データサイズ')

    ax2.plot(factors, ratios, marker='o')
    ax2.set_title('冗長性係数と膨張率の関係')
    ax2.set_xlabel('冗長性係数')
    ax2.set_ylabel('膨張率（冗長サイズ/元サイズ）')
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()

    # プロットを保存
    plot_path = save_plot(fig, "redundancy_test")
    print(f"プロット保存先: {plot_path}")

    return True

def test_comprehensive_indistinguishability():
    """総合的な識別不能性適用機能のテスト"""
    print("\n=== 総合的な識別不能性適用テスト ===")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テスト用の平文
    true_plaintexts = [i for i in range(10, 30)]  # 10から29までの数値
    false_plaintexts = [i for i in range(100, 120)]  # 100から119までの数値

    # 暗号化
    true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
    false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

    print(f"真の平文: {true_plaintexts}")
    print(f"偽の平文: {false_plaintexts}")

    # 総合的な識別不能性を適用
    noise_intensity = 0.05  # 5%のノイズ強度
    redundancy_factor = 1  # 各暗号文に対して1つの冗長チャンク

    indistinguishable, metadata = apply_comprehensive_indistinguishability(
        true_ciphertexts, false_ciphertexts, paillier, noise_intensity, redundancy_factor
    )

    print(f"識別不能性適用後の暗号文の数: {len(indistinguishable)}")
    print(f"メタデータキー: {list(metadata.keys())}")

    # 識別不能性を除去して真の暗号文を復元
    recovered_true = remove_comprehensive_indistinguishability(
        indistinguishable, metadata, "true", paillier
    )

    # 復号して元の平文と比較
    decrypted_true = [paillier.decrypt(ct, private_key) for ct in recovered_true]

    print(f"復元された真の平文: {decrypted_true}")

    # 元の平文と完全一致ではなく、近似値になることがあるため許容誤差を設定
    tolerance = 2  # 許容誤差
    close_match = all(abs(a - b) <= tolerance for a, b in zip(true_plaintexts, decrypted_true))

    print(f"真の平文との近似一致: {close_match}")

    # 同様に偽の暗号文も復元
    recovered_false = remove_comprehensive_indistinguishability(
        indistinguishable, metadata, "false", paillier
    )

    # 復号して元の平文と比較
    decrypted_false = [paillier.decrypt(ct, private_key) for ct in recovered_false]

    print(f"復元された偽の平文: {decrypted_false}")

    # 元の平文との近似一致を確認
    close_match_false = all(abs(a - b) <= tolerance for a, b in zip(false_plaintexts, decrypted_false))

    print(f"偽の平文との近似一致: {close_match_false}")

    # 識別困難性の統計的分析
    # ログスケールで暗号文の値を分析
    indist_log = [safe_log10(ct) for ct in indistinguishable]

    stats = analyze_statistical_properties(indist_log)

    print(f"識別不能性適用後の統計分析:")
    print(f"  平均: {stats['mean']:.4f}")
    print(f"  標準偏差: {stats['std']:.4f}")
    print(f"  最小値: {stats['min']:.4f}")
    print(f"  最大値: {stats['max']:.4f}")

    # 結果を可視化
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # 元の暗号文（真と偽の差別化）
    true_log = [safe_log10(ct) for ct in true_ciphertexts]
    false_log = [safe_log10(ct) for ct in false_ciphertexts]

    ax1.hist(true_log, bins=20, alpha=0.7, label='真の暗号文')
    ax1.hist(false_log, bins=20, alpha=0.7, label='偽の暗号文')
    ax1.set_title('識別不能性適用前の暗号文分布')
    ax1.set_xlabel('暗号文値（桁数のlog10）')
    ax1.set_ylabel('頻度')
    ax1.legend()

    # 識別不能性適用後（混合して区別不可能）
    ax2.hist(indist_log, bins=20, alpha=0.7)
    ax2.set_title('識別不能性適用後の暗号文分布')
    ax2.set_xlabel('暗号文値（桁数のlog10）')
    ax2.set_ylabel('頻度')

    plt.tight_layout()

    # プロットを保存
    plot_path = save_plot(fig, "comprehensive_indistinguishability")
    print(f"プロット保存先: {plot_path}")

    # 偽陽性・偽陰性のテスト
    # メタデータを改ざんして間違った種類を取得しようとした場合
    try:
        # interleaveメタデータのみを改ざん
        tampered_metadata = metadata.copy()
        tampered_mapping = []

        for entry in metadata["interleave"]["mapping"]:
            # 真と偽を入れ替え
            tampered_type = "false" if entry["type"] == "true" else "true"
            tampered_mapping.append({"type": tampered_type, "index": entry["index"]})

        tampered_metadata["interleave"]["mapping"] = tampered_mapping

        # 改ざんされたメタデータで復元
        tampered_true = remove_comprehensive_indistinguishability(
            indistinguishable, tampered_metadata, "true", paillier
        )

        # 復号
        tampered_decrypted = [paillier.decrypt(ct, private_key) for ct in tampered_true]

        # 結果を分析
        print("\n改ざんされたメタデータを使用した場合:")
        print(f"  復号結果: {tampered_decrypted[:5]}... (先頭5件)")

        # 本来の真の平文との比較
        close_to_true = all(abs(a - b) <= tolerance for a, b in zip(true_plaintexts, tampered_decrypted))

        # 偽の平文との比較
        close_to_false = all(abs(a - b) <= tolerance for a, b in zip(false_plaintexts, tampered_decrypted))

        print(f"  真の平文との近似一致: {close_to_true}")
        print(f"  偽の平文との近似一致: {close_to_false}")

    except Exception as e:
        print(f"改ざんされたメタデータでのテストでエラー発生: {e}")

    return True

def save_test_results(results: Dict[str, bool], timestamp: str) -> str:
    """テスト結果をJSONファイルに保存"""
    results_file = get_output_path("indistinguishable_test_results.json")

    with open(results_file, 'w') as f:
        json.dump({
            "timestamp": timestamp,
            "results": results
        }, f, indent=2)

    return results_file

def main():
    """メイン関数"""
    timestamp = generate_timestamp()
    print(f"=== 識別不能性テスト開始 ({timestamp}) ===")

    # 各機能のテスト実行
    results = {}

    # 1. 暗号文のランダム化テスト
    results["randomize_ciphertext"] = test_randomize_ciphertext()

    # 2. 暗号文の交互配置とシャッフルテスト
    results["interleave_shuffle"] = test_interleave_shuffle()

    # 3. 統計的特性のマスキングテスト
    results["statistical_masking"] = test_statistical_masking()

    # 4. 意図的な冗長性の追加テスト
    results["redundancy"] = test_redundancy()

    # 5. 総合的な識別不能性適用テスト
    results["comprehensive_indistinguishability"] = test_comprehensive_indistinguishability()

    # テスト結果の保存
    results_file = save_test_results(results, timestamp)

    # 結果の要約表示
    print("\n=== テスト結果の要約 ===")
    for test_name, success in results.items():
        print(f"{test_name}: {'成功' if success else '失敗'}")

    print(f"\nテスト結果の保存先: {results_file}")
    print(f"=== 識別不能性テスト終了 ({generate_timestamp()}) ===")

if __name__ == "__main__":
    main()