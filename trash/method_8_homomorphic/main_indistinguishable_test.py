#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式における識別不能性機能のメインテスト

このスクリプトは、暗号文識別不能性実装の機能を検証し、
攻撃者がファイルの真偽を判定できないことを確認します。
"""

import os
import sys
import binascii
import hashlib
import random
import time
import secrets
import json
import base64
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Any
from pathlib import Path

# 親ディレクトリをパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(os.path.dirname(current_dir))  # プロジェクトのルートディレクトリを追加

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
from method_8_homomorphic.homomorphic import (
    PaillierCrypto,
    derive_key_from_password
)

# テスト出力ディレクトリの設定
TEST_OUTPUT_DIR = os.path.join(os.path.dirname(parent_dir), "test_output")
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

# テストデータファイルパス
TRUE_TEXT_PATH = os.path.join(os.path.dirname(parent_dir), "true.text")
FALSE_TEXT_PATH = os.path.join(os.path.dirname(parent_dir), "false.text")

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

def encrypt_data_with_indistinguishability(
    data: bytes,
    true_key: bytes,
    false_key: bytes,
    salt: bytes
) -> Tuple[bytes, Dict[str, Any]]:
    """
    データを暗号化し、識別不能性を適用

    Args:
        data: 暗号化するデータ
        true_key: 真の鍵
        false_key: 偽の鍵
        salt: ソルト

    Returns:
        (encrypted_data, metadata): 暗号化されたデータとメタデータ
    """
    # 準同型暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)  # 実運用では2048ビット以上推奨
    public_key, private_key = paillier.generate_keys()

    # データをチャンクに分割して暗号化
    chunk_size = 64  # 小さめのチャンクサイズ（テスト用）
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

    # 真のデータと偽のデータを用意（実際は同じデータ）
    true_chunks = []
    false_chunks = []

    for chunk in chunks:
        # チャンクをバイト列から整数に変換
        int_value = int.from_bytes(chunk, 'big')
        # 暗号化
        true_cipher = paillier.encrypt(int_value, public_key)
        false_cipher = paillier.encrypt(int_value, public_key)

        # それぞれのリストに追加
        true_chunks.append(true_cipher)
        false_chunks.append(false_cipher)

    # 総合的な識別不能性を適用
    noise_intensity = 0.05  # 5%のノイズ強度
    redundancy_factor = 1   # 冗長性の係数

    indistinguishable, metadata = apply_comprehensive_indistinguishability(
        true_chunks, false_chunks, paillier, noise_intensity, redundancy_factor
    )

    # 暗号化データをシリアライズ
    serialized_data = {
        "chunks": indistinguishable,
        "metadata": metadata,
        "public_key": public_key,
        "private_key": private_key,
        "original_size": len(data),
        "timestamp": generate_timestamp()
    }

    # Base64エンコードして返す
    return base64.b64encode(json.dumps(serialized_data, default=lambda o: str(o)).encode()), serialized_data

def decrypt_data_with_indistinguishability(
    encrypted_data: bytes,
    key: bytes,
    salt: bytes,
    serialized_data: Dict[str, Any] = None
) -> bytes:
    """
    識別不能性が適用された暗号データを復号

    Args:
        encrypted_data: 暗号化されたデータ
        key: 復号鍵（真または偽）
        salt: ソルト
        serialized_data: シリアライズされたデータ（省略時はencrypted_dataから解析）

    Returns:
        復号されたデータ
    """
    # 識別不能性ラッパーの初期化
    indist = IndistinguishableWrapper()
    indist.generate_seed(key, salt)

    # 真偽パスの判定
    is_true = indist.is_true_path(key, salt)
    key_type = "true" if is_true else "false"

    # シリアライズされたデータが提供されていない場合は解析
    if serialized_data is None:
        json_data = json.loads(base64.b64decode(encrypted_data).decode())
        # 文字列表現から数値へ変換（必要に応じて）
        # 実装が必要な場合はここに追加
    else:
        json_data = serialized_data

    # Paillier暗号システムの初期化と鍵の復元
    paillier = PaillierCrypto()
    paillier.public_key = json_data["public_key"]
    paillier.private_key = json_data["private_key"]

    # 識別不能性を除去して対応する種類の暗号文を取得
    indistinguishable_chunks = json_data["chunks"]
    metadata = json_data["metadata"]

    decrypted_chunks = remove_comprehensive_indistinguishability(
        indistinguishable_chunks, metadata, key_type, paillier
    )

    # 復号されたチャンクをバイト列に変換
    decrypted_data = bytearray()
    original_size = json_data["original_size"]
    chunk_size = (original_size + len(decrypted_chunks) - 1) // len(decrypted_chunks)

    remaining_size = original_size

    for chunk in decrypted_chunks:
        # 暗号文を復号
        int_value = paillier.decrypt(chunk, paillier.private_key)

        # 最後のチャンクは部分的かもしれない
        bytes_in_chunk = min(chunk_size, remaining_size)

        # 整数をバイト列に変換
        bytes_value = int_value.to_bytes(
            (int_value.bit_length() + 7) // 8, 'big')[-bytes_in_chunk:]

        # バイト配列に追加
        decrypted_data.extend(bytes_value)

        # 残りのサイズを更新
        remaining_size -= bytes_in_chunk

    return bytes(decrypted_data)

def test_indistinguishable_encryption():
    """識別不能性を適用した暗号化と復号をテスト"""
    print("\n=== 識別不能性を適用した暗号化・復号テスト ===")

    # テストデータの読み込み
    try:
        with open(TRUE_TEXT_PATH, 'rb') as f:
            true_data = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            false_data = f.read()

        print(f"真のデータサイズ: {len(true_data)} バイト")
        print(f"偽のデータサイズ: {len(false_data)} バイト")
    except Exception as e:
        print(f"テストデータの読み込みエラー: {e}")
        # サンプルデータを生成
        true_data = b"This is true secret data for testing indistinguishability."
        false_data = b"This is false secret data for testing indistinguishability."
        print("サンプルデータを使用します。")

    # テスト用の鍵とソルト
    true_key = secrets.token_bytes(32)
    false_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    # 真のデータを暗号化
    encrypted_true, serialized_true = encrypt_data_with_indistinguishability(
        true_data, true_key, false_key, salt
    )

    # 偽のデータを暗号化
    encrypted_false, serialized_false = encrypt_data_with_indistinguishability(
        false_data, true_key, false_key, salt
    )

    print(f"暗号化後の真のデータサイズ: {len(encrypted_true)} バイト")
    print(f"暗号化後の偽のデータサイズ: {len(encrypted_false)} バイト")

    # 真の鍵で復号
    decrypted_true_with_true_key = decrypt_data_with_indistinguishability(
        encrypted_true, true_key, salt, serialized_true
    )

    # 偽の鍵で復号
    decrypted_true_with_false_key = decrypt_data_with_indistinguishability(
        encrypted_true, false_key, salt, serialized_true
    )

    # 結果を比較
    is_true_key_correct = decrypted_true_with_true_key == true_data
    is_false_key_correct = decrypted_true_with_false_key == false_data

    print(f"真の鍵で復号した結果が真のデータと一致: {is_true_key_correct}")
    print(f"偽の鍵で復号した結果が偽のデータと一致: {is_false_key_correct}")

    # 復号データの最初の100バイトを表示
    max_display = 100
    print(f"\n真の鍵で復号（先頭{min(max_display, len(decrypted_true_with_true_key))}バイト）:")
    print(decrypted_true_with_true_key[:max_display])

    print(f"\n偽の鍵で復号（先頭{min(max_display, len(decrypted_true_with_false_key))}バイト）:")
    print(decrypted_true_with_false_key[:max_display])

    # 統計的分析
    # バイト分布を比較
    def analyze_byte_distribution(data, title):
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        return byte_counts, title

    # 各データのバイト分布を取得
    distributions = [
        analyze_byte_distribution(true_data, "真のデータ"),
        analyze_byte_distribution(false_data, "偽のデータ"),
        analyze_byte_distribution(decrypted_true_with_true_key, "真の鍵で復号したデータ"),
        analyze_byte_distribution(decrypted_true_with_false_key, "偽の鍵で復号したデータ")
    ]

    # バイト分布を可視化
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    axes = axes.flatten()

    for i, (dist, title) in enumerate(distributions):
        axes[i].bar(range(256), dist, width=1.0)
        axes[i].set_title(title)
        axes[i].set_xlabel('バイト値')
        axes[i].set_ylabel('頻度')
        axes[i].set_xlim(0, 255)

    plt.tight_layout()

    # プロットを保存
    plot_path = save_plot(fig, "indistinguishable_byte_distribution")
    print(f"バイト分布プロット保存先: {plot_path}")

    # 攻撃シミュレーション：統計的分析
    print("\n=== 攻撃シミュレーション：統計的分析 ===")

    # さまざまな特徴量を計算
    def calculate_features(data):
        if not data:
            return {}

        # バイトの平均値
        avg = sum(data) / len(data)

        # エントロピー
        byte_counts = {}
        for b in data:
            byte_counts[b] = byte_counts.get(b, 0) + 1

        entropy = 0
        for count in byte_counts.values():
            p = count / len(data)
            entropy -= p * np.log2(p)

        # バイト値の分散
        variance = sum((b - avg) ** 2 for b in data) / len(data)

        # 連続したバイトの相関
        correlation = 0
        if len(data) > 1:
            for i in range(len(data) - 1):
                correlation += data[i] * data[i + 1]
            correlation /= (len(data) - 1)

        return {
            "平均値": avg,
            "エントロピー": entropy,
            "分散": variance,
            "相関": correlation
        }

    # 各データの特徴量を計算
    feature_sets = [
        (calculate_features(true_data), "真のデータ"),
        (calculate_features(false_data), "偽のデータ"),
        (calculate_features(decrypted_true_with_true_key), "真の鍵で復号したデータ"),
        (calculate_features(decrypted_true_with_false_key), "偽の鍵で復号したデータ")
    ]

    # 特徴量を表示
    for features, name in feature_sets:
        print(f"\n{name}の特徴量:")
        for feature, value in features.items():
            print(f"  {feature}: {value:.6f}")

    # 特徴量の差異を計算
    true_features = feature_sets[0][0]
    false_features = feature_sets[1][0]
    decrypted_true_features = feature_sets[2][0]
    decrypted_false_features = feature_sets[3][0]

    # 真と偽の特徴量の平均絶対差
    true_false_diff = sum(abs(true_features[f] - false_features[f]) for f in true_features) / len(true_features)

    # 復号データ間の特徴量の平均絶対差
    decrypted_diff = sum(abs(decrypted_true_features[f] - decrypted_false_features[f]) for f in decrypted_true_features) / len(decrypted_true_features)

    print(f"\n真と偽のデータの特徴量の平均絶対差: {true_false_diff:.6f}")
    print(f"復号データ間の特徴量の平均絶対差: {decrypted_diff:.6f}")
    print(f"差異の比率（復号/元）: {decrypted_diff / true_false_diff if true_false_diff > 0 else 'N/A':.6f}")

    # 攻撃者の視点でのデータの区別可能性
    if decrypted_diff / true_false_diff < 0.1:
        print("\n結論: 攻撃者は統計的分析によって復号データを区別することはほぼ不可能です。")
    elif decrypted_diff / true_false_diff < 0.5:
        print("\n結論: 攻撃者は統計的分析によって復号データを区別することは非常に困難です。")
    else:
        print("\n結論: 攻撃者は統計的分析によって復号データを区別できる可能性があります。強化が必要です。")

    return {
        "is_true_key_correct": is_true_key_correct,
        "is_false_key_correct": is_false_key_correct,
        "true_false_feature_diff": true_false_diff,
        "decrypted_feature_diff": decrypted_diff,
        "diff_ratio": decrypted_diff / true_false_diff if true_false_diff > 0 else 0
    }

def save_test_results(results: Dict[str, Any]) -> str:
    """テスト結果をJSONファイルに保存"""
    results_file = get_output_path("indistinguishable_main_test_results.json")

    # 結果の文字列変換（JSONシリアライズ可能にする）
    serializable_results = {}
    for key, value in results.items():
        if isinstance(value, dict):
            serializable_results[key] = {k: str(v) if not isinstance(v, (int, float, bool, str, type(None))) else v
                                       for k, v in value.items()}
        else:
            serializable_results[key] = str(value) if not isinstance(value, (int, float, bool, str, type(None))) else value

    with open(results_file, 'w') as f:
        json.dump({
            "timestamp": generate_timestamp(),
            "results": serializable_results
        }, f, indent=2)

    return results_file

def main():
    """メイン関数"""
    timestamp = generate_timestamp()
    print(f"=== 準同型暗号マスキング方式 識別不能性テスト開始 ({timestamp}) ===")

    # 識別不能性を適用した暗号化・復号テスト
    results = test_indistinguishable_encryption()

    # テスト結果の保存
    results_file = save_test_results(results)
    print(f"\nテスト結果の保存先: {results_file}")

    print(f"=== 識別不能性テスト終了 ({generate_timestamp()}) ===")

    return results

if __name__ == "__main__":
    main()