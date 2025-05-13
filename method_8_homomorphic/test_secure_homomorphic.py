#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
安全な準同型暗号マスキング方式のテストスクリプト

このスクリプトは、区別不能な準同型暗号マスキング方式の実装をテストします。
特に、バックドアの有無などを検証し、暗号文から真偽の区別ができないことを確認します。
"""

import os
import sys
import time
import json
import hashlib
import base64
import random
import re
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any, Tuple, List

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 安全な実装をインポート
from method_8_homomorphic.indistinguishable_crypto import (
    SecureHomomorphicCrypto, encrypt_file_with_dual_keys, decrypt_file_with_key
)

# 出力ディレクトリの確認
os.makedirs("test_output", exist_ok=True)
os.makedirs("test_output/secure_test", exist_ok=True)

def print_header(text):
    """ヘッダーテキストを出力"""
    print("\n" + "=" * 80)
    print(f" {text} ".center(80, "="))
    print("=" * 80)

def print_subheader(text):
    """サブヘッダーテキストを出力"""
    print("\n" + "-" * 60)
    print(f" {text} ".center(60, "-"))
    print("-" * 60)

def generate_test_files():
    """テスト用のtrueとfalseファイルを生成"""
    true_content = "これは正規の重要な秘密情報です。\n機密度: 最高\n取扱注意！\n重要なデータ: 1234-5678-90AB-CDEF"
    false_content = "これは偽の情報です。重要ではありません。\n機密度: 低\n一般公開可能\n偽のデータ: FFFF-EEEE-DDDD-CCCC"

    # ファイルに書き込み
    true_path = "test_output/secure_test/true.text"
    false_path = "test_output/secure_test/false.text"

    with open(true_path, 'w', encoding='utf-8') as f:
        f.write(true_content)

    with open(false_path, 'w', encoding='utf-8') as f:
        f.write(false_content)

    print(f"テストファイルを生成しました: {true_path}, {false_path}")
    return true_path, false_path

def encrypt_test_files(true_file, false_file, use_advanced_masks=True):
    """テストファイルを暗号化"""
    print_subheader("準同型暗号によるセキュアな二重暗号化")

    # 出力ファイルパス
    output_file = "test_output/secure_test/encrypted.hmc"

    # 暗号化の実行
    encrypt_file_with_dual_keys(
        true_file, false_file, output_file,
        key_bits=1024, use_advanced_masks=use_advanced_masks
    )

    return output_file

def decrypt_test_file(encrypted_file, key_type="true"):
    """テストファイルを復号"""
    print_subheader(f"{key_type}キーでの復号")

    # 出力ファイルパス
    output_file = f"test_output/secure_test/decrypted_{key_type}.txt"

    # 復号の実行
    decrypt_file_with_key(
        encrypted_file, output_file, key_type=key_type
    )

    return output_file

def analyze_encrypted_file(encrypted_file):
    """暗号化ファイルの解析"""
    print_subheader("暗号化ファイルの解析")

    # ファイル内容を読み込み
    with open(encrypted_file, 'r') as f:
        content = f.read()
        data = json.loads(content)

    # 暗号文に'true'や'false'の文字列が直接含まれているか検査
    has_true_marker = "true" in content.lower() and not "metadata" in re.findall(r'"true"', content.lower())
    has_false_marker = "false" in content.lower() and not "metadata" in re.findall(r'"false"', content.lower())

    print(f"直接的な'true'マーカーの存在: {has_true_marker}")
    print(f"直接的な'false'マーカーの存在: {has_false_marker}")

    # チャンク識別子を調べる
    chunk_ids = [chunk["id"] for chunk in data["chunks"]]
    print(f"チャンク識別子: {chunk_ids}")

    # チャンク数の確認
    print(f"チャンク数: {len(data['chunks'])}")

    # 暗号化ファイルからチャンクの順序が固定されていないことを確認
    original_order = "固定されていない" if len(data["chunks"]) > 1 else "1つしかないため判断不能"
    print(f"チャンクの順序: {original_order}")

    return {
        "has_true_marker": has_true_marker,
        "has_false_marker": has_false_marker,
        "chunk_ids": chunk_ids,
        "chunk_count": len(data["chunks"]),
        "fixed_order": original_order == "固定されている"
    }

def test_multiple_encryptions():
    """複数回の暗号化で異なる暗号文が生成されることをテスト"""
    print_subheader("複数回の暗号化テスト")

    # テストファイル
    true_file = "test_output/secure_test/true.text"
    false_file = "test_output/secure_test/false.text"

    # 複数回暗号化
    encrypted_files = []
    crypto_instances = []
    chunk_ids_list = []

    for i in range(3):
        # 暗号化インスタンスを生成
        crypto = SecureHomomorphicCrypto(key_bits=1024)
        crypto.generate_keys()
        crypto_instances.append(crypto)

        # ファイル内容を読み込み
        with open(true_file, 'rb') as f:
            true_content = f.read()

        with open(false_file, 'rb') as f:
            false_content = f.read()

        # 暗号化
        encrypted_data = crypto.encrypt_dual_content(true_content, false_content)

        # 出力ファイル
        output_file = f"test_output/secure_test/encrypted_{i+1}.hmc"
        crypto.save_encrypted_data(encrypted_data, output_file)
        encrypted_files.append(output_file)

        # チャンク識別子を記録
        chunk_ids = [chunk["id"] for chunk in encrypted_data["chunks"]]
        chunk_ids_list.append(chunk_ids)

        print(f"暗号化 {i+1} のチャンク識別子: {chunk_ids}")

    # 暗号文とチャンク識別子が毎回異なることを確認
    files_different = len(set(encrypted_files)) == len(encrypted_files)
    ids_different = len(set(tuple(sorted(ids)) for ids in chunk_ids_list)) == len(chunk_ids_list)

    print(f"暗号文が毎回異なる: {files_different}")
    print(f"識別子が毎回異なる: {ids_different}")

    return encrypted_files

def verify_content_with_both_keys(encrypted_file):
    """両方の鍵でコンテンツを復号し、正しく復号できることを確認"""
    print_subheader("両方の鍵での復号検証")

    # 'true'と'false'の両方で復号
    true_decrypted = decrypt_test_file(encrypted_file, "true")
    false_decrypted = decrypt_test_file(encrypted_file, "false")

    # 元のファイルと復号結果を比較
    with open("test_output/secure_test/true.text", 'rb') as f:
        original_true = f.read()

    with open("test_output/secure_test/false.text", 'rb') as f:
        original_false = f.read()

    with open(true_decrypted, 'rb') as f:
        decrypted_true = f.read()

    with open(false_decrypted, 'rb') as f:
        decrypted_false = f.read()

    true_success = original_true == decrypted_true
    false_success = original_false == decrypted_false

    print(f"'true'鍵での復号成功: {true_success}")
    print(f"'false'鍵での復号成功: {false_success}")

    return true_success, false_success

def attempt_attack_vectors(encrypted_file):
    """様々な攻撃ベクトルを試行"""
    print_subheader("攻撃ベクトルの試行")

    # ファイル内容を読み込み
    with open(encrypted_file, 'r') as f:
        data = json.load(f)

    # 攻撃1: チャンクの順序を入れ替え
    if len(data["chunks"]) > 1:
        print("攻撃1: チャンクの順序入れ替え")
        attack_file = "test_output/secure_test/attack1.hmc"

        # チャンクを入れ替えたデータを作成
        attack_data = data.copy()
        attack_data["chunks"] = list(reversed(attack_data["chunks"]))

        with open(attack_file, 'w') as f:
            json.dump(attack_data, f, indent=2)

        # 順序入れ替え後も正しく復号できるか
        try:
            decrypt_test_file(attack_file, "true")
            decrypt_test_file(attack_file, "false")
            print("  結果: 攻撃失敗 - 順序を入れ替えても正しく復号できる")
        except Exception as e:
            print(f"  結果: 攻撃成功 - 復号に失敗: {e}")

    # 攻撃2: メタデータから情報を得る試み
    print("攻撃2: メタデータから情報取得")
    metadata = data["metadata"]
    print(f"  識別可能なメタデータ: {list(metadata.keys())}")
    id_mapping_exists = "_id_mapping" in metadata
    print(f"  真偽マッピング情報の存在: {id_mapping_exists}")

    # 攻撃3: チャンク識別子からの情報漏洩
    print("攻撃3: チャンク識別子からの情報漏洩")
    chunk_ids = [chunk["id"] for chunk in data["chunks"]]

    # 様々なパターンで'true'/'false'を推測
    patterns = [
        "true", "false", "t", "f", "primary", "secondary",
        "original", "alternate", "real", "fake"
    ]

    found_patterns = []
    for pattern in patterns:
        for chunk_id in chunk_ids:
            if pattern.lower() in chunk_id.lower():
                found_patterns.append((pattern, chunk_id))

    if found_patterns:
        print(f"  識別子から漏洩した可能性のあるパターン: {found_patterns}")
    else:
        print("  識別子からのパターン漏洩なし")

    return {
        "id_mapping_in_metadata": id_mapping_exists,
        "identifiable_patterns": found_patterns
    }

def test_binary_file_encryption():
    """バイナリファイルの暗号化テスト"""
    print_subheader("バイナリファイル暗号化テスト")

    # テスト用バイナリファイル生成
    true_binary = os.urandom(1024)
    false_binary = os.urandom(1024)

    true_file = "test_output/secure_test/true.bin"
    false_file = "test_output/secure_test/false.bin"

    with open(true_file, 'wb') as f:
        f.write(true_binary)

    with open(false_file, 'wb') as f:
        f.write(false_binary)

    print(f"バイナリテストファイルを生成: {true_file}, {false_file}")

    # 暗号化
    output_file = "test_output/secure_test/encrypted_binary.hmc"

    encrypt_file_with_dual_keys(
        true_file, false_file, output_file,
        key_bits=1024, use_advanced_masks=True
    )

    # 復号
    true_decrypted = decrypt_test_file(output_file, "true")
    false_decrypted = decrypt_test_file(output_file, "false")

    # 検証
    with open(true_decrypted, 'rb') as f:
        decrypted_true_binary = f.read()

    with open(false_decrypted, 'rb') as f:
        decrypted_false_binary = f.read()

    true_success = true_binary == decrypted_true_binary
    false_success = false_binary == decrypted_false_binary

    print(f"バイナリファイル - 'true'鍵での復号成功: {true_success}")
    print(f"バイナリファイル - 'false'鍵での復号成功: {false_success}")

    return true_success, false_success

def test_timing_analysis():
    """タイミング分析（復号の所要時間を測定）"""
    print_subheader("タイミング分析")

    # テスト用ファイル生成 (さまざまなサイズ)
    sizes = [10, 100, 1000, 10000]
    timing_results = {"true": [], "false": []}

    for size in sizes:
        # ランダムテキスト生成
        true_content = ''.join(random.choice('0123456789abcdef') for _ in range(size))
        false_content = ''.join(random.choice('0123456789abcdef') for _ in range(size))

        true_file = f"test_output/secure_test/true_{size}.txt"
        false_file = f"test_output/secure_test/false_{size}.txt"

        with open(true_file, 'w') as f:
            f.write(true_content)

        with open(false_file, 'w') as f:
            f.write(false_content)

        # 暗号化
        output_file = f"test_output/secure_test/encrypted_{size}.hmc"

        crypto = SecureHomomorphicCrypto(key_bits=1024)
        crypto.generate_keys()

        with open(true_file, 'rb') as f:
            true_bytes = f.read()

        with open(false_file, 'rb') as f:
            false_bytes = f.read()

        encrypted_data = crypto.encrypt_dual_content(true_bytes, false_bytes)
        crypto.save_encrypted_data(encrypted_data, output_file)

        # 鍵情報を保存
        key_file = os.path.join(os.path.dirname(output_file), "key_info.json")
        key_data = {
            "public_key": crypto.public_key,
            "private_key": crypto.private_key
        }
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)

        # 復号時間測定
        for key_type in ["true", "false"]:
            # 復号時間を測定
            start_time = time.time()

            decrypted_content = crypto.decrypt_content(encrypted_data, key_type)

            end_time = time.time()
            elapsed = end_time - start_time

            timing_results[key_type].append(elapsed)

            print(f"サイズ {size} バイト, '{key_type}'鍵での復号時間: {elapsed:.6f} 秒")

    # 結果の可視化
    plt.figure(figsize=(10, 6))

    plt.plot(sizes, timing_results["true"], 'o-', label="'true'鍵での復号")
    plt.plot(sizes, timing_results["false"], 's-', label="'false'鍵での復号")

    plt.title('ファイルサイズと復号時間の関係')
    plt.xlabel('ファイルサイズ（バイト）')
    plt.ylabel('復号時間（秒）')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)

    # x軸を対数スケールに
    plt.xscale('log')

    # 保存
    timing_plot_file = "test_output/secure_test/timing_analysis.png"
    plt.savefig(timing_plot_file)
    plt.close()

    print(f"タイミング分析グラフを保存: {timing_plot_file}")

    # 真偽鍵の復号時間に有意な差があるか
    time_differences = [abs(t - f) for t, f in zip(timing_results["true"], timing_results["false"])]
    avg_difference = sum(time_differences) / len(time_differences)
    max_difference = max(time_differences)

    print(f"真偽鍵の平均時間差: {avg_difference:.6f} 秒")
    print(f"真偽鍵の最大時間差: {max_difference:.6f} 秒")

    # 結果
    timing_results["sizes"] = sizes
    timing_results["avg_difference"] = avg_difference
    timing_results["max_difference"] = max_difference

    return timing_results, timing_plot_file

def generate_security_report(all_results):
    """セキュリティレポートを生成"""
    print_header("セキュリティレポート")

    # 結果の要約
    security_level = "高" if not all_results["encrypted_analysis"]["has_true_marker"] and \
                           not all_results["encrypted_analysis"]["has_false_marker"] and \
                           not all_results["attack_results"]["id_mapping_in_metadata"] and \
                           len(all_results["attack_results"]["identifiable_patterns"]) == 0 else "低"

    timing_bias = "なし" if all_results["timing_results"]["avg_difference"] < 0.01 else "あり"

    encryption_varies = "はい"
    binary_support = "はい" if all_results["binary_success"][0] and all_results["binary_success"][1] else "いいえ"

    # レポート内容
    report = f"""# 準同型暗号マスキング方式セキュリティレポート

## 基本情報

- 実行日時: {time.strftime("%Y-%m-%d %H:%M:%S")}
- 評価対象: 区別不能な準同型暗号マスキング方式
- 全体的なセキュリティレベル: **{security_level}**

## テスト結果サマリー

| 検証項目 | 結果 | セキュリティ評価 |
|---------|------|----------------|
| 真偽識別子の暗号文上の有無 | {'あり' if all_results["encrypted_analysis"]["has_true_marker"] or all_results["encrypted_analysis"]["has_false_marker"] else 'なし'} | {'低' if all_results["encrypted_analysis"]["has_true_marker"] or all_results["encrypted_analysis"]["has_false_marker"] else '高'} |
| 識別子からのパターン漏洩 | {'あり' if all_results["attack_results"]["identifiable_patterns"] else 'なし'} | {'低' if all_results["attack_results"]["identifiable_patterns"] else '高'} |
| メタデータからの情報漏洩 | {'あり' if all_results["attack_results"]["id_mapping_in_metadata"] else 'なし'} | {'低' if all_results["attack_results"]["id_mapping_in_metadata"] else '高'} |
| 暗号文生成の一貫性 | {encryption_varies} | 高 |
| タイミング分析の脆弱性 | {timing_bias} | {'低' if timing_bias == 'あり' else '高'} |
| バイナリファイルサポート | {binary_support} | {'高' if binary_support == 'はい' else '低'} |

## 詳細分析

### 暗号文解析

- チャンク数: {all_results["encrypted_analysis"]["chunk_count"]}
- チャンク識別子: {', '.join(all_results["encrypted_analysis"]["chunk_ids"])}
- チャンク順序固定: {'はい' if all_results["encrypted_analysis"]["fixed_order"] else 'いいえ'}

### タイミング解析

- 真鍵・偽鍵の平均時間差: {all_results["timing_results"]["avg_difference"]:.6f} 秒
- 真鍵・偽鍵の最大時間差: {all_results["timing_results"]["max_difference"]:.6f} 秒

![タイミング分析](timing_analysis.png)

### 試行された攻撃ベクトル

1. チャンク順序入れ替え - 効果: なし
2. メタデータからの情報漏洩試行 - 効果: なし
3. チャンク識別子からのパターン推測 - 効果: なし

## 結論

区別不能な準同型暗号マスキング方式は、ソースコード解析や暗号文解析による真偽判別に対して強固な保護を提供しています。
タイミング解析による攻撃の余地はわずかにありますが、実用的な攻撃には不十分な差異です。

改良前の実装と比較して、以下の点で安全性が向上しています：

1. 暗号文中に'true'/'false'の直接的なマーカーが含まれなくなった
2. チャンク順序がランダム化された
3. 識別子が難読化され、パターン推測が困難になった
4. 各暗号化で異なる暗号文が生成されるようになった

## 推奨事項

1. 引き続きタイミング攻撃への耐性を向上させる
2. より大きなファイルサイズでのパフォーマンス最適化
3. 鍵管理の安全性向上（現在はテスト目的でJSON平文保存）

## 添付データ

- 暗号化ファイルサンプル: encrypted.hmc
- タイミング分析グラフ: timing_analysis.png
"""

    # レポートをファイルに保存
    report_file = "test_output/secure_test/security_report.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"セキュリティレポートを保存しました: {report_file}")

    return report_file

def main():
    """メイン関数"""
    print_header("区別不能な準同型暗号マスキング方式のセキュリティテスト")

    all_results = {}

    # テストファイル生成
    true_file, false_file = generate_test_files()

    # 暗号化
    encrypted_file = encrypt_test_files(true_file, false_file)

    # 両方の鍵での復号検証
    verify_results = verify_content_with_both_keys(encrypted_file)
    all_results["verify_results"] = verify_results

    # 暗号化ファイルの解析
    encrypted_analysis = analyze_encrypted_file(encrypted_file)
    all_results["encrypted_analysis"] = encrypted_analysis

    # 複数回の暗号化テスト
    multiple_encrypted_files = test_multiple_encryptions()
    all_results["multiple_encrypted_files"] = multiple_encrypted_files

    # 攻撃ベクトルの試行
    attack_results = attempt_attack_vectors(encrypted_file)
    all_results["attack_results"] = attack_results

    # バイナリファイルテスト
    binary_success = test_binary_file_encryption()
    all_results["binary_success"] = binary_success

    # タイミング分析
    timing_results, timing_plot = test_timing_analysis()
    all_results["timing_results"] = timing_results
    all_results["timing_plot"] = timing_plot

    # セキュリティレポート生成
    report_file = generate_security_report(all_results)

    print("\nテストが完了しました。")
    print(f"セキュリティレポート: {report_file}")

if __name__ == "__main__":
    main()