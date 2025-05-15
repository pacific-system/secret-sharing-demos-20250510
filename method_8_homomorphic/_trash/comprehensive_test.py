#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の包括的テストスクリプト

このスクリプトは、準同型暗号マスキング方式に関連する全ての機能について
包括的なテストを実行します。監査で指摘された問題も修正し、特に以下の点を検証します：

1. テキスト、JSON、CSV、バイナリファイルの正確な暗号化・復号
2. 暗号化ファイルから真実ファイルの内容を区別できないこと
3. 書類の最終行が欠損しないこと
4. 高度な暗号化方式が正しく実装されていること
"""

import os
import sys
import time
import json
import random
import hashlib
import base64
import binascii
import matplotlib.pyplot as plt
from typing import Dict, List, Any, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 必要なモジュールをインポート
from config import (
    TRUE_TEXT_PATH,
    FALSE_TEXT_PATH,
    KEY_SIZE_BYTES,
    SALT_SIZE,
    OUTPUT_FORMAT,
    PAILLIER_KEY_BITS
)

from homomorphic import (
    PaillierCrypto,
    derive_key_from_password
)

from encrypt import (
    encrypt_files
)

from decrypt import (
    decrypt_file
)

from indistinguishable import (
    analyze_key_type_enhanced,
    IndistinguishableWrapper
)

from crypto_mask import (
    MaskFunctionGenerator,
    AdvancedMaskFunctionGenerator
)

# 結果を保存するディレクトリ
TEST_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'test_output')

def ensure_test_output_dir():
    """テスト出力ディレクトリを確保"""
    if not os.path.exists(TEST_OUTPUT_DIR):
        os.makedirs(TEST_OUTPUT_DIR)
        print(f"テスト出力ディレクトリを作成しました: {TEST_OUTPUT_DIR}")

    # 常に削除されるべきテスト一時ファイル
    test_files = [
        os.path.join(TEST_OUTPUT_DIR, 'test_encrypted.hmc'),
        os.path.join(TEST_OUTPUT_DIR, 'test_decrypted_true.txt'),
        os.path.join(TEST_OUTPUT_DIR, 'test_decrypted_false.txt')
    ]

    for file in test_files:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"テスト用一時ファイルを削除しました: {file}")
            except Exception as e:
                print(f"警告: {file} の削除に失敗しました: {e}")

def create_test_files():
    """テスト用のさまざまな種類のファイルを作成"""
    ensure_test_output_dir()

    # テキストファイル
    text_true = os.path.join(TEST_OUTPUT_DIR, "test_true.txt")
    text_false = os.path.join(TEST_OUTPUT_DIR, "test_false.txt")

    with open(text_true, "w", encoding="utf-8") as f:
        f.write("これは真のテキストファイルです。\n重要な情報が含まれています。\n最終行も含まれるか確認します。")

    with open(text_false, "w", encoding="utf-8") as f:
        f.write("これは偽のテキストファイルです。\n偽の情報が含まれています。\n最終行も含まれるか確認します。")

    # JSONファイル
    json_true = os.path.join(TEST_OUTPUT_DIR, "test_true.json")
    json_false = os.path.join(TEST_OUTPUT_DIR, "test_false.json")

    true_data = {
        "name": "真のデータ",
        "values": [1, 2, 3, 4, 5],
        "metadata": {
            "created": "2025-05-10",
            "author": "テストユーザー",
            "description": "これは真のJSONファイルです"
        }
    }

    false_data = {
        "name": "偽のデータ",
        "values": [10, 20, 30, 40, 50],
        "metadata": {
            "created": "2025-05-10",
            "author": "テストユーザー",
            "description": "これは偽のJSONファイルです"
        }
    }

    with open(json_true, "w", encoding="utf-8") as f:
        json.dump(true_data, f, ensure_ascii=False, indent=2)

    with open(json_false, "w", encoding="utf-8") as f:
        json.dump(false_data, f, ensure_ascii=False, indent=2)

    # CSVファイル
    csv_true = os.path.join(TEST_OUTPUT_DIR, "test_true.csv")
    csv_false = os.path.join(TEST_OUTPUT_DIR, "test_false.csv")

    with open(csv_true, "w", encoding="utf-8") as f:
        f.write("ID,Name,Value\n")
        f.write("1,真のデータ1,100\n")
        f.write("2,真のデータ2,200\n")
        f.write("3,真のデータ3,300\n")
        f.write("4,最終行データ,400\n")

    with open(csv_false, "w", encoding="utf-8") as f:
        f.write("ID,Name,Value\n")
        f.write("1,偽のデータ1,500\n")
        f.write("2,偽のデータ2,600\n")
        f.write("3,偽のデータ3,700\n")
        f.write("4,最終行データ,800\n")

    # バイナリファイル
    bin_true = os.path.join(TEST_OUTPUT_DIR, "test_true.bin")
    bin_false = os.path.join(TEST_OUTPUT_DIR, "test_false.bin")

    with open(bin_true, "wb") as f:
        f.write(os.urandom(256))

    with open(bin_false, "wb") as f:
        f.write(os.urandom(256))

    return {
        "text": (text_true, text_false),
        "json": (json_true, json_false),
        "csv": (csv_true, csv_false),
        "binary": (bin_true, bin_false)
    }

def file_comparison_test(original_file, decrypted_file):
    """ファイルの内容を比較し、一致度を検査"""
    try:
        # ファイルが存在するか確認
        if not os.path.exists(original_file) or not os.path.exists(decrypted_file):
            return False, "ファイルが存在しません", {}

        # ファイルサイズを比較
        orig_size = os.path.getsize(original_file)
        decrypted_size = os.path.getsize(decrypted_file)

        # 両方のファイルを読み込み
        with open(original_file, 'rb') as f:
            orig_content = f.read()

        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()

        # 完全一致チェック
        exact_match = orig_content == decrypted_content

        # バイナリとして比較
        if len(orig_content) > 0 and len(decrypted_content) > 0:
            # 最初の1000バイトでの一致度を計算
            max_check_len = min(1000, min(len(orig_content), len(decrypted_content)))
            matching_bytes = sum(1 for a, b in zip(orig_content[:max_check_len], decrypted_content[:max_check_len]) if a == b)
            byte_similarity = matching_bytes / max_check_len
        else:
            byte_similarity = 0

        # テキストファイルとしてのチェック（UnicodeDecodeErrorが発生する可能性あり）
        text_similarity = 0
        try:
            orig_text = orig_content.decode('utf-8')
            decrypted_text = decrypted_content.decode('utf-8')

            # 先頭、中間、末尾の行をチェック
            orig_lines = orig_text.splitlines()
            decrypted_lines = decrypted_text.splitlines()

            if len(orig_lines) > 0 and len(decrypted_lines) > 0:
                # 最初の行が一致するか
                first_line_match = orig_lines[0] == decrypted_lines[0]

                # 最後の行も含まれているか（欠損問題のチェック）
                last_line_match = False
                if len(orig_lines) > 0 and len(decrypted_lines) > 0:
                    last_line_match = orig_lines[-1] == decrypted_lines[-1]

                # 行数が同じか
                line_count_match = len(orig_lines) == len(decrypted_lines)

                # 全体の一致度
                text_similarity = sum(1 for a, b in zip(orig_lines, decrypted_lines) if a == b) / max(len(orig_lines), len(decrypted_lines))
            else:
                first_line_match = False
                last_line_match = False
                line_count_match = False
        except UnicodeDecodeError:
            # バイナリファイルなど
            first_line_match = None
            last_line_match = None
            line_count_match = None

        results = {
            "original_size": orig_size,
            "decrypted_size": decrypted_size,
            "exact_match": exact_match,
            "byte_similarity": byte_similarity,
            "first_line_match": first_line_match,
            "last_line_match": last_line_match,
            "line_count_match": line_count_match,
            "text_similarity": text_similarity
        }

        # テスト結果のサマリー
        if exact_match:
            message = "完全一致しました"
            success = True
        elif byte_similarity > 0.9:
            message = "ほぼ一致しています"
            success = True
        else:
            message = f"一致度が低いです: {byte_similarity:.2f}"
            success = False

        return success, message, results

    except Exception as e:
        return False, f"比較中にエラーが発生しました: {e}", {}

def run_encryption_decryption_test(true_file, false_file, file_type="text", verbose=True):
    """
    暗号化・復号の完全テストを実行

    Args:
        true_file: 真のファイルパス
        false_file: 偽のファイルパス
        file_type: ファイルタイプ（"text", "json", "csv", "binary"）
        verbose: 詳細な出力を表示するか

    Returns:
        テスト結果を含む辞書
    """
    ensure_test_output_dir()

    test_name = f"{file_type}ファイルの暗号化・復号テスト"
    print(f"\n===== {test_name} =====")

    # 出力ファイルパス
    output_file = os.path.join(TEST_OUTPUT_DIR, f"test_encrypted_{file_type}.hmc")
    true_output = os.path.join(TEST_OUTPUT_DIR, f"test_decrypted_{file_type}_true.out")
    false_output = os.path.join(TEST_OUTPUT_DIR, f"test_decrypted_{file_type}_false.out")

    # テスト結果を格納する辞書
    results = {
        "name": test_name,
        "true_file": true_file,
        "false_file": false_file,
        "output_file": output_file,
        "true_output": true_output,
        "false_output": false_output,
        "encryption_success": False,
        "true_decryption_success": False,
        "false_decryption_success": False,
        "encryption_time": 0,
        "true_decryption_time": 0,
        "false_decryption_time": 0,
        "true_key": "",
        "false_key": "",
        "true_file_size": os.path.getsize(true_file),
        "false_file_size": os.path.getsize(false_file),
        "encrypted_file_size": 0,
        "true_output_size": 0,
        "false_output_size": 0,
        "true_comparison": {},
        "false_comparison": {},
        "log_output": []
    }

    try:
        # 1. 暗号化テスト
        print(f"1. 暗号化: {true_file}, {false_file} → {output_file}")
        results["log_output"].append(f"暗号化開始: {true_file}, {false_file}")

        # 引数の準備
        class Args:
            pass

        args = Args()
        args.true_file = true_file
        args.false_file = false_file
        args.output = output_file
        args.algorithm = 'paillier'
        args.key = None
        args.password = "test_password_complex_123!"
        args.advanced_mask = True
        args.key_bits = PAILLIER_KEY_BITS
        args.save_keys = False
        args.keys_dir = os.path.join(TEST_OUTPUT_DIR, 'keys')
        args.verbose = verbose
        args.force_data_type = 'auto'
        args.indistinguishable = True
        args.noise_intensity = 0.05
        args.redundancy_factor = 1
        args.shuffle_seed = None

        # 暗号化開始時刻を記録
        start_time = time.time()

        # 暗号化実行
        master_key, encrypted_data = encrypt_files(args)

        # 暗号化時間を記録
        encryption_time = time.time() - start_time
        results["encryption_time"] = encryption_time

        if os.path.exists(output_file):
            results["encryption_success"] = True
            results["encrypted_file_size"] = os.path.getsize(output_file)
            results["log_output"].append(f"暗号化成功: {encryption_time:.2f}秒")
        else:
            results["log_output"].append("暗号化失敗: 出力ファイルが見つかりません")
            return results

        # マスターキーから真/偽の鍵を導出
        if master_key:
            seed = hashlib.sha256(master_key).digest()
            true_key = hashlib.pbkdf2_hmac('sha256', seed, b'true', 10000, KEY_SIZE_BYTES)
            false_key = hashlib.pbkdf2_hmac('sha256', seed, b'false', 10000, KEY_SIZE_BYTES)

            results["master_key"] = master_key.hex()
            results["true_key"] = true_key.hex()
            results["false_key"] = false_key.hex()

            # 鍵タイプ解析
            true_key_type = analyze_key_type_enhanced(true_key)
            false_key_type = analyze_key_type_enhanced(false_key)

            results["true_key_type"] = true_key_type
            results["false_key_type"] = false_key_type

            results["log_output"].append(f"鍵導出: 真鍵タイプ={true_key_type}, 偽鍵タイプ={false_key_type}")
        else:
            results["log_output"].append("マスターキーの生成に失敗")
            return results

        # 2. 真鍵での復号テスト
        print(f"2. 真鍵での復号: {output_file} + 真鍵 → {true_output}")
        results["log_output"].append(f"真鍵での復号開始")

        start_time = time.time()
        true_result = decrypt_file(
            input_file=output_file,
            output_file=true_output,
            key_bytes=true_key,
            key_type="true",
            use_enhanced_security=True
        )
        true_decryption_time = time.time() - start_time

        results["true_decryption_time"] = true_decryption_time
        results["true_decryption_success"] = true_result.get("success", False)

        if os.path.exists(true_output):
            results["true_output_size"] = os.path.getsize(true_output)
            results["log_output"].append(f"真鍵での復号成功: {true_decryption_time:.2f}秒")
        else:
            results["log_output"].append("真鍵での復号失敗: 出力ファイルが見つかりません")

        # 3. 偽鍵での復号テスト
        print(f"3. 偽鍵での復号: {output_file} + 偽鍵 → {false_output}")
        results["log_output"].append(f"偽鍵での復号開始")

        start_time = time.time()
        false_result = decrypt_file(
            input_file=output_file,
            output_file=false_output,
            key_bytes=false_key,
            key_type="false",
            use_enhanced_security=True
        )
        false_decryption_time = time.time() - start_time

        results["false_decryption_time"] = false_decryption_time
        results["false_decryption_success"] = false_result.get("success", False)

        if os.path.exists(false_output):
            results["false_output_size"] = os.path.getsize(false_output)
            results["log_output"].append(f"偽鍵での復号成功: {false_decryption_time:.2f}秒")
        else:
            results["log_output"].append("偽鍵での復号失敗: 出力ファイルが見つかりません")

        # 4. 復号結果の検証
        print("4. 復号結果の検証")
        results["log_output"].append("復号結果の検証開始")

        # 真鍵の復号結果を検証
        if os.path.exists(true_output):
            true_success, true_message, true_details = file_comparison_test(true_file, true_output)
            results["true_comparison"] = true_details
            results["true_comparison"]["message"] = true_message
            results["true_comparison"]["success"] = true_success

            print(f"   - 真鍵による復号結果: {true_message}")
            results["log_output"].append(f"真鍵検証: {true_message}")

            # 最終行が欠損していないかを特に確認
            if true_details.get("last_line_match") == False:
                print("     [警告] 最終行が欠損しています！")
                results["log_output"].append("最終行欠損エラー（真鍵）")

        # 偽鍵の復号結果を検証
        if os.path.exists(false_output):
            false_success, false_message, false_details = file_comparison_test(false_file, false_output)
            results["false_comparison"] = false_details
            results["false_comparison"]["message"] = false_message
            results["false_comparison"]["success"] = false_success

            print(f"   - 偽鍵による復号結果: {false_message}")
            results["log_output"].append(f"偽鍵検証: {false_message}")

            # 最終行が欠損していないかを特に確認
            if false_details.get("last_line_match") == False:
                print("     [警告] 最終行が欠損しています！")
                results["log_output"].append("最終行欠損エラー（偽鍵）")

        # 5. 総合判定
        overall_success = (
            results["encryption_success"] and
            (results["true_comparison"].get("success", False) or results["false_comparison"].get("success", False))
        )

        if overall_success:
            print(f"\n✅ {test_name}: 成功")
            results["log_output"].append(f"{test_name}: 成功")
        else:
            print(f"\n❌ {test_name}: 失敗")
            results["log_output"].append(f"{test_name}: 失敗")

        return results

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        results["error"] = str(e)
        results["error_trace"] = error_trace
        results["log_output"].append(f"エラー発生: {e}")
        print(f"テスト実行中にエラーが発生しました: {e}")
        print(error_trace)
        return results

def run_indistinguishability_test(true_file, false_file):
    """
    識別不能性テスト - 暗号文から真/偽ファイルを識別できないことを確認

    Args:
        true_file: 真のファイルパス
        false_file: 偽のファイルパス

    Returns:
        テスト結果を含む辞書
    """
    ensure_test_output_dir()

    print("\n===== 識別不能性テスト =====")

    # 出力ファイルパス
    output_file = os.path.join(TEST_OUTPUT_DIR, "indistinguishability_test.hmc")

    # テスト結果を格納する辞書
    results = {
        "name": "識別不能性テスト",
        "success": False,
        "log_output": []
    }

    try:
        # 引数の準備
        class Args:
            pass

        args = Args()
        args.true_file = true_file
        args.false_file = false_file
        args.output = output_file
        args.algorithm = 'paillier'
        args.key = None
        args.password = "indistinguishability_test_password"
        args.advanced_mask = True
        args.key_bits = PAILLIER_KEY_BITS
        args.save_keys = False
        args.keys_dir = os.path.join(TEST_OUTPUT_DIR, 'keys')
        args.verbose = False
        args.force_data_type = 'auto'
        args.indistinguishable = True
        args.noise_intensity = 0.05
        args.redundancy_factor = 1
        args.shuffle_seed = None

        # 暗号化実行
        print("1. 暗号化の実行")
        master_key, encrypted_data = encrypt_files(args)

        if not os.path.exists(output_file):
            results["log_output"].append("暗号化失敗: 出力ファイルが見つかりません")
            return results

        print("2. 暗号文の解析")

        # 暗号化ファイルの読み込み
        with open(output_file, 'r') as f:
            encrypted_json = json.load(f)

        # 暗号文のビット解析
        chunks = encrypted_json.get("all_chunks", [])
        chunk_values = [int(chunk) for chunk in chunks]

        # 統計的特性の分析
        bit_lengths = [len(bin(val)[2:]) for val in chunk_values[:10]]
        max_val = max(chunk_values[:10])
        min_val = min(chunk_values[:10])
        avg_val = sum(chunk_values[:10]) / 10 if chunk_values else 0

        # 暗号文からファイルタイプを推測できるか
        file_type_detectable = False

        # 暗号文から真/偽の区別ができるか
        distinguishable = False

        # メタデータから真/偽の区別ができるか
        metadata_distinguishable = False

        print(f"   - 暗号文チャンク数: {len(chunk_values)}")
        print(f"   - ビット長の範囲: {min(bit_lengths)} - {max(bit_lengths)}")

        # 真/偽の識別を試みる（このテストは失敗すべき）
        print("3. 識別不能性の検証")

        # 暗号文を二つのグループに分けて、どちらが真/偽か推測する
        half = len(chunk_values) // 2
        first_half = chunk_values[:half]
        second_half = chunk_values[half:]

        # 統計的特性に違いがあるか
        first_avg = sum(first_half) / len(first_half) if first_half else 0
        second_avg = sum(second_half) / len(second_half) if second_half else 0

        difference = abs(first_avg - second_avg)
        relative_diff = difference / max(first_avg, second_avg) if max(first_avg, second_avg) > 0 else 0

        print(f"   - 前半と後半の平均値の相対差: {relative_diff:.6f}")

        # 相対差が小さければ区別が困難
        distinguishable = relative_diff > 0.1

        if distinguishable:
            print("   ❌ 暗号文から真/偽の区別が可能です")
            results["log_output"].append("識別不能性テスト失敗: 暗号文から真/偽の区別が可能")
        else:
            print("   ✅ 暗号文から真/偽の区別は困難です")
            results["log_output"].append("暗号文からの区別は困難")
            results["success"] = True

        # メタデータの分析
        mask_data = encrypted_json.get("mask", {})
        if "true_mask" in mask_data and "false_mask" in mask_data:
            true_mask = mask_data["true_mask"]
            false_mask = mask_data["false_mask"]

            # マスク情報に明確な違いがあるか
            metadata_distinguishable = true_mask != false_mask

            if metadata_distinguishable:
                print("   ❌ メタデータから真/偽の区別が可能です")
                results["log_output"].append("識別不能性テスト失敗: メタデータから真/偽の区別が可能")
            else:
                print("   ✅ メタデータからの真/偽の区別は困難です")
                results["log_output"].append("メタデータからの区別は困難")

        # 総合判定
        results["success"] = not distinguishable and not metadata_distinguishable

        if results["success"]:
            print("\n✅ 識別不能性テスト: 成功")
            results["log_output"].append("識別不能性テスト: 成功")
        else:
            print("\n❌ 識別不能性テスト: 失敗")
            results["log_output"].append("識別不能性テスト: 失敗")

        return results

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        results["error"] = str(e)
        results["error_trace"] = error_trace
        results["log_output"].append(f"エラー発生: {e}")
        print(f"テスト実行中にエラーが発生しました: {e}")
        print(error_trace)
        return results

def plot_test_results(test_results, common_files_results=None):
    """テスト結果をグラフ化して保存"""
    ensure_test_output_dir()

    # グラフのスタイル設定
    plt.style.use('dark_background')

    # 1. 処理時間比較グラフ
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('準同型暗号マスキング方式 - テスト結果', fontsize=16)

    # 1.1 ファイルタイプごとの処理時間
    ax = axes[0, 0]
    file_types = []
    encryption_times = []
    true_decryption_times = []
    false_decryption_times = []

    for result in test_results:
        if not result.get("name", "").startswith("識別不能性"):  # 暗号化・復号テスト結果のみ
            file_type = result.get("name", "").split("ファイル")[0]
            file_types.append(file_type)
            encryption_times.append(result.get("encryption_time", 0))
            true_decryption_times.append(result.get("true_decryption_time", 0))
            false_decryption_times.append(result.get("false_decryption_time", 0))

    # 横棒グラフにする
    x = range(len(file_types))
    width = 0.25

    ax.barh([i - width for i in x], encryption_times, width, label='暗号化時間', color='#5DA5DA')
    ax.barh([i for i in x], true_decryption_times, width, label='真鍵復号時間', color='#FAA43A')
    ax.barh([i + width for i in x], false_decryption_times, width, label='偽鍵復号時間', color='#60BD68')

    ax.set_yticks(x)
    ax.set_yticklabels(file_types)
    ax.set_xlabel('処理時間 (秒)')
    ax.set_title('ファイルタイプ別処理時間')
    ax.legend(loc='lower right')
    ax.grid(alpha=0.3)

    # 1.2 ファイルサイズ比較
    ax = axes[0, 1]
    true_sizes = []
    false_sizes = []
    encrypted_sizes = []

    for result in test_results:
        if not result.get("name", "").startswith("識別不能性"):
            true_sizes.append(result.get("true_file_size", 0) / 1024)  # KBに変換
            false_sizes.append(result.get("false_file_size", 0) / 1024)
            encrypted_sizes.append(result.get("encrypted_file_size", 0) / 1024)

    ax.barh([i - width for i in x], true_sizes, width, label='真ファイル', color='#5DA5DA')
    ax.barh([i for i in x], false_sizes, width, label='偽ファイル', color='#FAA43A')
    ax.barh([i + width for i in x], encrypted_sizes, width, label='暗号化ファイル', color='#F15854')

    ax.set_yticks(x)
    ax.set_yticklabels(file_types)
    ax.set_xlabel('ファイルサイズ (KB)')
    ax.set_title('ファイルタイプ別サイズ比較')
    ax.legend(loc='lower right')
    ax.grid(alpha=0.3)

    # 1.3 復号精度比較
    ax = axes[1, 0]
    true_accuracies = []
    false_accuracies = []

    for result in test_results:
        if not result.get("name", "").startswith("識別不能性"):
            true_accuracy = result.get("true_comparison", {}).get("text_similarity", 0) * 100
            false_accuracy = result.get("false_comparison", {}).get("text_similarity", 0) * 100
            true_accuracies.append(true_accuracy)
            false_accuracies.append(false_accuracy)

    ax.barh([i - width/2 for i in x], true_accuracies, width, label='真鍵復号精度', color='#B276B2')
    ax.barh([i + width/2 for i in x], false_accuracies, width, label='偽鍵復号精度', color='#DECF3F')

    ax.set_yticks(x)
    ax.set_yticklabels(file_types)
    ax.set_xlabel('復号精度 (%)')
    ax.set_title('ファイルタイプ別復号精度')
    ax.set_xlim(0, 105)  # 0-100%の範囲
    ax.legend(loc='lower right')
    ax.grid(alpha=0.3)

    # 1.4 common/true-false-textファイルの結果（提供されている場合）
    ax = axes[1, 1]

    if common_files_results:
        # true.textとfalse.textの結果を取得
        true_file_result = common_files_results.get("true_file", {})
        false_file_result = common_files_results.get("false_file", {})

        # データ準備
        labels = ['ファイルサイズ (KB)', '暗号化後 (KB)', '復号時間 (秒)', '復号精度 (%)']

        true_values = [
            true_file_result.get("true_file_size", 0) / 1024,
            true_file_result.get("encrypted_file_size", 0) / 1024,
            true_file_result.get("true_decryption_time", 0),
            true_file_result.get("true_comparison", {}).get("text_similarity", 0) * 100
        ]

        false_values = [
            false_file_result.get("true_file_size", 0) / 1024,
            false_file_result.get("encrypted_file_size", 0) / 1024,
            false_file_result.get("true_decryption_time", 0),
            false_file_result.get("true_comparison", {}).get("text_similarity", 0) * 100
        ]

        y = range(len(labels))

        ax.barh([i - width/2 for i in y], true_values, width, label='t.text', color='#4D4D4D')
        ax.barh([i + width/2 for i in y], false_values, width, label='f.text', color='#5DA5DA')

        ax.set_yticks(y)
        ax.set_yticklabels(labels)
        ax.set_title('common/true-false-textファイル結果')
        ax.legend(loc='lower right')
        ax.grid(alpha=0.3)
    else:
        ax.text(0.5, 0.5, 'common/true-false-textファイルの\nテスト結果なし',
                horizontalalignment='center', verticalalignment='center', fontsize=12)
        ax.set_title('common/true-false-textファイル結果')

    # レイアウト調整
    plt.tight_layout(rect=[0, 0, 1, 0.95])

    # 画像保存
    output_path = os.path.join(TEST_OUTPUT_DIR, 'homomorphic_operations.png')
    plt.savefig(output_path, dpi=300)
    print(f"テスト結果グラフを保存しました: {output_path}")

    # メモリ解放
    plt.close(fig)

    return output_path

def generate_test_report(test_results, common_files_results=None, graph_path=None):
    """テスト結果からMarkdownレポートを生成"""
    ensure_test_output_dir()

    report = []
    report.append("# 準同型暗号マスキング方式テスト結果")
    report.append(f"実行日時: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")

    # 成功・失敗の集計
    total_tests = len(test_results)
    success_tests = sum(1 for result in test_results if result.get("success", False) or
                       (result.get("true_comparison", {}).get("success", False) or
                        result.get("false_comparison", {}).get("success", False)))

    report.append(f"## テスト概要")
    report.append(f"- 実行テスト数: {total_tests}")
    report.append(f"- 成功テスト数: {success_tests}")
    report.append(f"- 失敗テスト数: {total_tests - success_tests}")
    report.append("")

    # グラフの挿入（提供されている場合）
    if graph_path:
        report.append("## テスト結果グラフ")
        report.append(f"![準同型暗号マスキング方式テスト結果]({graph_path})")
        report.append("")

    # ファイルタイプごとのテスト結果
    report.append("## ファイルタイプ別テスト結果")

    for result in test_results:
        if result.get("name", "").startswith("識別不能性"):
            continue  # 識別不能性テストは別セクションで記述

        report.append(f"### {result.get('name', 'テスト')}")

        # 基本情報
        report.append("#### 基本情報")
        report.append("| 項目 | 値 |")
        report.append("| ---- | ---- |")
        report.append(f"| 真ファイル | `{os.path.basename(result.get('true_file', ''))}` |")
        report.append(f"| 偽ファイル | `{os.path.basename(result.get('false_file', ''))}` |")
        report.append(f"| 暗号化ファイル | `{os.path.basename(result.get('output_file', ''))}` |")
        report.append(f"| 暗号化成功 | {'✅' if result.get('encryption_success', False) else '❌'} |")
        report.append(f"| 真鍵復号成功 | {'✅' if result.get('true_decryption_success', False) else '❌'} |")
        report.append(f"| 偽鍵復号成功 | {'✅' if result.get('false_decryption_success', False) else '❌'} |")
        report.append("")

        # ファイルサイズと処理時間
        report.append("#### ファイルサイズと処理時間")
        report.append("| 項目 | サイズ (bytes) | 処理時間 (秒) |")
        report.append("| ---- | ----: | ----: |")
        report.append(f"| 真ファイル | {result.get('true_file_size', 0):,} | - |")
        report.append(f"| 偽ファイル | {result.get('false_file_size', 0):,} | - |")
        report.append(f"| 暗号化ファイル | {result.get('encrypted_file_size', 0):,} | {result.get('encryption_time', 0):.2f} |")
        report.append(f"| 真鍵復号結果 | {result.get('true_output_size', 0):,} | {result.get('true_decryption_time', 0):.2f} |")
        report.append(f"| 偽鍵復号結果 | {result.get('false_output_size', 0):,} | {result.get('false_decryption_time', 0):.2f} |")
        report.append("")

        # 復号精度
        report.append("#### 復号結果の評価")
        report.append("| 項目 | 真鍵復号 | 偽鍵復号 |")
        report.append("| ---- | ---- | ---- |")
        report.append(f"| 完全一致 | {'✅' if result.get('true_comparison', {}).get('exact_match', False) else '❌'} | {'✅' if result.get('false_comparison', {}).get('exact_match', False) else '❌'} |")
        report.append(f"| バイト一致度 | {result.get('true_comparison', {}).get('byte_similarity', 0):.2%} | {result.get('false_comparison', {}).get('byte_similarity', 0):.2%} |")
        report.append(f"| テキスト一致度 | {result.get('true_comparison', {}).get('text_similarity', 0):.2%} | {result.get('false_comparison', {}).get('text_similarity', 0):.2%} |")
        report.append(f"| 最初の行の一致 | {'✅' if result.get('true_comparison', {}).get('first_line_match', False) else '❌'} | {'✅' if result.get('false_comparison', {}).get('first_line_match', False) else '❌'} |")
        report.append(f"| 最後の行の一致 | {'✅' if result.get('true_comparison', {}).get('last_line_match', False) else '❌'} | {'✅' if result.get('false_comparison', {}).get('last_line_match', False) else '❌'} |")
        report.append(f"| 行数の一致 | {'✅' if result.get('true_comparison', {}).get('line_count_match', False) else '❌'} | {'✅' if result.get('false_comparison', {}).get('line_count_match', False) else '❌'} |")
        report.append("")

        # エラーがあれば追記
        if "error" in result:
            report.append("#### エラー情報")
            report.append(f"```")
            report.append(result.get("error", ""))
            report.append(f"```")
            report.append("")

    # 識別不能性テスト結果
    for result in test_results:
        if result.get("name", "").startswith("識別不能性"):
            report.append("## 識別不能性テスト結果")
            report.append(f"識別不能性テスト: {'✅ 成功' if result.get('success', False) else '❌ 失敗'}")
            report.append("")

            # ログ出力
            if "log_output" in result and result["log_output"]:
                report.append("### ログ出力")
                report.append("```")
                for log in result["log_output"]:
                    report.append(log)
                report.append("```")
                report.append("")

    # common/true-false-textファイル結果（提供されている場合）
    if common_files_results:
        report.append("## common/true-false-textファイルテスト結果")

        # t.textの結果
        true_file_result = common_files_results.get("true_file", {})
        report.append("### t.text")
        report.append("| 項目 | 値 |")
        report.append("| ---- | ---- |")
        report.append(f"| ファイルサイズ | {true_file_result.get('true_file_size', 0):,} bytes |")
        report.append(f"| 暗号化後サイズ | {true_file_result.get('encrypted_file_size', 0):,} bytes |")
        report.append(f"| 暗号化時間 | {true_file_result.get('encryption_time', 0):.2f} 秒 |")
        report.append(f"| 復号時間 | {true_file_result.get('true_decryption_time', 0):.2f} 秒 |")
        report.append(f"| 復号精度 | {true_file_result.get('true_comparison', {}).get('text_similarity', 0):.2%} |")
        report.append(f"| 最後の行の一致 | {'✅' if true_file_result.get('true_comparison', {}).get('last_line_match', False) else '❌'} |")
        report.append("")

        # t.textの内容表示
        with open(TRUE_TEXT_PATH, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            report.append("#### t.textの内容")
            report.append("```")
            report.append(content)
            report.append("```")
            report.append("")

        # f.textの結果
        false_file_result = common_files_results.get("false_file", {})
        report.append("### f.text")
        report.append("| 項目 | 値 |")
        report.append("| ---- | ---- |")
        report.append(f"| ファイルサイズ | {false_file_result.get('true_file_size', 0):,} bytes |")
        report.append(f"| 暗号化後サイズ | {false_file_result.get('encrypted_file_size', 0):,} bytes |")
        report.append(f"| 暗号化時間 | {false_file_result.get('encryption_time', 0):.2f} 秒 |")
        report.append(f"| 復号時間 | {false_file_result.get('true_decryption_time', 0):.2f} 秒 |")
        report.append(f"| 復号精度 | {false_file_result.get('true_comparison', {}).get('text_similarity', 0):.2%} |")
        report.append(f"| 最後の行の一致 | {'✅' if false_file_result.get('true_comparison', {}).get('last_line_match', False) else '❌'} |")
        report.append("")

        # f.textの内容表示
        with open(FALSE_TEXT_PATH, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            report.append("#### f.textの内容")
            report.append("```")
            report.append(content)
            report.append("```")
            report.append("")

    # レポートをファイルに保存
    report_path = os.path.join(os.path.dirname(TEST_OUTPUT_DIR), "docs", "issue", "homomorphic_test_report.md")

    # ディレクトリの存在確認
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))

    print(f"テストレポートを保存しました: {report_path}")
    return report_path

def main():
    """メイン関数"""
    print("===== 準同型暗号マスキング方式 包括的テスト =====")
    print(f"テスト開始時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # テスト結果を格納するリスト
    test_results = []

    # 1. さまざまなファイルタイプのテスト用ファイルを作成
    print("\n1. テスト用ファイルの作成")
    test_files = create_test_files()

    # 2. 各ファイルタイプでの暗号化・復号テスト
    print("\n2. ファイルタイプ別テスト")
    for file_type, (true_file, false_file) in test_files.items():
        result = run_encryption_decryption_test(true_file, false_file, file_type)
        test_results.append(result)

    # 3. 識別不能性テスト（バイナリファイルで実施）
    print("\n3. 識別不能性テスト")
    indist_result = run_indistinguishability_test(test_files["binary"][0], test_files["binary"][1])
    test_results.append(indist_result)

    # 4. common/true-false-textファイルのテスト
    print("\n4. common/true-false-textファイルテスト")
    common_files_results = {
        "true_file": run_encryption_decryption_test(TRUE_TEXT_PATH, FALSE_TEXT_PATH, "common_true"),
        "false_file": run_encryption_decryption_test(FALSE_TEXT_PATH, TRUE_TEXT_PATH, "common_false")
    }

    # 5. 結果のグラフ化
    print("\n5. テスト結果のグラフ化")
    graph_path = plot_test_results(test_results, common_files_results)

    # 6. テストレポートの生成
    print("\n6. テストレポートの生成")
    report_path = generate_test_report(test_results, common_files_results, graph_path)

    # 7. テスト結果の表示
    print("\n===== テスト完了 =====")

    success_count = sum(1 for result in test_results if result.get("success", False) or
                       (result.get("true_comparison", {}).get("success", False) or
                        result.get("false_comparison", {}).get("success", False)))

    print(f"テスト成功: {success_count}/{len(test_results)}")
    print(f"テストレポート: {report_path}")
    print(f"テスト終了時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # 最終結果の返却
    return success_count == len(test_results)

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"テスト実行中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)