#!/usr/bin/env python3
"""
準同型暗号マスキング方式の暗号化・復号テスト
"""

import os
import sys
import json
import base64
import subprocess
import tempfile
import hashlib
import time
import random
import string
from typing import Dict, Tuple, List, Any, Optional, Union

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

# テスト用ディレクトリの設定
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_output")
os.makedirs(TEST_DIR, exist_ok=True)

def run_command(cmd, cwd=None):
    """
    コマンドを実行してその結果を返す
    """
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=cwd, universal_newlines=True
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr

def create_test_file(filename, content):
    """テストファイルを作成"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    return os.path.abspath(filename)

def create_test_binary_file(filename, size_bytes):
    """バイナリテストファイルを作成"""
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_bytes))
    return os.path.abspath(filename)

def compute_hash(filename):
    """ファイルのSHA-256ハッシュを計算"""
    with open(filename, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash

def check_content(file1, file2):
    """2つのファイルの内容が一致するかチェック"""
    hash1 = compute_hash(file1)
    hash2 = compute_hash(file2)
    return hash1 == hash2, hash1, hash2

def test_encryption_decryption():
    """暗号化と復号のテスト"""
    print("=== 準同型暗号マスキング方式の暗号化・復号テスト ===")

    tests = [
        {"name": "テキストデータ", "type": "text", "size": 100},
        {"name": "バイナリデータ", "type": "binary", "size": 200},
        {"name": "大きなテキスト", "type": "text", "size": 1024},
        {"name": "大きなバイナリ", "type": "binary", "size": 2048},
    ]

    test_results = []

    # 暗号化・復号スクリプトのパス
    encrypt_script = os.path.join(current_dir, "encrypt.py")
    decrypt_script = os.path.join(current_dir, "decrypt.py")

    for i, test in enumerate(tests):
        print(f"\nテスト {i+1}: {test['name']} ({test['type']}, {test['size']}バイト)")

        # テストファイルの作成
        true_filename = os.path.join(TEST_DIR, f"true_{i}.data")
        false_filename = os.path.join(TEST_DIR, f"false_{i}.data")
        encrypted_filename = os.path.join(TEST_DIR, f"encrypted_{i}.hmc")
        decrypted_filename = os.path.join(TEST_DIR, f"decrypted_{i}.data")

        if test["type"] == "text":
            # ランダムなテキストを生成
            chars = string.ascii_letters + string.digits + string.punctuation + " \n\t"
            true_content = ''.join(random.choice(chars) for _ in range(test["size"]))
            false_content = ''.join(random.choice(chars) for _ in range(test["size"] // 2))

            true_file = create_test_file(true_filename, true_content)
            false_file = create_test_file(false_filename, false_content)
        else:
            # ランダムなバイナリデータを生成
            true_file = create_test_binary_file(true_filename, test["size"])
            false_file = create_test_binary_file(false_filename, test["size"] // 2)

        print(f"テストファイル作成: 真={true_file}, 偽={false_file}")

        # --- 暗号化の実行 ---
        print("\n暗号化を実行:")
        encrypt_cmd = [
            "python3", encrypt_script,
            "--true-file", true_file,
            "--false-file", false_file,
            "--output", encrypted_filename,
            "--save-keys",
            "--verbose"
        ]

        encryption_start = time.time()
        ret_code, stdout, stderr = run_command(encrypt_cmd)
        encryption_time = time.time() - encryption_start

        if ret_code != 0:
            print(f"暗号化に失敗しました。エラーコード: {ret_code}")
            print(f"標準出力:\n{stdout}")
            print(f"標準エラー出力:\n{stderr}")
            test_results.append({
                "name": test["name"],
                "result": "failure",
                "stage": "encryption",
                "error": stderr
            })
            continue

        print(f"暗号化成功: 処理時間={encryption_time:.2f}秒")
        print(f"暗号化ファイル: {encrypted_filename}")

        # 暗号化データのサイズを確認
        encrypted_size = os.path.getsize(encrypted_filename)
        original_size = os.path.getsize(true_file)
        size_ratio = encrypted_size / original_size
        print(f"暗号文サイズ: {encrypted_size}バイト (元のデータの{size_ratio:.2f}倍)")

        # 暗号化データの検証
        try:
            with open(encrypted_filename, 'r') as f:
                encrypted_data = json.load(f)
                print(f"暗号化データ形式: {encrypted_data.get('format', 'unknown')}")
                print(f"暗号化バージョン: {encrypted_data.get('version', 'unknown')}")
                print(f"チャンク数: 真={encrypted_data.get('true_chunks', 0)}, 偽={encrypted_data.get('false_chunks', 0)}")

                # 復号用の鍵を抽出
                key = encrypted_data.get('encryption_key', '')
                if not key and 'key' in encrypted_data:
                    key = encrypted_data.get('key', '')
        except (json.JSONDecodeError, UnicodeDecodeError):
            print("暗号化データはJSON形式ではありません")
            key = None

            # keys/encryption_key.binファイルから鍵を読み込む
            key_file = os.path.join(current_dir, "keys", "encryption_key.bin")
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key = f.read().hex()
                print(f"鍵ファイルから鍵を読み込みました: {key[:10]}...")

        # --- 復号化の実行 ---
        print("\n復号を実行:")
        decrypt_cmd = [
            "python3", decrypt_script,
            "--output", decrypted_filename,
            "--key", "keys/encryption_key.bin",  # 鍵ファイルを使用
            "--key-type", "true",  # 真の鍵を使用
            "--verbose",
            encrypted_filename
        ]

        decryption_start = time.time()
        ret_code, stdout, stderr = run_command(decrypt_cmd)
        decryption_time = time.time() - decryption_start

        if ret_code != 0:
            print(f"復号に失敗しました。エラーコード: {ret_code}")
            print(f"標準出力:\n{stdout}")
            print(f"標準エラー出力:\n{stderr}")
            test_results.append({
                "name": test["name"],
                "result": "failure",
                "stage": "decryption",
                "error": stderr
            })
            continue

        print(f"復号成功: 処理時間={decryption_time:.2f}秒")
        print(f"復号ファイル: {decrypted_filename}")

        # 復号データと元のデータを比較
        if os.path.exists(decrypted_filename):
            is_match, original_hash, decrypted_hash = check_content(true_file, decrypted_filename)
            if is_match:
                print("✅ 復号成功: 元のデータと一致しました")
                test_results.append({
                    "name": test["name"],
                    "result": "success",
                    "encryption_time": encryption_time,
                    "decryption_time": decryption_time,
                    "size_ratio": size_ratio
                })
            else:
                print("❌ 復号失敗: 元のデータと一致しませんでした")
                print(f"元のファイルのハッシュ: {original_hash}")
                print(f"復号ファイルのハッシュ: {decrypted_hash}")
                test_results.append({
                    "name": test["name"],
                    "result": "failure",
                    "stage": "verification",
                    "original_hash": original_hash,
                    "decrypted_hash": decrypted_hash
                })
        else:
            print("❌ 復号失敗: 復号ファイルが作成されませんでした")
            test_results.append({
                "name": test["name"],
                "result": "failure",
                "stage": "verification",
                "error": "復号ファイルが存在しません"
            })

    # テスト結果のサマリー
    print("\n=== テスト結果サマリー ===")
    success_count = sum(1 for result in test_results if result["result"] == "success")
    print(f"テスト総数: {len(test_results)}")
    print(f"成功: {success_count}")
    print(f"失敗: {len(test_results) - success_count}")

    if success_count == len(test_results):
        print("\n✅ すべてのテストが成功しました!")
    else:
        print("\n❌ 一部のテストが失敗しました。")

    # 詳細な結果レポートをJSON形式で保存
    report_file = os.path.join(TEST_DIR, "encryption_decryption_test_report.json")
    with open(report_file, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tests": test_results,
            "summary": {
                "total": len(test_results),
                "success": success_count,
                "failure": len(test_results) - success_count
            }
        }, f, indent=2)

    print(f"\nテスト結果レポートを保存しました: {report_file}")

if __name__ == "__main__":
    test_encryption_decryption()