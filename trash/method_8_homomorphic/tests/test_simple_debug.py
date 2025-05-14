#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の簡易デバッグスクリプト
"""

import os
import sys
import json
import base64
import hashlib
import tempfile
import time
import random
import string
import subprocess
from typing import Dict, Tuple, List, Any, Optional, Union

from method_8_homomorphic.homomorphic import PaillierCrypto
from method_8_homomorphic.crypto_mask import MaskFunctionGenerator
from method_8_homomorphic.crypto_adapters import (
    DataAdapter, TextAdapter, BinaryAdapter, JSONAdapter, Base64Adapter,
    process_data_for_encryption, process_data_after_decryption
)

def run_command(cmd, cwd=None):
    """コマンドを実行"""
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=cwd, universal_newlines=True
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr

def test_simple():
    """簡単なテスト"""
    # テスト設定
    test_file = "test_simple.txt"
    encrypted_file = "test_simple.hmc"
    decrypted_file = "test_simple_decrypted.txt"

    # テストファイルの作成
    with open(test_file, "w") as f:
        f.write("テスト文字列")

    print(f"テストファイルを作成しました: {test_file}")

    # 暗号化
    print("\n=== 暗号化実行 ===")
    cmd = [sys.executable, "-m", "method_8_homomorphic.encrypt",
           "--true-file", test_file, "-o", encrypted_file, "--save-keys", "--verbose"]
    returncode, stdout, stderr = run_command(cmd)

    print(f"暗号化実行結果: {returncode}")
    print(f"標準出力:\n{stdout}")
    if stderr:
        print(f"標準エラー出力:\n{stderr}")

    # 暗号化ファイルの確認
    if os.path.exists(encrypted_file):
        print(f"\n=== 暗号化ファイル確認 ===")
        with open(encrypted_file, "r") as f:
            encrypted_data = json.load(f)

        # 暗号文データの概要表示
        print(f"暗号文データキー: {list(encrypted_data.keys())}")
        print(f"フォーマット: {encrypted_data.get('format')}")
        print(f"バージョン: {encrypted_data.get('version')}")
        print(f"真チャンク数: {len(encrypted_data.get('true_chunks', []))}")
        print(f"偽チャンク数: {len(encrypted_data.get('false_chunks', []))}")

        # マスク情報
        print(f"真マスク: {encrypted_data.get('true_mask')}")
        print(f"偽マスク: {encrypted_data.get('false_mask')}")

        # 公開鍵情報
        if 'public_key' in encrypted_data:
            print(f"公開鍵情報あり: {type(encrypted_data['public_key'])}")
        else:
            print("公開鍵情報なし")

    # 暗号化鍵の取得
    key_file = "keys/encryption_key.bin"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key_data = f.read()
        print(f"\n鍵ファイル: {key_file}")
        print(f"鍵データ長: {len(key_data)} バイト")
        print(f"鍵16進データ: {key_data.hex()}")

    # 内部的にマスク関数を生成
    print("\n=== 内部マスク関数テスト ===")
    try:
        if os.path.exists(encrypted_file):
            with open(encrypted_file, "r") as f:
                encrypted_data = json.load(f)

            # 暗号文と関連データの抽出
            key_type = "true"  # true または false
            chunks = [int(chunk, 16) for chunk in encrypted_data.get(f"{key_type}_chunks", [])]
            mask_info = encrypted_data.get(f"{key_type}_mask", {})
            public_key_info = encrypted_data.get("public_key", {})

            print(f"使用する鍵タイプ: {key_type}")
            print(f"チャンク数: {len(chunks)}")
            if len(chunks) > 0:
                print(f"先頭チャンク: {hex(chunks[0])[:100]}...")
            print(f"マスク情報: {mask_info}")

            # 準同型暗号システムの初期化
            paillier = PaillierCrypto()

            # 公開鍵情報の復元
            if public_key_info:
                public_key = {
                    "n": int(public_key_info["n"]),
                    "g": int(public_key_info["g"])
                }
                paillier.public_key = public_key
                print(f"公開鍵を設定: n={public_key['n']}, g={public_key['g']}")

                # ダミー秘密鍵
                paillier.private_key = {
                    "lambda": 0,
                    "mu": 1,
                    "p": 0,
                    "q": 0,
                    "n": public_key["n"]
                }

            # マスク情報からシードを取得
            if mask_info.get("seed"):
                seed = base64.b64decode(mask_info["seed"])
                print(f"シード: {seed.hex()}")

                # マスク関数生成
                mask_generator = MaskFunctionGenerator(paillier, seed)
                true_mask, false_mask = mask_generator.generate_mask_pair()
                mask = true_mask if key_type == "true" else false_mask

                print(f"生成された{key_type}マスク: {mask}")

                # マスク除去テスト
                try:
                    unmasked_chunks = mask_generator.remove_mask(chunks, mask)
                    print(f"マスク除去成功: チャンク数={len(unmasked_chunks)}")
                    if len(unmasked_chunks) > 0:
                        print(f"マスク除去後先頭チャンク: {hex(unmasked_chunks[0])[:100]}...")

                    # テスト復号
                    if len(unmasked_chunks) > 0:
                        # 鍵なしで復号はできないが、テスト用のダミー秘密鍵を使用
                        try:
                            print(f"テスト用ダミー復号試行...")
                            # ここでは正確な復号はできない
                        except Exception as e:
                            print(f"予測された復号エラー: {e}")
                except Exception as e:
                    print(f"マスク除去エラー: {e}")
            else:
                print(f"マスク情報にシードがありません")
    except Exception as e:
        print(f"内部テストエラー: {e}")
        import traceback
        traceback.print_exc()

    # 復号
    print("\n=== 復号実行 ===")
    cmd = [sys.executable, "-m", "method_8_homomorphic.decrypt",
           encrypted_file, "--key", key_file, "-o", decrypted_file, "--verbose"]
    returncode, stdout, stderr = run_command(cmd)

    print(f"復号実行結果: {returncode}")
    print(f"標準出力:\n{stdout}")
    if stderr:
        print(f"標準エラー出力:\n{stderr}")

    # 復号ファイルの確認
    if os.path.exists(decrypted_file):
        print(f"\n=== 復号ファイル確認 ===")
        try:
            with open(decrypted_file, "r") as f:
                decrypted_content = f.read()
            print(f"復号ファイルサイズ: {os.path.getsize(decrypted_file)} バイト")
            print(f"復号内容: {decrypted_content}")

            # 元のファイルと比較
            with open(test_file, "r") as f:
                original_content = f.read()

            if decrypted_content == original_content:
                print("結果: 復号成功 - 元のファイルと一致しています")
            else:
                print("結果: 復号失敗 - 元のファイルと一致しません")
                print(f"元のファイル: {original_content}")
                print(f"復号ファイル: {decrypted_content}")
        except Exception as e:
            print(f"復号ファイル確認エラー: {e}")
    else:
        print(f"復号ファイルが存在しません: {decrypted_file}")

if __name__ == "__main__":
    test_simple()