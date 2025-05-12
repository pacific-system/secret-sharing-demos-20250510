#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
最終テスト - テキストデータの暗号化と復号
"""

import os
import sys
import json
import base64
import hashlib
import time
from typing import Dict, Any, List, Union

# 親ディレクトリをインポートパスに追加
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.abspath(os.path.join(parent_dir, '..')))

from method_8_homomorphic.crypto_adapters import (
    TextAdapter, process_data_for_encryption, process_data_after_decryption
)

def test_direct_text_processing():
    """
    テキストデータの処理を直接テスト
    """
    test_dir = os.path.join(os.path.dirname(__file__), '..', 'test_output')
    os.makedirs(test_dir, exist_ok=True)

    # テスト用のテキストデータ
    test_text = "これはテスト用のテキストです。日本語文字列も含みます。Special characters: !@#$%^&*()"
    test_bytes = test_text.encode('utf-8')

    print(f"テスト入力テキスト: {test_text}")
    print(f"テストバイト列 ({len(test_bytes)}バイト): {test_bytes[:30]}...")

    # テキストアダプタを使用した直接テスト
    print("\n===== TextAdapterの直接テスト =====")

    # エンコード
    print("--- エンコード処理 ---")
    text_adapter = TextAdapter()

    # 多段エンコーディングを適用
    encoded_bytes = text_adapter.apply_multi_stage_encoding(test_text)
    print(f"多段エンコード結果 ({len(encoded_bytes)}バイト): {encoded_bytes[:50]}...")

    # デコード
    print("\n--- デコード処理 ---")
    try:
        decoded_text = text_adapter.reverse_multi_stage_encoding(encoded_bytes)
        print(f"多段デコード結果 ({len(decoded_text)}文字): {decoded_text}")

        # 結果の検証
        if decoded_text == test_text:
            print("✅ テスト成功: 元のテキストと復元テキストが一致")
        else:
            print("❌ テスト失敗: テキストが一致しません")
            print(f"元のテキスト ({len(test_text)}文字): {test_text}")
            print(f"復元テキスト ({len(decoded_text)}文字): {decoded_text}")
    except Exception as e:
        print(f"❌ デコード中にエラーが発生: {e}")

    # process_data関数のテスト
    print("\n===== process_data関数のテスト =====")

    # エンコード
    print("--- 暗号化前処理 ---")
    processed_data, data_type = process_data_for_encryption(test_bytes, force_type='text')
    print(f"処理後データ ({len(processed_data)}バイト): {processed_data[:50]}...")
    print(f"データタイプ: {data_type}")

    # デコード
    print("\n--- 復号後処理 ---")
    try:
        result = process_data_after_decryption(processed_data, data_type)
        print(f"復元結果の型: {type(result)}")

        if isinstance(result, str):
            print(f"復元テキスト ({len(result)}文字): {result}")
            # 結果の検証
            if result == test_text:
                print("✅ テスト成功: 元のテキストと復元テキストが一致")
            else:
                print("❌ テスト失敗: テキストが一致しません")
                print(f"元のテキスト ({len(test_text)}文字): {test_text}")
                print(f"復元テキスト ({len(result)}文字): {result}")
        else:
            print(f"復元バイナリ ({len(result)}バイト): {result[:50]}...")
            # バイナリからテキストを復元
            for encoding in ['utf-8', 'latin-1', 'shift-jis', 'euc-jp']:
                try:
                    text = result.decode(encoding)
                    print(f"{encoding}でデコード: {text}")
                    if text == test_text:
                        print(f"✅ {encoding}で一致")
                    break
                except UnicodeDecodeError:
                    continue
    except Exception as e:
        print(f"❌ 復号後処理中にエラーが発生: {e}")

    # ファイルに書き込んでテスト
    print("\n===== ファイル処理テスト =====")

    # 入力ファイル作成
    input_file = os.path.join(test_dir, "final_test_input.txt")
    with open(input_file, 'w', encoding='utf-8') as f:
        f.write(test_text)
    print(f"テスト入力ファイル作成: {input_file}")

    # 暗号化コマンド実行
    print("\n--- 暗号化実行 ---")
    encrypt_result = run_encrypt_command(input_file)

    if encrypt_result:
        print("暗号化成功、鍵情報:", encrypt_result)
        encrypted_file = encrypt_result.get('output_file')
        key = encrypt_result.get('key')

        # 復号実行
        print("\n--- 復号実行 ---")
        decrypt_result = run_decrypt_command(encrypted_file, key)

        if decrypt_result and decrypt_result.get('success'):
            # 結果の比較
            output_file = decrypt_result.get('output_file')

            try:
                with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                    decrypted_text = f.read()

                print(f"復号されたテキスト: {decrypted_text}")

                if decrypted_text == test_text:
                    print("✅ テスト成功: 元のテキストと復号テキストが一致")
                else:
                    print("❌ テスト失敗: テキストが一致しません")
                    print(f"元のテキスト ({len(test_text)}文字): {test_text}")
                    print(f"復号テキスト ({len(decrypted_text)}文字): {decrypted_text}")
            except Exception as e:
                print(f"❌ 復号ファイル読み込み中にエラー: {e}")
        else:
            print("❌ 復号失敗:", decrypt_result)
    else:
        print("❌ 暗号化に失敗しました。")

def run_encrypt_command(input_file: str) -> Dict[str, Any]:
    """
    暗号化コマンドを実行

    Args:
        input_file: 暗号化する入力ファイル

    Returns:
        暗号化結果情報（鍵、出力ファイルなど）
    """
    try:
        import subprocess

        # 出力ファイル
        output_file = os.path.join(os.path.dirname(input_file), "final_encrypted.hmc")

        # コマンド実行
        cmd = [
            "python3",
            os.path.join(os.path.dirname(__file__), "..", "encrypt.py"),
            "-t", input_file,
            "-f", os.path.join(os.path.dirname(__file__), "..", "false.text"),
            "-o", output_file,
            "-p", "finaltest123",
            "--verbose",
            "--force-data-type", "text"  # 重要: 強制的にテキストとして処理
        ]

        print(f"コマンド実行: {' '.join(cmd)}")

        # コマンド実行
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            # 成功した場合は出力から鍵情報を抽出
            output = result.stdout
            print(f"暗号化成功: {output}")

            # 鍵情報の抽出
            key_line = next((line for line in output.split('\n') if '鍵（安全に保管してください）' in line), None)
            if key_line:
                key = key_line.split(':', 1)[1].strip()
                return {
                    'success': True,
                    'output_file': output_file,
                    'key': key
                }

            return {
                'success': True,
                'output_file': output_file
            }
        else:
            print(f"暗号化失敗: {result.stderr}")
            return None
    except Exception as e:
        print(f"暗号化コマンド実行中にエラー: {e}")
        return None

def run_decrypt_command(encrypted_file: str, key: str) -> Dict[str, Any]:
    """
    復号コマンドを実行

    Args:
        encrypted_file: 復号する暗号化ファイル
        key: 復号鍵

    Returns:
        復号結果情報
    """
    try:
        import subprocess

        # 出力ファイル
        output_file = os.path.join(os.path.dirname(encrypted_file), "final_decrypted.txt")

        # コマンド実行
        cmd = [
            "python3",
            os.path.join(os.path.dirname(__file__), "..", "decrypt.py"),
            encrypted_file,
            "-k", key,
            "-o", output_file,
            "--verbose",
            "--force-text",
            "--key-type", "true"  # 重要: 明示的に真の鍵と指定
        ]

        print(f"コマンド実行: {' '.join(cmd)}")

        # コマンド実行
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            output = result.stdout
            print(f"復号成功: {output}")
            return {
                'success': True,
                'output_file': output_file
            }
        else:
            print(f"復号失敗: {result.stderr}")
            return {
                'success': False,
                'error': result.stderr
            }
    except Exception as e:
        print(f"復号コマンド実行中にエラー: {e}")
        return {
            'success': False,
            'error': str(e)
        }

if __name__ == "__main__":
    test_direct_text_processing()