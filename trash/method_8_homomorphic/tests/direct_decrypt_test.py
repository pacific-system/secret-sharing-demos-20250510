#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
より直接的な復号処理のテストスクリプト
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

from method_8_homomorphic.homomorphic import PaillierCrypto
from method_8_homomorphic.crypto_mask import MaskFunctionGenerator, extract_by_key_type
from method_8_homomorphic.key_analyzer import analyze_key_type, extract_seed_from_key
from method_8_homomorphic.crypto_adapters import process_data_after_decryption, TextAdapter, BinaryAdapter

def test_direct_decrypt():
    """
    より直接的な復号処理のテスト
    """
    test_dir = os.path.join(os.path.dirname(__file__), '..', 'test_output')
    os.makedirs(test_dir, exist_ok=True)

    # テスト用の暗号化ファイル
    encrypted_file = os.path.join(test_dir, 'encrypted2.hmc')

    # テスト用のテキストファイル作成
    test_text_file = os.path.join(test_dir, 'test_input.txt')
    test_text = "これはテスト用のテキストです。日本語文字列も含みます。Special characters: !@#$%^&*()"

    with open(test_text_file, 'w', encoding='utf-8') as f:
        f.write(test_text)
    print(f"テスト入力ファイル作成: {test_text_file}")

    # 新しく暗号化を実行
    print("\n===== 新規暗号化の実行 =====")
    encrypt_result = run_encrypt_command(test_text_file)

    if encrypt_result:
        print("暗号化成功、鍵情報:", encrypt_result)
        encrypted_file = encrypt_result.get('output_file')
        key = encrypt_result.get('key')

        # 復号実行
        print("\n===== 復号の実行 =====")
        decrypt_result = run_decrypt_command(encrypted_file, key)

        if decrypt_result and decrypt_result.get('success'):
            # 結果の比較
            output_file = decrypt_result.get('output_file')
            with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                decrypted_text = f.read()

            print(f"復号されたテキスト: {decrypted_text}")

            if decrypted_text == test_text:
                print("テスト成功: 元のテキストと復号テキストが一致")
            else:
                print("テスト失敗: テキストが一致しません")
                print(f"元のテキスト ({len(test_text)}文字): {test_text}")
                print(f"復号テキスト ({len(decrypted_text)}文字): {decrypted_text}")
        else:
            print("復号失敗:", decrypt_result)
    else:
        print("暗号化に失敗しました。既存の暗号化ファイルを使用します。")

        # 直接復号を試みる
        print("\n===== 直接復号処理 =====")
        try:
            # テスト用の鍵（実際の鍵に置き換える）
            test_key = "fc66f1a401520d52bc4feca298ea2515326bfbcf440e1f7af05313d9bcab81f4"
            key_bytes = bytes.fromhex(test_key)

            print(f"テスト鍵: {test_key}")

            # 鍵の解析
            key_type = analyze_key_type(key_bytes)
            print(f"鍵の解析結果: {key_type}")

            # 鍵タイプを上書き（問題のデバッグ用）
            key_type = "true"
            print(f"鍵タイプを強制指定: {key_type}")

            # 暗号化ファイルを読み込み
            with open(encrypted_file, 'r') as f:
                encrypted_data = json.load(f)
            print(f"暗号化ファイルを読み込みました: {encrypted_file}")

            # 公開鍵情報を取得
            public_key_str = encrypted_data.get("public_key", {})
            public_key = {
                "n": int(public_key_str["n"]),
                "g": int(public_key_str["g"])
            }

            # 準同型暗号システムの初期化
            print("準同型暗号システムを初期化...")
            paillier = PaillierCrypto()
            paillier.public_key = public_key

            # 暗号文とマスク情報の抽出
            chunks, mask_info = extract_by_key_type(encrypted_data, key_type)
            print(f"チャンク数: {len(chunks)}")
            print(f"マスク情報: {mask_info}")

            # マスク関数生成器の初期化
            seed = base64.b64decode(mask_info['seed'])
            mask_generator = MaskFunctionGenerator(paillier, seed)

            # マスク関数を除去
            true_mask, false_mask = mask_generator.generate_mask_pair()
            mask = true_mask if key_type == "true" else false_mask

            print("マスク関数を除去中...")
            unmasked_chunks = mask_generator.remove_mask(chunks, mask)
            print(f"マスク除去後のチャンク数: {len(unmasked_chunks)}")

            # 鍵データから秘密鍵を導出
            print("鍵データから秘密鍵を導出中...")
            # シードから秘密鍵を生成
            import random
            from sympy import randprime
            from math import gcd

            # シードから乱数生成器を初期化
            seed_int = int.from_bytes(seed, 'big')
            random.seed(seed_int)

            # 鍵ペア生成
            p = randprime(2**(1024-1), 2**1024)
            q = randprime(2**(1024-1), 2**1024)
            n = p * q
            lambda_val = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
            g = n + 1

            # μの計算
            n_squared = n * n
            g_lambda = pow(g, lambda_val, n_squared)
            l_g_lambda = (g_lambda - 1) // n

            # μの逆元を計算
            from sympy import mod_inverse
            mu = mod_inverse(l_g_lambda, n)

            # 秘密鍵の設定
            private_key = {'lambda': lambda_val, 'mu': mu, 'p': p, 'q': q, 'n': n}
            paillier.private_key = private_key

            # 暗号文を復号
            print("\n復号中...")
            decrypted_data = bytearray()

            for i, chunk in enumerate(unmasked_chunks):
                try:
                    # 復号
                    decrypted_int = paillier.decrypt(chunk, private_key)

                    # バイト列への変換
                    byte_length = (decrypted_int.bit_length() + 7) // 8
                    if byte_length == 0:
                        print(f"警告: チャンク {i} の復号結果が0になりました")
                        chunk_bytes = b''
                    else:
                        chunk_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
                        if i == 0:
                            print(f"復号された先頭チャンク({byte_length}バイト): {chunk_bytes.hex()}")

                    decrypted_data.extend(chunk_bytes)
                except Exception as e:
                    print(f"エラー: チャンク {i} の復号中に問題が発生しました: {e}")

            print(f"復号されたデータ長: {len(decrypted_data)} バイト")

            # データタイプを取得
            current_data_type = encrypted_data.get(f"{key_type}_data_type", "auto")
            print(f"データタイプ: {current_data_type}")

            # テキストデータを強制的に使用
            forced_data_type = "text"
            print(f"強制的なデータタイプ: {forced_data_type}")

            # データの後処理
            try:
                processed_data = process_data_after_decryption(decrypted_data, forced_data_type)
                print(f"データ処理成功: サイズ={len(processed_data)} バイト")
            except Exception as e:
                print(f"警告: データの後処理中にエラーが発生しました: {e}")
                processed_data = decrypted_data

            # 出力ファイル名の決定
            output_path = os.path.join(test_dir, "direct_decrypted_result.txt")

            # テキストファイルの処理
            if isinstance(processed_data, str):
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(processed_data)
                print(f"テキストデータとして保存しました: {output_path}")
                print(f"復号結果: {processed_data[:min(100, len(processed_data))]}")
            else:
                with open(output_path, 'wb') as f:
                    f.write(processed_data)
                print(f"バイナリデータとして保存しました: {output_path}")

                # バイナリをテキストに変換してみる
                text_adapter = TextAdapter()
                try:
                    for encoding in ['utf-8', 'latin-1', 'shift-jis', 'euc-jp']:
                        try:
                            decoded_text = processed_data.decode(encoding)
                            print(f"{encoding}でデコードしました: {decoded_text[:min(100, len(decoded_text))]}")
                            break
                        except UnicodeDecodeError:
                            continue
                except Exception as e:
                    print(f"テキスト変換エラー: {e}")

        except Exception as e:
            print(f"直接復号中にエラーが発生しました: {e}")
            import traceback
            traceback.print_exc()

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
        output_file = os.path.join(os.path.dirname(input_file), "direct_encrypted.hmc")

        # コマンド実行
        cmd = [
            "python3",
            os.path.join(os.path.dirname(__file__), "..", "encrypt.py"),
            "-t", input_file,
            "-f", os.path.join(os.path.dirname(__file__), "..", "false.text"),
            "-o", output_file,
            "-p", "directtest123",
            "--verbose"
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
        output_file = os.path.join(os.path.dirname(encrypted_file), "direct_decrypted.txt")

        # コマンド実行
        cmd = [
            "python3",
            os.path.join(os.path.dirname(__file__), "..", "decrypt.py"),
            encrypted_file,
            "-k", key,
            "-o", output_file,
            "--verbose",
            "--force-text"
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
    test_direct_decrypt()