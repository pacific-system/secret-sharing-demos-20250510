#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
復号処理のテストスクリプト
"""

import os
import sys
import json
import base64
import hashlib
from typing import Dict, Any

# 親ディレクトリをインポートパスに追加
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.abspath(os.path.join(parent_dir, '..')))

from method_8_homomorphic.homomorphic import PaillierCrypto
from method_8_homomorphic.crypto_mask import MaskFunctionGenerator
from method_8_homomorphic.key_analyzer import analyze_key_type, extract_seed_from_key
from method_8_homomorphic.crypto_adapters import process_data_after_decryption

def test_decrypt():
    """
    復号処理の基本テスト
    """
    test_dir = os.path.join(os.path.dirname(__file__), '..', 'test_output')
    os.makedirs(test_dir, exist_ok=True)

    # テスト用の暗号化ファイル
    encrypted_file = os.path.join(test_dir, 'encrypted2.hmc')

    # テスト用の鍵
    test_key = "fc66f1a401520d52bc4feca298ea2515326bfbcf440e1f7af05313d9bcab81f4"
    key_bytes = bytes.fromhex(test_key)

    print(f"テスト鍵: {test_key}")

    # 鍵の解析
    key_type = analyze_key_type(key_bytes)
    print(f"鍵の解析結果: {key_type}")

    # 暗号化ファイルを読み込み
    try:
        with open(encrypted_file, 'r') as f:
            encrypted_data = json.load(f)
        print(f"暗号化ファイルを読み込みました: {encrypted_file}")
    except Exception as e:
        print(f"エラー: ファイル読み込みに失敗: {e}")
        return

    # 鍵タイプを上書き
    force_key_type = "true"
    print(f"鍵タイプを強制指定: {force_key_type}")

    # 真偽両方のデータを試す
    for test_key_type in ["true", "false"]:
        print(f"\n===== {test_key_type}鍵でのテスト =====")

        # 公開鍵情報を取得
        public_key_str = encrypted_data.get("public_key", {})
        if not public_key_str:
            print("エラー: 公開鍵情報が見つかりません")
            continue

        # 公開鍵を整数に変換
        public_key = {
            "n": int(public_key_str["n"]),
            "g": int(public_key_str["g"])
        }

        # 準同型暗号システムの初期化
        print("準同型暗号システムを初期化...")
        paillier = PaillierCrypto()
        paillier.public_key = public_key

        # 暗号文とマスク情報を取得
        from method_8_homomorphic.crypto_mask import extract_by_key_type

        # 暗号文とマスク情報の抽出
        chunks, mask_info = extract_by_key_type(encrypted_data, test_key_type)

        if not chunks:
            print(f"エラー: {test_key_type}鍵用のチャンクが見つかりません")
            continue

        print(f"チャンク数: {len(chunks)}")
        print(f"マスク情報: {mask_info}")

        # マスク関数生成器の初期化
        seed = base64.b64decode(mask_info['seed'])
        mask_generator = MaskFunctionGenerator(paillier, seed)

        # マスク関数を除去
        try:
            # 真偽に応じたマスクを生成
            true_mask, false_mask = mask_generator.generate_mask_pair()
            mask = true_mask if test_key_type == "true" else false_mask

            # マスク関数を除去
            print("マスク関数を除去...")
            unmasked_chunks = mask_generator.remove_mask(chunks, mask)

            # 復号
            print("復号中...")
            decrypted_chunks = []
            decrypted_data = bytearray()

            # シードから秘密鍵を生成
            # 注意: これは通常のキー派生とは異なり、テスト用に簡略化
            # 実際のアプリケーションでは適切な鍵の導出が必要
            from sympy import randprime
            from math import gcd

            # シードから乱数生成器を初期化
            import random
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

            # 各チャンクを復号
            for i, chunk in enumerate(unmasked_chunks):
                try:
                    decrypted_int = paillier.decrypt(chunk, private_key)
                    byte_length = (decrypted_int.bit_length() + 7) // 8
                    chunk_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
                    decrypted_chunks.append(chunk_bytes)
                    decrypted_data.extend(chunk_bytes)
                except Exception as e:
                    print(f"チャンク{i}の復号中にエラー: {e}")

            # データタイプ情報を取得
            data_type = encrypted_data.get(f"{test_key_type}_data_type", "auto")

            # 復号データの処理
            try:
                processed_data = process_data_after_decryption(decrypted_data, data_type)
                print(f"データ処理成功: サイズ={len(processed_data)}バイト")

                # 結果を出力
                output_file = os.path.join(test_dir, f"decrypted_{test_key_type}_test.txt")
                mode = 'w' if isinstance(processed_data, str) else 'wb'
                with open(output_file, mode) as f:
                    f.write(processed_data)
                print(f"復号結果を保存: {output_file}")

                # 内容確認
                if isinstance(processed_data, str):
                    print(f"復号されたテキスト: {processed_data[:100]}")
                else:
                    print(f"復号されたバイナリ (先頭30バイト): {processed_data[:30]}")

            except Exception as e:
                print(f"データ処理中にエラー: {e}")

        except Exception as e:
            print(f"マスク除去または復号中にエラー: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_decrypt()