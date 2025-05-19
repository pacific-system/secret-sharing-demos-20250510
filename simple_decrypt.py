#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
シンプルな復号スクリプト

このスクリプトは暗号化ファイルを直接読み込み、復号して結果を表示します。
"""

import os
import sys
import json
import base64
import hashlib
import time
import argparse
from typing import Dict, List, Any, Tuple, Optional, Union

# インポートエラー回避のためパスを追加
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# 同じディレクトリ内のモジュールをインポート
from homomorphic import PaillierCrypto
from crypto_adapters import process_data_after_decryption

def main():
    # デバッグ環境の有効化
    def debug_print(msg):
        """デバッグメッセージを確実に出力する"""
        sys.stdout.write(str(msg) + "\n")
        sys.stdout.flush()

    debug_print("デバッグ出力を開始します")

    parser = argparse.ArgumentParser(description='シンプルな復号スクリプト')
    parser.add_argument('input_file', help='暗号化ファイルパス')
    parser.add_argument('--key', '-k', required=True, help='鍵ファイルパス')
    parser.add_argument('--output', '-o', help='出力ファイルパス')
    parser.add_argument('--verbose', '-v', action='store_true', help='詳細出力')
    parser.add_argument('--use-false', action='store_true', help='falseチャンクを使用する')

    args = parser.parse_args()

    # 鍵ファイルの読み込み
    with open(args.key, 'rb') as f:
        key_data = f.read()

    print(f"鍵を読み込みました: {len(key_data)} バイト")

    # 暗号化ファイルの読み込み
    with open(args.input_file, 'r') as f:
        encrypted_data = json.load(f)

    # ファイルの構造を確認
    print(f"ファイルキー: {list(encrypted_data.keys())}")

    # 暗号文の取得（フォーマットに合わせる）
    true_chunks = encrypted_data.get('true_chunks', [])
    false_chunks = encrypted_data.get('false_chunks', [])

    # チャンク情報の表示
    print(f"trueチャンク: {len(true_chunks)}個")
    print(f"falseチャンク: {len(false_chunks)}個")

    # どのチャンクを使用するか選択
    if args.use_false:
        ciphertexts = false_chunks
        chunk_type = "false"
    else:
        ciphertexts = true_chunks
        chunk_type = "true"

    print(f"{chunk_type}チャンクを使用します")

    # チャンクの中身をデバッグ出力
    if len(ciphertexts) > 0:
        print(f"最初のチャンク: {ciphertexts[0]}")
    else:
        print("チャンクが空です")

    # メタデータ表示
    print(f"メタデータ: {encrypted_data.get('metadata', {})}")
    print(f"true_size: {encrypted_data.get('true_size', 0)}")
    print(f"false_size: {encrypted_data.get('false_size', 0)}")
    print(f"true_original_size: {encrypted_data.get('true_original_size', 0)}")
    print(f"false_original_size: {encrypted_data.get('false_original_size', 0)}")

    # Paillier暗号の初期化
    paillier = PaillierCrypto()

    # 公開鍵・秘密鍵のシード値を設定
    seed = hashlib.sha256(key_data).digest()
    seed_int = int.from_bytes(seed, 'big')

    # 鍵ペアを生成
    import random
    random.seed(seed_int)
    public_key, private_key = paillier.generate_keys()

    print(f"鍵ペアを生成しました: モジュラス={public_key['n']}")

    # 復号処理
    if len(ciphertexts) == 0:
        print("チャンクが空のため処理を終了します")
        return

    decrypted_chunks = []
    chunk_size = 256  # 標準チャンクサイズ

    for i, ct in enumerate(ciphertexts):
        try:
            print(f"チャンク {i+1}/{len(ciphertexts)} を処理中...")
            # チャンクを復号
            pt = paillier.decrypt(ct, private_key)

            print(f"チャンク{i}復号: {pt}")

            # バイト列に変換
            bit_length = pt.bit_length()
            min_bytes = (bit_length + 7) // 8

            try:
                # 整数をバイト列に変換
                if min_bytes == 0:
                    byte_chunk = b'\x00' * chunk_size
                else:
                    # 必要なサイズでバイト列に変換
                    buffer_size = max(min_bytes, chunk_size)
                    byte_chunk = pt.to_bytes(buffer_size, 'big')

                    # サイズ調整
                    if len(byte_chunk) > chunk_size:
                        byte_chunk = byte_chunk[-chunk_size:]
                    elif len(byte_chunk) < chunk_size:
                        byte_chunk = byte_chunk.rjust(chunk_size, b'\x00')

                print(f"バイト変換: {min_bytes}バイト→{len(byte_chunk)}バイト")

            except Exception as e:
                print(f"バイト変換エラー: {e}")
                byte_chunk = b'\x00' * chunk_size

            decrypted_chunks.append(byte_chunk)

        except Exception as e:
            print(f"復号エラー: {e}")
            import traceback
            traceback.print_exc()
            # エラー時は0パディング
            decrypted_chunks.append(b'\x00' * chunk_size)

    # チャンクを結合
    decrypted_data = b''.join(decrypted_chunks)

    # ゼロパディングを削除
    decrypted_data = decrypted_data.lstrip(b'\x00')

    print(f"復号データサイズ: {len(decrypted_data)}バイト")

    # マーカーの検出とデータタイプの判定
    data_type = "text"
    markers = {
        b"TEXT:UTF8:": "text",
        b"JSON:UTF8:": "json",
        b"CSV:UTF8:": "csv",
        b"TEXT:": "text",
        b"JSON:": "json",
        b"CSV:": "csv",
        b"BINARY:": "binary"
    }

    detected_marker = None
    for marker, marker_type in markers.items():
        if decrypted_data.startswith(marker):
            detected_marker = marker
            data_type = marker_type
            print(f"マーカー検出: {marker.decode('ascii', errors='replace')}, タイプ={data_type}")
            break

    print(f"復号データ: {len(decrypted_data)}バイト")
    if len(decrypted_data) > 0:
        print(f"先頭バイト: {decrypted_data[:min(20, len(decrypted_data))]}")

    # データの後処理
    processed_data = process_data_after_decryption(decrypted_data, data_type)

    # 結果の表示
    if isinstance(processed_data, str):
        print("\n--- 復号結果（テキスト） ---")
        print(processed_data)
    else:
        print("\n--- 復号結果（バイナリ） ---")
        print(f"サイズ: {len(processed_data)} バイト")
        if len(processed_data) > 0:
            print(f"先頭20バイト: {processed_data[:20]}")

    # 結果の保存
    if args.output:
        if isinstance(processed_data, str):
            with open(args.output, 'w') as f:
                f.write(processed_data)
        else:
            with open(args.output, 'wb') as f:
                f.write(processed_data)
        print(f"\n復号結果を保存しました: {args.output}")

if __name__ == "__main__":
    main()