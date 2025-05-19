#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
修正版復号スクリプト

暗号化ファイルからtrue_chunksまたはfalse_chunksを明示的に取得します。
"""

import os
import sys
import json
import base64
import hashlib
import time
import random
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
    parser = argparse.ArgumentParser(description='修正版復号スクリプト')
    parser.add_argument('input_file', help='暗号化ファイルパス')
    parser.add_argument('--key', '-k', required=True, help='鍵ファイルパス')
    parser.add_argument('--output', '-o', help='出力ファイルパス')
    parser.add_argument('--use-false', action='store_true', help='falseチャンクを使用する')

    args = parser.parse_args()

    # デバッグフラグ
    verbose = True

    # 鍵ファイルの読み込み
    with open(args.key, 'r') as f:
        key_text = f.read().strip()

    # 鍵をバイト列に変換
    key_bytes = bytes.fromhex(key_text)

    print(f"鍵を読み込みました: {len(key_bytes)} バイト, {key_text[:10]}...")

    # 暗号化ファイルの読み込み
    try:
        with open(args.input_file, 'r') as f:
            encrypted_data = json.load(f)
    except json.JSONDecodeError:
        print(f"JSONデコードエラー: {args.input_file}")
        sys.exit(1)

    # ファイルキーの確認
    print(f"ファイルキー: {list(encrypted_data.keys())}")

    # チャンクの取得
    true_chunks = encrypted_data.get('true_chunks', [])
    false_chunks = encrypted_data.get('false_chunks', [])

    # どちらのチャンクを使用するか選択
    if args.use_false:
        chunks_to_use = false_chunks
        key_type = 'false'
    else:
        chunks_to_use = true_chunks
        key_type = 'true'

    print(f"trueチャンク: {len(true_chunks)}個")
    print(f"falseチャンク: {len(false_chunks)}個")
    print(f"使用するチャンク: {key_type}, {len(chunks_to_use)}個")

    if len(chunks_to_use) == 0:
        print("チャンクが空のため処理を終了します")
        sys.exit(1)

    # Paillier暗号の初期化
    paillier = PaillierCrypto()

    # 公開鍵・秘密鍵のシード値を設定
    seed = hashlib.sha256(key_bytes).digest()
    seed_int = int.from_bytes(seed, 'big')

    # 鍵ペアを生成
    random.seed(seed_int)
    public_key, private_key = paillier.generate_keys()

    print(f"鍵ペアを生成しました: モジュラス={public_key['n']}")

    # バッファサイズ
    chunk_size = 256

    # 各チャンクを復号
    decrypted_chunks = []

    for i, chunk in enumerate(chunks_to_use):
        try:
            if verbose:
                print(f"チャンク {i+1}/{len(chunks_to_use)} を処理中...")

            # 整数として解釈
            if isinstance(chunk, str):
                if chunk.startswith('0x'):
                    chunk_int = int(chunk, 16)
                else:
                    chunk_int = int(chunk)
            else:
                chunk_int = chunk

            # チャンクを復号
            decrypted_value = paillier.decrypt(chunk_int, private_key)

            if verbose and i == 0:
                print(f"復号結果: {decrypted_value}")

            # バイト列に変換
            try:
                # ビット長を計算
                bit_length = decrypted_value.bit_length()
                byte_length = (bit_length + 7) // 8

                # バイト長が0の場合（0の場合）
                if byte_length == 0:
                    decrypted_bytes = b'\x00' * chunk_size
                else:
                    # できるだけ多くの情報を保持するために十分なバッファを確保
                    buffer_length = max(byte_length, chunk_size)

                    # 整数をバイト列に変換
                    try:
                        bytes_value = decrypted_value.to_bytes(buffer_length, byteorder='big')

                        # サイズ調整
                        if len(bytes_value) > chunk_size:
                            # 末尾のchunk_sizeバイトを取得
                            decrypted_bytes = bytes_value[-chunk_size:]
                        else:
                            # 右詰めでパディング
                            decrypted_bytes = bytes_value.rjust(chunk_size, b'\x00')

                    except (OverflowError, ValueError) as e:
                        print(f"バイト変換エラー: {e}")
                        # エラー時は0パディング
                        decrypted_bytes = b'\x00' * chunk_size

                if verbose and i == 0:
                    print(f"バイト変換: {byte_length}バイト→{len(decrypted_bytes)}バイト")
                    if len(decrypted_bytes) > 0:
                        print(f"先頭バイト: {decrypted_bytes[:min(20, len(decrypted_bytes))]}")

            except Exception as e:
                print(f"バイト変換エラー: {e}")
                decrypted_bytes = b'\x00' * chunk_size

            decrypted_chunks.append(decrypted_bytes)

        except Exception as e:
            print(f"復号エラー: {e}")
            import traceback
            traceback.print_exc()

            # エラー時は0パディング
            decrypted_chunks.append(b'\x00' * chunk_size)

    # すべてのチャンクを結合
    decrypted_data = b''.join(decrypted_chunks)

    # 先頭のNULLバイトを削除
    decrypted_data = decrypted_data.lstrip(b'\x00')

    print(f"復号データサイズ: {len(decrypted_data)}バイト")
    if len(decrypted_data) > 0:
        print(f"復号データ先頭: {decrypted_data[:min(30, len(decrypted_data))]}")

    # マーカーの検出
    marker_patterns = {
        b"TEXT:UTF8:": "text",
        b"JSON:UTF8:": "json",
        b"CSV:UTF8:": "csv",
        b"TEXT:": "text",
        b"JSON:": "json",
        b"CSV:": "csv",
        b"BINARY:": "binary"
    }

    # デフォルトデータタイプ
    data_type = "text"

    # マーカーの検出
    for marker, marker_type in marker_patterns.items():
        if decrypted_data.startswith(marker):
            data_type = marker_type
            print(f"マーカー '{marker.decode('ascii', errors='replace')}' を検出: タイプ={data_type}")
            break

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
        try:
            if isinstance(processed_data, str):
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(processed_data)
            else:
                with open(args.output, 'wb') as f:
                    f.write(processed_data)
            print(f"\n復号結果を保存しました: {args.output}")
        except Exception as e:
            print(f"ファイル保存エラー: {e}")

if __name__ == "__main__":
    main()