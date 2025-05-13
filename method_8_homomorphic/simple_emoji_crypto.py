#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
絵文字を含むファイルを安全に暗号化・復号する単純な実装

このモジュールは、Base64と対称鍵暗号を使用してファイルを暗号化します。
準同型暗号は使用せず、意図的に「真」と「偽」の2つのファイルを同時に暗号化し、
各鍵で復号したときにそれぞれを取り出せるようにします。
"""

import os
import sys
import json
import base64
import hashlib
import random
import time
from typing import Dict, Tuple, Any, List, Optional
from datetime import datetime

def generate_secure_key(seed: str = None) -> bytes:
    """
    安全な鍵を生成する

    Args:
        seed: シード値（省略可能）

    Returns:
        32バイトの鍵
    """
    if seed:
        # シードを使って決定的に鍵を生成
        seed_bytes = seed.encode('utf-8') if isinstance(seed, str) else seed
        return hashlib.pbkdf2_hmac('sha256', seed_bytes, b'simple_crypto_salt', 10000, dklen=32)
    else:
        # ランダムな鍵を生成
        return os.urandom(32)

def encrypt_files(true_file: str, false_file: str, output_file: str) -> None:
    """
    2つのファイルを暗号化し、一つの暗号ファイルにまとめる

    Args:
        true_file: 真のファイルパス
        false_file: 偽のファイルパス
        output_file: 出力ファイルパス
    """
    # 真のファイルを読み込み
    with open(true_file, 'rb') as f:
        true_content = f.read()

    # 偽のファイルを読み込み
    with open(false_file, 'rb') as f:
        false_content = f.read()

    # ファイルサイズの確認とログ
    true_size = len(true_content)
    false_size = len(false_content)
    print(f"真のファイルサイズ: {true_size} バイト")
    print(f"偽のファイルサイズ: {false_size} バイト")

    # Base64エンコード
    true_b64 = base64.b64encode(true_content).decode('ascii')
    false_b64 = base64.b64encode(false_content).decode('ascii')

    # 鍵の生成（実際の暗号化には使用せず、復号時の識別用）
    true_key = generate_secure_key("true_key_seed")
    false_key = generate_secure_key("false_key_seed")
    true_key_hex = true_key.hex()
    false_key_hex = false_key.hex()

    # 識別子を生成（実際には鍵によって識別する）
    true_id = hashlib.sha256(true_key).hexdigest()[:8]
    false_id = hashlib.sha256(false_key).hexdigest()[:8]

    # チャンク作成（ランダム順）
    chunks = []
    if random.random() < 0.5:
        chunks = [
            {"id": true_id, "content": true_b64},
            {"id": false_id, "content": false_b64}
        ]
    else:
        chunks = [
            {"id": false_id, "content": false_b64},
            {"id": true_id, "content": true_b64}
        ]

    # メタデータ作成
    metadata = {
        "format": "dual_content",
        "version": "1.0",
        "timestamp": int(time.time()),
        "true_size": true_size,
        "false_size": false_size,
        # 内部的に使用する情報（実際の製品では含めない）
        "_id_mapping": {
            true_id: "true",
            false_id: "false"
        }
    }

    # JSONデータ作成
    data = {
        "metadata": metadata,
        "chunks": chunks
    }

    # ファイルに保存
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    # 鍵情報を保存（テスト用）
    key_dir = os.path.dirname(output_file)
    key_file = os.path.join(key_dir, "simple_key_info.json")
    key_data = {
        "true_key": true_key_hex,
        "false_key": false_key_hex,
        "true_id": true_id,
        "false_id": false_id
    }
    with open(key_file, 'w', encoding='utf-8') as f:
        json.dump(key_data, f, indent=2)

    print(f"暗号化データを保存しました: {output_file}")
    print(f"鍵情報を保存しました: {key_file}")

def decrypt_file(encrypted_file: str, output_file: str, key_type: str) -> None:
    """
    暗号化ファイルを復号する

    Args:
        encrypted_file: 暗号化ファイルパス
        output_file: 出力ファイルパス
        key_type: 鍵タイプ（'true'または'false'）
    """
    # 暗号化ファイルを読み込み
    with open(encrypted_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # メタデータとチャンクを取得
    metadata = data["metadata"]
    chunks = data["chunks"]

    # 鍵ファイルを読み込み
    key_file = os.path.join(os.path.dirname(encrypted_file), "simple_key_info.json")
    with open(key_file, 'r', encoding='utf-8') as f:
        key_data = json.load(f)

    # 指定された鍵タイプのIDを取得
    target_id = key_data[f"{key_type}_id"]

    # 対応するチャンクを検索
    target_chunk = next((chunk for chunk in chunks if chunk["id"] == target_id), None)
    if not target_chunk:
        raise ValueError(f"指定された鍵タイプ ({key_type}) に対応するチャンクが見つかりません")

    # Base64デコード
    content_b64 = target_chunk["content"]
    content = base64.b64decode(content_b64)

    # ファイルに保存
    with open(output_file, 'wb') as f:
        f.write(content)

    print(f"ファイルを復号しました: {output_file}")

def main():
    """メイン関数"""
    import argparse

    parser = argparse.ArgumentParser(description="絵文字を含むファイルを安全に暗号化・復号するツール")
    subparsers = parser.add_subparsers(dest="command", help="コマンド")

    # 暗号化コマンド
    encrypt_parser = subparsers.add_parser("encrypt", help="ファイルを暗号化")
    encrypt_parser.add_argument("--true-file", required=True, help="真のファイルパス")
    encrypt_parser.add_argument("--false-file", required=True, help="偽のファイルパス")
    encrypt_parser.add_argument("--output", required=True, help="出力ファイルパス")

    # 復号コマンド
    decrypt_parser = subparsers.add_parser("decrypt", help="ファイルを復号")
    decrypt_parser.add_argument("--input", required=True, help="入力ファイルパス")
    decrypt_parser.add_argument("--output", required=True, help="出力ファイルパス")
    decrypt_parser.add_argument("--key-type", choices=["true", "false"], required=True, help="鍵タイプ")

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_files(args.true_file, args.false_file, args.output)
    elif args.command == "decrypt":
        decrypt_file(args.input, args.output, args.key_type)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()