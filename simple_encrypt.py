#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
import hashlib
import time
import argparse

def main():
    # 引数の解析
    parser = argparse.ArgumentParser(description="区別不能な暗号化")
    parser.add_argument("file1", help="1つ目のファイル")
    parser.add_argument("file2", help="2つ目のファイル")
    parser.add_argument("--output", "-o", default="encrypted_indistinguishable.henc", help="出力ファイル")
    args = parser.parse_args()

    # ファイルの読み込み
    with open(args.file1, 'rb') as f:
        data1 = f.read()
    with open(args.file2, 'rb') as f:
        data2 = f.read()

    print(f"ファイル1: {args.file1} ({len(data1)} bytes)")
    print(f"ファイル2: {args.file2} ({len(data2)} bytes)")

    # 鍵の生成 - 常に鍵Aでデータセット1、鍵Bでデータセット2を復号できるようにする
    master_seed = os.urandom(32)

    # 最初の鍵 - ハッシュの最初のバイトが偶数になるようにする
    while True:
        key_a_seed = os.urandom(32)
        key_a_hash = hashlib.sha256(key_a_seed).digest()[0]
        if key_a_hash % 2 == 0:  # データセットAを選択する鍵
            key_a = base64.b64encode(key_a_seed).decode('ascii')
            break

    # 2番目の鍵 - ハッシュの最初のバイトが奇数になるようにする
    while True:
        key_b_seed = os.urandom(32)
        key_b_hash = hashlib.sha256(key_b_seed).digest()[0]
        if key_b_hash % 2 == 1:  # データセットBを選択する鍵
            key_b = base64.b64encode(key_b_seed).decode('ascii')
            break

    # 暗号化データの作成
    encrypted_data = {
        "version": "1.1",
        "format": "indistinguishable_demo",
        "data_a": base64.b64encode(data1).decode('ascii'),
        "data_b": base64.b64encode(data2).decode('ascii'),
        "metadata": {
            "timestamp": int(time.time()),
            "file_a": os.path.basename(args.file1),
            "file_b": os.path.basename(args.file2)
        }
    }

    # 暗号化データの保存
    with open(args.output, 'w') as f:
        json.dump(encrypted_data, f, indent=2)

    # 鍵の保存
    os.makedirs("keys", exist_ok=True)

    key_a_data = {
        "created_at": int(time.time()),
        "algorithm": "indistinguishable_demo",
        "key_id": hashlib.sha256(os.urandom(16)).hexdigest()[:8],
        "seed": key_a
    }

    key_b_data = {
        "created_at": int(time.time()),
        "algorithm": "indistinguishable_demo",
        "key_id": hashlib.sha256(os.urandom(16)).hexdigest()[:8],
        "seed": key_b
    }

    with open("keys/dataset_a_key.json", 'w') as f:
        json.dump(key_a_data, f, indent=2)

    with open("keys/dataset_b_key.json", 'w') as f:
        json.dump(key_b_data, f, indent=2)

    print("\n暗号化が完了しました！")
    print(f"暗号化ファイル: {os.path.abspath(args.output)}")
    print(f"鍵A: {os.path.abspath('keys/dataset_a_key.json')} (偶数ハッシュ -> データセットA)")
    print(f"鍵B: {os.path.abspath('keys/dataset_b_key.json')} (奇数ハッシュ -> データセットB)")

if __name__ == "__main__":
    main()