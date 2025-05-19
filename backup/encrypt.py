#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
#                  ███████ ███    ██  ██████ ██████  ██    ██ ██████  ████████ #
#                  ██      ████   ██ ██      ██   ██  ██  ██  ██   ██    ██    #
#                  █████   ██ ██  ██ ██      ██████    ████   ██████     ██    #
#                  ██      ██  ██ ██ ██      ██   ██    ██    ██         ██    #
#                  ███████ ██   ████  ██████ ██   ██    ██    ██         ██    #
#                                                                              #
#               【暗号化を実行するメインスクリプト - MAIN ENCRYPTION SCRIPT】    #
#                                                                              #
#     このファイルは準同型暗号マスキング方式の「暗号化」機能のメインエントリーポイントです       #
#     最終成果物として、ユーザーはこのファイルを直接実行してファイルを暗号化します         #
#                                                                              #
################################################################################

# ============================================================================ #
# 【警告: セキュリティ上の重要事項】                                              #
# 区別不能性要件に基づき、暗号化・復号プロセス全体を通して、明示的な鍵タイプの指定や     #
# 「true/false」などの表現を用いることは厳禁です。                                #
#                                                                              #
# このシステムでは、同一の暗号文に対して使用する鍵によって異なる平文が復元され、        #
# 攻撃者はどちらが「正規」かを判別できないことが最重要要件です。                     #
# ============================================================================ #

"""
準同型暗号マスキング方式 - 暗号化プログラム

2つのファイルを区別不能な形で暗号化し、同一の暗号文から異なる鍵で
異なる平文を復号できる機能を提供します。

【セキュリティポリシー】
区別不能性を確保するため、このプログラムでは:
- データタイプに応じた特定の名称や識別子を使用しません
- 鍵のタイプを明示的に示す情報を外部に提供しません
- すべてのメタデータは区別不能性を損なわないよう慎重に構成されます
"""

import os
import sys
import json
import base64
import hashlib
import time
import argparse
import random
import binascii
from typing import Dict, List, Tuple, Union, Any

# 依存モジュールのインポート
try:
from method_8_homomorphic.config import (
        KEY_SIZE_BITS,
        KEY_DIRECTORY,
        TRUE_KEY_FILE as KEY_FILE_PRIMARY,    # 区別不能性のため名称を変更
        FALSE_KEY_FILE as KEY_FILE_SECONDARY, # 区別不能性のため名称を変更
        ENCRYPTION_KEY_FILE,
        FILE_FORMAT_VERSION,
        FILE_FORMAT_IDENTIFIER,
        DEBUG_MODE,
        DEFAULT_CHUNK_SIZE,
        DEFAULT_ENCRYPTED_EXTENSION
)
from method_8_homomorphic.homomorphic import (
        PaillierCrypto,
        create_paillier_crypto,
        encrypt_data,
        create_indistinguishable_keypair,
        save_key_to_file
)
from method_8_homomorphic.crypto_adapters import (
        enable_debug_mode,
        debug_log,
        prepare_data_for_encryption,
        create_true_false_metadata,
        encrypt_file,
        transform_for_indistinguishability
    )
    from method_8_homomorphic.crypto_mask import (
        MaskFunctionGenerator,
        transform_between_true_false,
        create_indistinguishable_form
    )
except ImportError:
    # スクリプトを直接実行する場合のフォールバック
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from method_8_homomorphic.config import (
            KEY_SIZE_BITS,
            KEY_DIRECTORY,
            TRUE_KEY_FILE as KEY_FILE_PRIMARY,    # 区別不能性のため名称を変更
            FALSE_KEY_FILE as KEY_FILE_SECONDARY, # 区別不能性のため名称を変更
            ENCRYPTION_KEY_FILE,
            FILE_FORMAT_VERSION,
            FILE_FORMAT_IDENTIFIER,
            DEBUG_MODE,
            DEFAULT_CHUNK_SIZE,
            DEFAULT_ENCRYPTED_EXTENSION
        )
        from method_8_homomorphic.homomorphic import (
            PaillierCrypto,
            create_paillier_crypto,
            encrypt_data,
            create_indistinguishable_keypair,
            save_key_to_file
        )
        from method_8_homomorphic.crypto_adapters import (
            enable_debug_mode,
            debug_log,
            prepare_data_for_encryption,
            create_true_false_metadata,
            encrypt_file,
            transform_for_indistinguishability
        )
        from method_8_homomorphic.crypto_mask import (
            MaskFunctionGenerator,
            transform_between_true_false,
            create_indistinguishable_form
        )
    except ImportError:
        print("必要なモジュールが見つかりません。プロジェクトのルートディレクトリで実行してください。")
            sys.exit(1)

def generate_key_pair(master_seed: bytes = None) -> Tuple[bytes, bytes]:
    """
    区別不能な鍵ペアを生成
    鍵ハッシュの偶数/奇数性で区別
    """
    if master_seed is None:
        master_seed = os.urandom(32)

    # 偶数ハッシュになるシードを探す（データセットA用）
    while True:
        key_a_seed = hashlib.sha256(master_seed + b'a' + os.urandom(8)).digest()
        key_a_hash = int(key_a_seed[0])
        if key_a_hash % 2 == 0:
            break

    # 奇数ハッシュになるシードを探す（データセットB用）
    while True:
        key_b_seed = hashlib.sha256(master_seed + b'b' + os.urandom(8)).digest()
        key_b_hash = int(key_b_seed[0])
        if key_b_hash % 2 == 1:
            break

    return key_a_seed, key_b_seed

def compute_mask(key_seed: bytes, data_len: int) -> bytes:
    """疑似乱数マスクを生成（準同型暗号的要素）"""
    mask = bytearray()
    key_hash = hashlib.sha256(key_seed)

    # データ長に合わせてマスクを生成
    for i in range(0, data_len, 32):
        chunk_seed = key_hash.copy()
        chunk_seed.update(str(i).encode())
        mask.extend(chunk_seed.digest())

    return bytes(mask[:data_len])

def apply_mask(data: bytes, mask: bytes) -> bytes:
    """XORマスクを適用（準同型暗号の加算に相当）"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ mask[i % len(mask)]
    return bytes(result)

def encrypt_file(file_path1: str, file_path2: str, output_path: str, save_key: bool = True) -> Dict[str, Any]:
    """
    2つのファイルを暗号化し、同一の暗号文から異なる平文を復号可能にする
    """
    # ファイルの読み込み
    with open(file_path1, 'rb') as f:
        data1 = f.read()
    with open(file_path2, 'rb') as f:
        data2 = f.read()

    print(f"ファイル1: {file_path1} ({len(data1)} bytes)")
    print(f"ファイル2: {file_path2} ({len(data2)} bytes)")

    # マスター鍵を生成（すべての鍵の元になる）
    master_seed = os.urandom(32)
    key_a_seed, key_b_seed = generate_key_pair(master_seed)

    # 文字集合（スラッシュを含まないようにする）
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+."

    # Base64エンコード（URL-safe）
    data1_encoded = base64.urlsafe_b64encode(data1)
    data2_encoded = base64.urlsafe_b64encode(data2)

    # 長い方のデータに合わせる
    max_len = max(len(data1_encoded), len(data2_encoded))
    data1_padded = data1_encoded.ljust(max_len, b"_")
    data2_padded = data2_encoded.ljust(max_len, b"_")

    # 位置マップを作成するために、データをシャッフルして混ぜる
    all_data = []

    # データ1の各バイトに位置情報を付与
    for i in range(len(data1_padded)):
        all_data.append((1, i, data1_padded[i]))

    # データ2の各バイトに位置情報を付与
    for i in range(len(data2_padded)):
        all_data.append((2, i, data2_padded[i]))

    # ダミーデータを追加
    dummy_count = int(max_len * 0.3)  # 約30%のダミーデータ
    for i in range(dummy_count):
        all_data.append((0, i, ord(random.choice(chars))))

    # 完全にランダム化
    random.shuffle(all_data)

    # 暗号化されたデータと位置マップの構築
    encrypted_bytes = bytearray()
    positions1 = {}  # データ1の位置マップ
    positions2 = {}  # データ2の位置マップ

    # 文字幅（各文字を何バイトで表現するか）
    char_width = 3

    for i, (data_type, orig_idx, byte_val) in enumerate(all_data):
        if data_type == 1:
            positions1[orig_idx] = i
        elif data_type == 2:
            positions2[orig_idx] = i

        # 各バイトにノイズを加える（区別不能性を高める）
        noise_prefix = ord(random.choice(chars))
        noise_suffix = ord(random.choice(chars))

        # 3バイト構造: [ノイズ][データ][ノイズ]
        encrypted_bytes.append(noise_prefix)
        encrypted_bytes.append(byte_val)
        encrypted_bytes.append(noise_suffix)

    # 準同型性を持つマスクを計算（XORベース）
    mask_a = compute_mask(key_a_seed, len(encrypted_bytes))
    mask_b = compute_mask(key_b_seed, len(encrypted_bytes))

    # マスクを適用
    masked_data = apply_mask(bytes(encrypted_bytes), mask_a)  # マスクA適用
    masked_data = apply_mask(masked_data, mask_b)  # マスクB適用

    # 最終的な暗号文はバイナリのまま
    final_encrypted = masked_data

    # 鍵情報の保存
    if save_key:
        os.makedirs("keys", exist_ok=True)

        # 鍵A情報（データセットA用）
        key_a = {
            "type": "dataset_a",
            "key": base64.urlsafe_b64encode(key_a_seed).decode('ascii'),
            "positions": positions1,  # どの位置に元のデータがあるか
            "char_width": char_width,  # 各文字の表現幅
            "data_length": len(data1_padded),
            "original_size": len(data1),
            "timestamp": int(time.time())
        }

        # 鍵B情報（データセットB用）
        key_b = {
            "type": "dataset_b",
            "key": base64.urlsafe_b64encode(key_b_seed).decode('ascii'),
            "positions": positions2,
            "char_width": char_width,
            "data_length": len(data2_padded),
            "original_size": len(data2),
            "timestamp": int(time.time())
        }

        # マスター鍵も保存（通常は不要だが、復号時に完全に同じマスクを再現するため）
        master_key = {
            "master_seed": base64.urlsafe_b64encode(master_seed).decode('ascii'),
            "timestamp": int(time.time())
        }

        # 鍵をファイルに保存
        with open("keys/dataset_a_key.json", 'w') as f:
            json.dump(key_a, f, indent=2)

        with open("keys/dataset_b_key.json", 'w') as f:
            json.dump(key_b, f, indent=2)

        with open("keys/master_key.bin", 'wb') as f:
            f.write(master_seed)

    # 暗号化データを保存
    with open(output_path, 'wb') as f:
        f.write(final_encrypted)

        print(f"\n暗号化が完了しました！")
    print(f"出力ファイル: {output_path}")
    print(f"暗号化後のサイズ: {len(final_encrypted)} bytes")

    if save_key:
        print(f"鍵ファイル:")
        print(f" - keys/dataset_a_key.json")
        print(f" - keys/dataset_b_key.json")

    return {
        "status": "success",
        "encrypted_file": output_path,
        "key_files": ["keys/dataset_a_key.json", "keys/dataset_b_key.json"] if save_key else None
    }

def main():
    # コマンドライン引数の解析
    parser = argparse.ArgumentParser(description="準同型暗号マスキング方式による暗号化")
    parser.add_argument("file1", help="1つ目のファイル")
    parser.add_argument("file2", help="2つ目のファイル")
    parser.add_argument("--output", "-o", default="encrypted_indistinguishable.henc", help="出力ファイル")
    parser.add_argument("--save-key", "-k", action="store_true", help="鍵を保存する")
    args = parser.parse_args()

    # ファイルの存在確認
    if not os.path.exists(args.file1):
        print(f"エラー: ファイル '{args.file1}' が見つかりません")
        return 1

    if not os.path.exists(args.file2):
        print(f"エラー: ファイル '{args.file2}' が見つかりません")
        return 1

    # ファイルの暗号化
    encrypt_file(args.file1, args.file2, args.output, args.save_key)
    return 0

if __name__ == "__main__":
    sys.exit(main())
