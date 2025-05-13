#!/usr/bin/env python3
"""
ハニーポットカプセルのデバッグスクリプト

暗号化・復号プロセスをステップバイステップで追跡し、データの形式を確認します。
"""

import os
import sys
import binascii
from typing import Dict, Any, Tuple

# テスト対象のモジュールへのパスを追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# テスト対象のモジュールをインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.encrypt import (
    read_file, symmetric_encrypt, encrypt_files
)
from method_7_honeypot.honeypot_capsule import (
    HoneypotCapsule, HoneypotCapsuleFactory,
    create_honeypot_file, extract_data_from_capsule,
    read_data_from_honeypot_file
)


def print_bytes_info(label: str, data: bytes, max_len: int = 32):
    """バイトデータの情報を表示"""
    print(f"{label}:")
    print(f"  長さ: {len(data)} バイト")
    hex_data = binascii.hexlify(data[:max_len]).decode()
    if len(data) > max_len:
        hex_data += "..."
    print(f"  内容: {hex_data}")
    try:
        # 表示可能なASCII文字のみ表示
        ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:max_len])
        if len(data) > max_len:
            ascii_data += "..."
        print(f"  ASCII: {ascii_data}")
    except:
        print("  ASCII表示不可")
    print()


def debug_honeypot_capsule():
    """ハニーポットカプセルのデバッグ"""
    print("=== ハニーポットカプセルのデバッグ開始 ===\n")

    # テスト用のデータを作成
    true_text = b"This is the TRUE data that should be revealed with the correct key."
    false_text = b"This is the FALSE data that will be shown with an incorrect key."

    print_bytes_info("正規データ", true_text)
    print_bytes_info("非正規データ", false_text)

    # マスター鍵とトラップドアパラメータの生成
    master_key = create_master_key()
    print_bytes_info("マスター鍵", master_key)

    params = create_trapdoor_parameters(master_key)
    print("トラップドアパラメータ生成完了")

    # 鍵ペアの導出
    keys, salt = derive_keys_from_trapdoor(params)
    print_bytes_info("正規鍵", keys[KEY_TYPE_TRUE])
    print_bytes_info("非正規鍵", keys[KEY_TYPE_FALSE])
    print_bytes_info("ソルト", salt)

    # データの対称暗号化
    true_encrypted, true_iv = symmetric_encrypt(true_text, keys[KEY_TYPE_TRUE])
    false_encrypted, false_iv = symmetric_encrypt(false_text, keys[KEY_TYPE_FALSE])

    print_bytes_info("暗号化された正規データ", true_encrypted)
    print_bytes_info("正規データのIV", true_iv)
    print_bytes_info("暗号化された非正規データ", false_encrypted)
    print_bytes_info("非正規データのIV", false_iv)

    # ハニーポットカプセルの作成
    print("\n--- ハニーポットカプセル生成プロセス ---\n")

    factory = HoneypotCapsuleFactory(params)
    capsule = factory.create_capsule(true_encrypted, false_encrypted)

    # カプセル内のブロックを表示
    print("カプセル内のブロック:")
    for i, block in enumerate(capsule.blocks):
        block_type = "正規" if block['type'] == 1 else "非正規" if block['type'] == 2 else "その他"
        print(f"  ブロック {i+1}: タイプ={block_type}, サイズ={block['size']}バイト")

    # カプセルをシリアライズ
    serialized = capsule.serialize()
    print(f"\nシリアライズされたカプセルのサイズ: {len(serialized)} バイト")

    # ファイル形式で保存
    capsule_file = create_honeypot_file(true_encrypted, false_encrypted, params)
    print(f"ハニーポットファイルのサイズ: {len(capsule_file)} バイト")

    print("\n--- 復号プロセス ---\n")

    # カプセルからデータを抽出
    true_data = extract_data_from_capsule(capsule, KEY_TYPE_TRUE)
    false_data = extract_data_from_capsule(capsule, KEY_TYPE_FALSE)

    print_bytes_info("カプセルから抽出した正規データ", true_data)
    print_bytes_info("カプセルから抽出した非正規データ", false_data)

    # 比較
    print("\n--- 元データとの比較 ---\n")

    if true_data == true_encrypted:
        print("抽出した正規データは暗号化された正規データと一致しています")
    else:
        print("抽出した正規データと暗号化された正規データは一致していません")

    if false_data == false_encrypted:
        print("抽出した非正規データは暗号化された非正規データと一致しています")
    else:
        print("抽出した非正規データと暗号化された非正規データは一致していません")

    # ファイルからのデータ読み取り
    print("\n--- ファイルからの読み取り ---\n")

    read_true_data, _ = read_data_from_honeypot_file(capsule_file, KEY_TYPE_TRUE)
    read_false_data, _ = read_data_from_honeypot_file(capsule_file, KEY_TYPE_FALSE)

    print_bytes_info("ファイルから読み取った正規データ", read_true_data)
    print_bytes_info("ファイルから読み取った非正規データ", read_false_data)

    # 比較
    if read_true_data == true_data:
        print("ファイルから読み取った正規データはカプセルから抽出した正規データと一致しています")
    else:
        print("ファイルから読み取った正規データとカプセルから抽出した正規データは一致していません")

    if read_false_data == false_data:
        print("ファイルから読み取った非正規データはカプセルから抽出した非正規データと一致しています")
    else:
        print("ファイルから読み取った非正規データとカプセルから抽出した非正規データは一致していません")

    # トークンとのバインディングをチェック
    print("\n--- _bind_token_to_dataの挙動チェック ---\n")

    # HoneypotCapsuleFactoryのプライベートメソッドにアクセス
    # 注: 通常は推奨されませんが、デバッグ目的で使用
    token_true = b"true_token" * 4  # 32バイト
    token_false = b"false_token" * 4  # 32バイト

    bound_true = factory._bind_token_to_data(true_encrypted, token_true)
    bound_false = factory._bind_token_to_data(false_encrypted, token_false)

    print_bytes_info("バインドされた正規データ", bound_true)
    print_bytes_info("バインドされた非正規データ", bound_false)

    # トークンサイズを確認
    TOKEN_SIZE = 32  # configから取得する代わりに直接定義

    print(f"トークンサイズ: {TOKEN_SIZE}")
    if bound_true[:TOKEN_SIZE] == token_true:
        print("バインドされた正規データの先頭にトークンが付加されています")

    if bound_true[TOKEN_SIZE:] == true_encrypted:
        print("バインドされた正規データのトークン以降が元の暗号化データと一致しています")
    else:
        print("バインドされた正規データのトークン以降が元の暗号化データと一致していません")

    print("\n=== デバッグ完了 ===\n")


if __name__ == "__main__":
    debug_honeypot_capsule()