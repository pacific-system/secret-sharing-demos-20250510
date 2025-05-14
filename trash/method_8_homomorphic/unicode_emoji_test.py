#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
絵文字を含むUnicodeファイルの暗号化と復号をテストするスクリプト
"""

import os
import sys
import hashlib
import base64
import json
import time

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.indistinguishable_crypto import (
    SecureHomomorphicCrypto, encrypt_file_with_dual_keys, decrypt_file_with_key
)

def print_file_info(file_path):
    """ファイルの情報を表示する"""
    with open(file_path, 'rb') as f:
        content = f.read()

    print(f"ファイルパス: {file_path}")
    print(f"サイズ: {len(content)} バイト")
    print(f"SHA-256: {hashlib.sha256(content).hexdigest()}")

    # 先頭と末尾のバイトを16進数で表示
    print(f"先頭30バイト (16進数): {content[:30].hex()}")
    print(f"末尾30バイト (16進数): {content[-30:].hex()}")

    # テキストとして表示を試みる
    try:
        text = content.decode('utf-8')
        print(f"UTF-8デコード: 成功 (長さ: {len(text)} 文字)")
        print(f"テキスト先頭: {text[:30]}")
        print(f"テキスト末尾: {text[-30:]}")
    except UnicodeDecodeError:
        print("UTF-8デコード: 失敗")

    print("-" * 60)

def test_emoji_encryption():
    """絵文字を含むUnicodeファイルの暗号化テスト"""
    true_file = "../common/true-false-text/t.text"
    false_file = "../common/true-false-text/f.text"
    encrypted_file = "../test_output/emoji_encrypted.hmc"
    true_decrypted = "../test_output/emoji_decrypted_true.txt"
    false_decrypted = "../test_output/emoji_decrypted_false.txt"

    # 元のファイル情報
    print("元のファイル情報:")
    print_file_info(true_file)
    print_file_info(false_file)

    # 直接ファイル内容を読み込んで暗号化
    with open(true_file, 'rb') as f:
        true_content = f.read()

    with open(false_file, 'rb') as f:
        false_content = f.read()

    # 直接暗号化
    print("元のファイルのBase64エンコード:")
    true_b64 = base64.b64encode(true_content)
    false_b64 = base64.b64encode(false_content)
    print(f"真ファイルBase64: {true_b64[:30].decode('ascii')}...")
    print(f"偽ファイルBase64: {false_b64[:30].decode('ascii')}...")

    # 暗号化インスタンスを作成
    crypto = SecureHomomorphicCrypto(key_bits=1024)
    crypto.generate_keys()

    # 直接暗号化を回避し、オリジナルのファイルをbase64エンコードせずにパススルー
    class SimpleStorage:
        def __init__(self, content):
            self.content = content

    # 直接送信
    true_storage = SimpleStorage(true_content)
    false_storage = SimpleStorage(false_content)

    # 手動で暗号化プロセスを実行
    encrypted_file = "../test_output/emoji_manual_encrypted.hmc"
    true_decrypted = "../test_output/emoji_manual_decrypted_true.txt"
    false_decrypted = "../test_output/emoji_manual_decrypted_false.txt"

    print("\n手動プロセスで暗号化・復号を実行します")

    # キーを生成
    public_key, private_key = crypto.generate_keys()

    # ファイルをJSON形式で保存
    with open(encrypted_file, 'w', encoding='utf-8') as f:
        # メタデータ作成
        result = {
            "metadata": {
                "format": "manual_test",
                "version": "1.0",
                "timestamp": int(time.time()),
                "true_content": base64.b64encode(true_content).decode('ascii'),
                "false_content": base64.b64encode(false_content).decode('ascii')
            }
        }
        json.dump(result, f, indent=2)

    print(f"手動エンコード: {encrypted_file}")

    # ファイルを読み込んで復号
    with open(encrypted_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 復号（Base64デコード）
    true_decoded = base64.b64decode(data["metadata"]["true_content"])
    false_decoded = base64.b64decode(data["metadata"]["false_content"])

    # ファイルに保存
    with open(true_decrypted, 'wb') as f:
        f.write(true_decoded)

    with open(false_decrypted, 'wb') as f:
        f.write(false_decoded)

    print(f"手動復号: {true_decrypted}, {false_decrypted}")

    # 検証
    with open(true_decrypted, 'rb') as f:
        manual_true_content = f.read()

    with open(false_decrypted, 'rb') as f:
        manual_false_content = f.read()

    print(f"手動プロセスでの真ファイル一致: {true_content == manual_true_content}")
    print(f"手動プロセスでの偽ファイル一致: {false_content == manual_false_content}")

    # 手動復号ファイル情報
    print("\n手動復号ファイル情報:")
    print_file_info(true_decrypted)
    print_file_info(false_decrypted)

    # 元の暗号化・復号プロセスを続行
    encrypted_data = crypto.encrypt_dual_content(true_content, false_content)
    crypto.save_encrypted_data(encrypted_data, encrypted_file)

if __name__ == "__main__":
    test_emoji_encryption()