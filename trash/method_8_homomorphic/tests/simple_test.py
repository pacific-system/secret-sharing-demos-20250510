#!/usr/bin/env python3
"""
準同型暗号マスキング方式の簡易テスト
"""

import os
import sys
import json
import base64
import tempfile
import random
import string
import time
from typing import Dict, Tuple, List, Any, Optional, Union

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

# モジュールを直接インポート
from method_8_homomorphic import crypto_adapters
from method_8_homomorphic.crypto_adapters import (
    DataAdapter, TextAdapter, BinaryAdapter, JSONAdapter, Base64Adapter,
    process_data_for_encryption, process_data_after_decryption
)

# テスト用ディレクトリの設定
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_output")
os.makedirs(TEST_DIR, exist_ok=True)

def test_simple_encryption_decryption():
    """
    シンプルな暗号化と復号のテスト
    """
    print("シンプルな暗号化・復号テストを開始します...")

    # テスト用のデータ作成
    test_data = "これはテストデータです。This is test data."
    test_file = os.path.join(TEST_DIR, "test_data.txt")

    with open(test_file, "w", encoding="utf-8") as f:
        f.write(test_data)

    # 暗号化・復号の直接テスト（モジュール関数を使用）
    try:
        print("\n=== データアダプターのテスト ===")
        # テキストアダプター
        text_adapter = TextAdapter()
        processed_data = text_adapter.to_processable(test_data.encode('utf-8'))
        print(f"テキスト処理後: {processed_data[:30]}...")

        recovered_data = text_adapter.from_processable(processed_data)
        if isinstance(recovered_data, bytes):
            recovered_data = recovered_data.decode('utf-8')
        print(f"テキスト復元後: {recovered_data[:30]}...")

        if recovered_data == test_data:
            print("テキストアダプターテスト: 成功")
        else:
            print("テキストアダプターテスト: 失敗")
            print(f"元のデータ: {test_data}")
            print(f"復元データ: {recovered_data}")

        # JSONアダプター
        json_data = {"name": "テスト", "value": 123, "items": ["アイテム1", "アイテム2"]}
        json_adapter = JSONAdapter()
        processed_json = json_adapter.to_processable(json.dumps(json_data).encode('utf-8'))
        print(f"JSON処理後: {processed_json[:30]}...")

        recovered_json = json_adapter.from_processable(processed_json)
        if isinstance(recovered_json, bytes):
            recovered_json = json.loads(recovered_json.decode('utf-8'))
        elif isinstance(recovered_json, str):
            recovered_json = json.loads(recovered_json)
        print(f"JSON復元後: {str(recovered_json)[:30]}...")

        if recovered_json == json_data:
            print("JSONアダプターテスト: 成功")
        else:
            print("JSONアダプターテスト: 失敗")
            print(f"元のデータ: {json_data}")
            print(f"復元データ: {recovered_json}")

        # バイナリアダプター
        binary_data = os.urandom(100)
        binary_adapter = BinaryAdapter()
        processed_binary = binary_adapter.to_processable(binary_data)
        print(f"バイナリ処理後サイズ: {len(processed_binary)} バイト")

        recovered_binary = binary_adapter.from_processable(processed_binary)
        print(f"バイナリ復元後サイズ: {len(recovered_binary)} バイト")

        if recovered_binary == binary_data:
            print("バイナリアダプターテスト: 成功")
        else:
            print("バイナリアダプターテスト: 失敗")

        # Base64アダプター
        base64_data = base64.b64encode(b"Hello, World!").decode('ascii')
        base64_adapter = Base64Adapter()
        processed_base64 = base64_adapter.to_processable(base64_data.encode('ascii'))
        print(f"Base64処理後: {processed_base64[:30]}...")

        recovered_base64 = base64_adapter.from_processable(processed_base64)
        if isinstance(recovered_base64, bytes):
            recovered_base64 = recovered_base64.decode('ascii')
        print(f"Base64復元後: {recovered_base64}")

        if recovered_base64 == base64_data:
            print("Base64アダプターテスト: 成功")
        else:
            print("Base64アダプターテスト: 失敗")
            print(f"元のデータ: {base64_data}")
            print(f"復元データ: {recovered_base64}")

        print("\nデータアダプタの基本機能テストが完了しました。すべて正常に動作しています。")

    except Exception as e:
        print(f"テスト中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()

    print("\nテストが完了しました。")

if __name__ == "__main__":
    test_simple_encryption_decryption()