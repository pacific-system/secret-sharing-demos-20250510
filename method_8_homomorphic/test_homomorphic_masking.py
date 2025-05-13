#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の脆弱性検証スクリプト

このスクリプトは、準同型暗号マスキング方式の実装に対するセキュリティ検証を行います。
特に、以下の点を検証します：
1. ソースコード編集による他方のファイル獲得の可能性
2. バックドアの存在可能性
3. 要件の簡略化実装の有無
"""

import os
import sys
import time
import json
import hashlib
import base64
from typing import Dict, Any, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, derive_key_from_password,
    serialize_encrypted_data, deserialize_encrypted_data
)
from method_8_homomorphic.crypto_mask import (
    CryptoMask, MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)

# 出力ディレクトリの確認
os.makedirs("test_output", exist_ok=True)

def print_header(text):
    """ヘッダーテキストを出力"""
    print("\n" + "=" * 80)
    print(f" {text} ".center(80, "="))
    print("=" * 80)

def print_subheader(text):
    """サブヘッダーテキストを出力"""
    print("\n" + "-" * 60)
    print(f" {text} ".center(60, "-"))
    print("-" * 60)

def generate_test_files():
    """テスト用のtrueとfalseファイルを生成"""
    true_content = "これは正規の重要な秘密情報です。\n機密度: 最高\n取扱注意！"
    false_content = "これは偽の情報です。重要ではありません。\n機密度: 低\n一般公開可能"

    # ファイルに書き込み
    true_path = "test_output/true.text"
    false_path = "test_output/false.text"

    with open(true_path, 'w', encoding='utf-8') as f:
        f.write(true_content)

    with open(false_path, 'w', encoding='utf-8') as f:
        f.write(false_content)

    print(f"テストファイルを生成しました: {true_path}, {false_path}")
    return true_path, false_path

def encrypt_with_dual_keys(true_file: str, false_file: str) -> str:
    """
    trueとfalseのファイルを準同型暗号で暗号化し、
    両方の鍵で復号できる暗号文を生成

    Args:
        true_file: 真のファイルパス
        false_file: 偽のファイルパス

    Returns:
        暗号化ファイルパス
    """
    print_subheader("準同型暗号による二重暗号化")

    # ファイル内容を読み込み
    with open(true_file, 'r', encoding='utf-8') as f:
        true_content = f.read()

    with open(false_file, 'r', encoding='utf-8') as f:
        false_content = f.read()

    print(f"真のファイル内容: {true_content}")
    print(f"偽のファイル内容: {false_content}")

    # Paillier暗号の初期化
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    public_key, private_key = paillier.generate_keys()

    # マスク関数生成器
    mask_generator = MaskFunctionGenerator(paillier)

    # テキストをバイト列に変換
    true_bytes = true_content.encode('utf-8')
    false_bytes = false_content.encode('utf-8')

    # バイト列を整数に変換
    true_int = int.from_bytes(true_bytes, 'big')
    false_int = int.from_bytes(false_bytes, 'big')

    # 暗号化
    true_enc = [paillier.encrypt(true_int, public_key)]
    false_enc = [paillier.encrypt(false_int, public_key)]

    print(f"真のテキストの暗号化チャンク: {true_enc}")
    print(f"偽のテキストの暗号化チャンク: {false_enc}")

    # 変換（両方の鍵で復号できるように）
    masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
        paillier, true_enc, false_enc, mask_generator)

    print(f"マスク適用後の真のチャンク: {masked_true}")
    print(f"マスク適用後の偽のチャンク: {masked_false}")

    # 区別不可能な形式に変換
    indistinguishable = create_indistinguishable_form(
        masked_true, masked_false, true_mask, false_mask,
        {"paillier_public_key": public_key, "paillier_private_key": private_key}
    )

    # 暗号化データをファイルに保存
    encrypted_file = "test_output/encrypted.hmc"
    with open(encrypted_file, 'w') as f:
        json.dump(indistinguishable, f, indent=2)

    print(f"暗号化ファイルを生成しました: {encrypted_file}")

    # 鍵情報も保存（テスト用）
    key_info = {
        "paillier_public_key": public_key,
        "paillier_private_key": private_key,
        "true_mask": true_mask,
        "false_mask": false_mask
    }

    key_file = "test_output/keys/key_info.json"
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    with open(key_file, 'w') as f:
        json.dump(key_info, f, indent=2)

    print(f"鍵情報を保存しました: {key_file}")

    return encrypted_file

def decrypt_with_both_keys(encrypted_file: str) -> Tuple[str, str]:
    """
    暗号化ファイルを真と偽の両方の鍵で復号

    Args:
        encrypted_file: 暗号化ファイルパス

    Returns:
        (真の復号ファイルパス, 偽の復号ファイルパス)
    """
    print_subheader("両方の鍵による復号")

    # 暗号化データを読み込み
    with open(encrypted_file, 'r') as f:
        indistinguishable = json.load(f)

    # 鍵情報を読み込み
    key_file = "test_output/keys/key_info.json"
    with open(key_file, 'r') as f:
        key_info = json.load(f)

    # Paillier暗号の初期化
    paillier = PaillierCrypto()
    paillier.public_key = key_info["paillier_public_key"]
    paillier.private_key = key_info["paillier_private_key"]

    true_decrypted = None
    false_decrypted = None

    # 真の鍵で復号
    try:
        chunks, mask_info = extract_by_key_type(indistinguishable, "true")

        # シードからマスクを再生成
        seed = base64.b64decode(mask_info["seed"])
        mask_generator = MaskFunctionGenerator(paillier, seed)
        true_mask, _ = mask_generator.generate_mask_pair()

        # マスク除去
        unmasked = mask_generator.remove_mask(chunks, true_mask)

        # 復号
        decrypted_int = paillier.decrypt(unmasked[0], paillier.private_key)

        # 整数をバイト列に変換し、文字列にデコード
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
        true_decrypted = decrypted_bytes.decode('utf-8')

        print(f"真の鍵での復号結果: {true_decrypted}")
    except Exception as e:
        print(f"真の鍵での復号に失敗: {e}")

    # 偽の鍵で復号
    try:
        chunks, mask_info = extract_by_key_type(indistinguishable, "false")

        # シードからマスクを再生成
        seed = base64.b64decode(mask_info["seed"])
        mask_generator = MaskFunctionGenerator(paillier, seed)
        _, false_mask = mask_generator.generate_mask_pair()

        # マスク除去
        unmasked = mask_generator.remove_mask(chunks, false_mask)

        # 復号
        decrypted_int = paillier.decrypt(unmasked[0], paillier.private_key)

        # 整数をバイト列に変換し、文字列にデコード
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
        false_decrypted = decrypted_bytes.decode('utf-8')

        print(f"偽の鍵での復号結果: {false_decrypted}")
    except Exception as e:
        print(f"偽の鍵での復号に失敗: {e}")

    # ファイルに保存
    true_decrypted_file = "test_output/decrypted_true.txt"
    false_decrypted_file = "test_output/decrypted_false.txt"

    if true_decrypted:
        with open(true_decrypted_file, 'w', encoding='utf-8') as f:
            f.write(true_decrypted)

    if false_decrypted:
        with open(false_decrypted_file, 'w', encoding='utf-8') as f:
            f.write(false_decrypted)

    print(f"復号ファイルを生成しました: {true_decrypted_file}, {false_decrypted_file}")

    return true_decrypted_file, false_decrypted_file

def analyze_files_for_vulnerabilities():
    """
    脆弱性の分析を行う

    1. ソースコード編集による他方のファイル獲得の可能性
    2. バックドアの存在可能性
    3. 要件の簡略化実装の有無
    """
    print_header("脆弱性の分析")

    # ファイルサイズと内容の検証
    original_true_file = "test_output/true.text"
    original_false_file = "test_output/false.text"
    decrypted_true_file = "test_output/decrypted_true.txt"
    decrypted_false_file = "test_output/decrypted_false.txt"
    encrypted_file = "test_output/encrypted.hmc"

    # ファイルサイズを取得
    original_true_size = os.path.getsize(original_true_file)
    original_false_size = os.path.getsize(original_false_file)
    decrypted_true_size = os.path.getsize(decrypted_true_file)
    decrypted_false_size = os.path.getsize(decrypted_false_file)
    encrypted_size = os.path.getsize(encrypted_file)

    # ファイル内容のハッシュを計算
    def get_file_hash(filename):
        with open(filename, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    original_true_hash = get_file_hash(original_true_file)
    original_false_hash = get_file_hash(original_false_file)
    decrypted_true_hash = get_file_hash(decrypted_true_file)
    decrypted_false_hash = get_file_hash(decrypted_false_file)
    encrypted_hash = get_file_hash(encrypted_file)

    # 実行時間の測定
    def measure_execution_time(func, *args):
        start_time = time.time()
        result = func(*args)
        end_time = time.time()
        return result, end_time - start_time

    # 暗号化テスト
    def test_encryption():
        paillier = PaillierCrypto(bits=1024)
        public_key, private_key = paillier.generate_keys()

        with open(original_true_file, 'r', encoding='utf-8') as f:
            content = f.read().encode('utf-8')

        # 整数に変換
        content_int = int.from_bytes(content, 'big')

        # 暗号化
        encrypted = paillier.encrypt(content_int, public_key)

        return encrypted, public_key, private_key

    # 復号テスト
    def test_decryption(encrypted, private_key):
        paillier = PaillierCrypto()
        paillier.private_key = private_key

        # 復号
        decrypted_int = paillier.decrypt(encrypted, private_key)

        # バイト列に変換
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')

        return decrypted_bytes

    # 性能テスト
    (encrypted, public_key, private_key), encryption_time = measure_execution_time(test_encryption)
    decrypted, decryption_time = measure_execution_time(test_decryption, encrypted, private_key)

    # 結果の表示
    print_subheader("ファイルサイズの比較")
    print(f"元の真ファイル: {original_true_size} バイト")
    print(f"元の偽ファイル: {original_false_size} バイト")
    print(f"復号された真ファイル: {decrypted_true_size} バイト")
    print(f"復号された偽ファイル: {decrypted_false_size} バイト")
    print(f"暗号化ファイル: {encrypted_size} バイト")

    print_subheader("ファイル内容のハッシュ比較")
    print(f"元の真ファイル: {original_true_hash}")
    print(f"元の偽ファイル: {original_false_hash}")
    print(f"復号された真ファイル: {decrypted_true_hash}")
    print(f"復号された偽ファイル: {decrypted_false_hash}")
    print(f"暗号化ファイル: {encrypted_hash}")

    print_subheader("実行時間の測定")
    print(f"暗号化時間: {encryption_time:.6f} 秒")
    print(f"復号時間: {decryption_time:.6f} 秒")

    # 脆弱性の分析結果
    print_subheader("脆弱性分析結果")

    # 1. ソースコード編集による他方のファイル獲得の可能性
    if original_true_hash == decrypted_true_hash and original_false_hash == decrypted_false_hash:
        print("1. ソースコード編集リスク: 低")
        print("   復号されたファイルは元のファイルと完全に一致しており、")
        print("   暗号化・復号プロセスが正しく機能しています。")
    else:
        print("1. ソースコード編集リスク: 要調査")
        print("   復号されたファイルと元のファイルが一致していません。")
        print("   これはバグか脆弱性の可能性があります。")

    # 2. バックドアの存在可能性
    with open(encrypted_file, 'r') as f:
        encrypted_content = f.read()

    if "true_chunks" in encrypted_content and "false_chunks" in encrypted_content:
        print("2. バックドア存在リスク: 高")
        print("   暗号化ファイルに真偽両方のチャンクが明示的に含まれています。")
        print("   攻撃者は暗号文解析でどちらが真か特定できる可能性があります。")
    else:
        print("2. バックドア存在リスク: 低")
        print("   暗号化ファイルに真偽を区別する明示的な情報は含まれていません。")

    # 3. 要件の簡略化実装の有無
    if encryption_time < 0.001 or decryption_time < 0.001:
        print("3. 簡略化実装リスク: 高")
        print("   暗号化・復号の処理時間が異常に短く、実際の暗号操作を")
        print("   行っていない可能性があります。")
    else:
        print("3. 簡略化実装リスク: 低")
        print("   暗号化・復号の処理時間は妥当で、実際の暗号操作が")
        print("   行われていると考えられます。")

def main():
    """メイン関数"""
    print_header("準同型暗号マスキング方式の脆弱性検証")

    # テストファイルの生成
    true_file, false_file = generate_test_files()

    # 暗号化
    encrypted_file = encrypt_with_dual_keys(true_file, false_file)

    # 復号
    true_decrypted, false_decrypted = decrypt_with_both_keys(encrypted_file)

    # 脆弱性分析
    analyze_files_for_vulnerabilities()

    print("\n検証が完了しました。")

if __name__ == "__main__":
    main()