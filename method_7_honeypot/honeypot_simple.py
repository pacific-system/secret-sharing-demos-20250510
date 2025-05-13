#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 簡略化したデモ実装

このモジュールは暗号学的ハニーポット方式のコンセプトデモを提供します。
同一の暗号文から異なる鍵で異なる平文を復元できることを示します。
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import secrets
import random
import time
from typing import Dict, Tuple, Any, Optional, Union
from pathlib import Path

# 定数
KEY_TYPE_TRUE = "true"
KEY_TYPE_FALSE = "false"
KEY_SIZE = 32  # 256ビット


def generate_key_pair() -> Dict[str, bytes]:
    """
    正規鍵と非正規鍵のペアを生成

    Returns:
        {"true": 正規鍵, "false": 非正規鍵}
    """
    # マスターシードの生成
    master_seed = secrets.token_bytes(KEY_SIZE)

    # 正規鍵と非正規鍵を導出
    true_key = hmac.new(master_seed, b"true_key", hashlib.sha256).digest()
    false_key = hmac.new(master_seed, b"false_key", hashlib.sha256).digest()

    return {
        KEY_TYPE_TRUE: true_key,
        KEY_TYPE_FALSE: false_key
    }


def encrypt_file(true_file: str, false_file: str, output_file: str) -> Dict[str, bytes]:
    """
    正規ファイルと非正規ファイルを暗号化し、ハニーポットカプセルを作成

    Args:
        true_file: 正規ファイルのパス
        false_file: 非正規ファイルのパス
        output_file: 出力ファイルのパス

    Returns:
        生成された鍵ペア
    """
    # 入力ファイルを読み込み
    with open(true_file, 'rb') as f:
        true_data = f.read()

    with open(false_file, 'rb') as f:
        false_data = f.read()

    # 鍵ペアを生成
    keys = generate_key_pair()

    # 初期化ベクトル (IV) を生成
    iv = os.urandom(16)

    # 正規データの暗号化
    true_encrypted = encrypt_data(true_data, keys[KEY_TYPE_TRUE], iv)

    # 非正規データの暗号化
    false_encrypted = encrypt_data(false_data, keys[KEY_TYPE_FALSE], iv)

    # メタデータを作成
    metadata = {
        "format": "honeypot",
        "version": "1.0",
        "iv": base64.b64encode(iv).decode('utf-8'),
        "timestamp": int(time.time())
    }

    # カプセルデータを作成
    capsule = {
        "metadata": metadata,
        "true_data": base64.b64encode(true_encrypted).decode('utf-8'),
        "false_data": base64.b64encode(false_encrypted).decode('utf-8')
    }

    # JSONとして出力
    with open(output_file, 'w') as f:
        json.dump(capsule, f)

    return keys


def decrypt_file(encrypted_file: str, key: bytes, output_file: str) -> str:
    """
    暗号化ファイルを復号

    Args:
        encrypted_file: 暗号化ファイルのパス
        key: 復号鍵
        output_file: 出力ファイルのパス

    Returns:
        検出された鍵タイプ（"true" または "false"）
    """
    # 暗号化ファイルを読み込み
    with open(encrypted_file, 'r') as f:
        capsule = json.load(f)

    # メタデータを取得
    metadata = capsule["metadata"]
    iv = base64.b64decode(metadata["iv"])

    # 両方のデータを取得
    true_data = base64.b64decode(capsule["true_data"])
    false_data = base64.b64decode(capsule["false_data"])

    # 鍵タイプを判定（両方のデータを試し、正しく復号できる方を選択）
    try:
        result = decrypt_data(true_data, key, iv)
        key_type = KEY_TYPE_TRUE
    except Exception:
        try:
            result = decrypt_data(false_data, key, iv)
            key_type = KEY_TYPE_FALSE
        except Exception as e:
            raise ValueError(f"復号失敗: 鍵が無効です: {str(e)}")

    # 結果を出力
    with open(output_file, 'wb') as f:
        f.write(result)

    return key_type


def encrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    データを暗号化

    Args:
        data: 暗号化するデータ
        key: 暗号化キー
        iv: 初期化ベクトル

    Returns:
        暗号化されたデータ
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # パディングを実施
    padder = PKCS7Padder()
    padded_data = padder.pad(data)

    # 暗号化
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def decrypt_data(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    データを復号

    Args:
        encrypted_data: 復号するデータ
        key: 復号キー
        iv: 初期化ベクトル

    Returns:
        復号されたデータ
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # 復号
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # パディングを除去
    unpadder = PKCS7Padder()
    return unpadder.unpad(decrypted_data)


class PKCS7Padder:
    """PKCS#7 パディングを実装するクラス"""

    def __init__(self, block_size: int = 16):
        """
        初期化

        Args:
            block_size: ブロックサイズ（デフォルト: 16バイト = 128ビット）
        """
        self.block_size = block_size

    def pad(self, data: bytes) -> bytes:
        """
        データにパディングを追加

        Args:
            data: パディングを追加するデータ

        Returns:
            パディングが追加されたデータ
        """
        padding_len = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def unpad(self, data: bytes) -> bytes:
        """
        パディングを除去

        Args:
            data: パディングを除去するデータ

        Returns:
            パディングが除去されたデータ
        """
        padding_len = data[-1]
        if padding_len > self.block_size:
            raise ValueError("パディングが不正です")

        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("パディングが不正です")

        return data[:-padding_len]


def save_keys(keys: Dict[str, bytes], output_dir: str, base_name: str = "honeypot") -> None:
    """
    鍵を保存

    Args:
        keys: 保存する鍵の辞書
        output_dir: 出力ディレクトリ
        base_name: ベースファイル名
    """
    # ディレクトリが存在しない場合は作成
    os.makedirs(output_dir, exist_ok=True)

    # 鍵を保存
    for key_type, key in keys.items():
        filename = f"{base_name}.{key_type}.key"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, 'wb') as f:
            f.write(key)

        print(f"{key_type}鍵を保存しました: {filepath}")


def main():
    """メイン関数"""
    import argparse

    parser = argparse.ArgumentParser(description="暗号学的ハニーポット方式のデモ")
    subparsers = parser.add_subparsers(dest="command", help="コマンド")

    # 暗号化用パーサー
    encrypt_parser = subparsers.add_parser("encrypt", help="ファイルを暗号化")
    encrypt_parser.add_argument("--true", required=True, help="正規ファイルのパス")
    encrypt_parser.add_argument("--false", required=True, help="非正規ファイルのパス")
    encrypt_parser.add_argument("--output", "-o", required=True, help="出力ファイルのパス")
    encrypt_parser.add_argument("--save-keys", action="store_true", help="鍵をファイルに保存")
    encrypt_parser.add_argument("--keys-dir", default="keys", help="鍵を保存するディレクトリ")

    # 復号用パーサー
    decrypt_parser = subparsers.add_parser("decrypt", help="ファイルを復号")
    decrypt_parser.add_argument("file", help="復号するファイルのパス")
    decrypt_parser.add_argument("--key-file", required=True, help="鍵ファイルのパス")
    decrypt_parser.add_argument("--output", "-o", required=True, help="出力ファイルのパス")

    args = parser.parse_args()

    if args.command == "encrypt":
        try:
            # ファイルを暗号化
            keys = encrypt_file(args.true, args.false, args.output)
            print(f"暗号化完了: {args.output}")

            # 鍵を保存
            if args.save_keys:
                base_name = Path(args.output).stem
                save_keys(keys, args.keys_dir, base_name)
            else:
                # 鍵を表示
                for key_type, key in keys.items():
                    print(f"{key_type}鍵: {base64.b64encode(key).decode()}")
        except Exception as e:
            print(f"エラー: {str(e)}", file=sys.stderr)
            return 1

    elif args.command == "decrypt":
        try:
            # 鍵を読み込み
            with open(args.key_file, 'rb') as f:
                key = f.read()

            # ファイルを復号
            key_type = decrypt_file(args.file, key, args.output)
            print(f"復号完了: {args.output} (鍵タイプ: {key_type})")
        except Exception as e:
            print(f"エラー: {str(e)}", file=sys.stderr)
            return 1

    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())