#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 復号プログラム

ハニーポットカプセル化された暗号文を復号し、提供された鍵に応じて
正規または非正規の平文を出力します。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import time
import secrets
import binascii
import random
from typing import Dict, Tuple, Any, Optional, List, Union
from pathlib import Path
from datetime import datetime

# 内部モジュールからのインポート
from .trapdoor import (
    KEY_TYPE_TRUE, KEY_TYPE_FALSE,
    evaluate_key_type, generate_honey_token
)
from .key_verification import verify_key_and_select_path
from .deception import verify_with_tamper_resistance
from .honeypot_capsule import read_data_from_honeypot_file
from .config import OUTPUT_EXTENSION


def symmetric_decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    対称鍵暗号を使用してデータを復号

    Args:
        encrypted_data: 復号するデータ（暗号文 + 認証タグ）
        key: 復号キー
        iv: 初期化ベクトル

    Returns:
        復号されたデータ

    Raises:
        ValueError: 認証に失敗した場合
    """
    # 実装の詳細は省略しますが、ここでは暗号ライブラリを使用して
    # AES-GCM または ChaCha20-Poly1305 などの認証付き暗号を使用することを推奨します

    # 簡易的な実装例（本番環境では適切な暗号ライブラリを使用してください）
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    # 暗号文と認証タグを分離
    ciphertext_len = len(encrypted_data) - 16  # 認証タグは16バイト
    ciphertext = encrypted_data[:ciphertext_len]
    auth_tag = encrypted_data[ciphertext_len:]

    # 認証タグを検証
    expected_tag = hashlib.sha256(key + iv + ciphertext).digest()[:16]
    if not secrets.compare_digest(auth_tag, expected_tag):
        raise ValueError("認証に失敗しました。データが改ざんされている可能性があります。")

    # AES-CTRモードで復号
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def read_key_from_file(key_path: str) -> bytes:
    """
    ファイルから鍵を読み込む

    Args:
        key_path: 鍵ファイルのパス

    Returns:
        鍵のバイト列

    Raises:
        FileNotFoundError: ファイルが存在しない場合
    """
    try:
        with open(key_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"エラー: 鍵ファイル '{key_path}' が見つかりません。", file=sys.stderr)
        raise


def read_key_from_hex(hex_key: str) -> bytes:
    """
    16進数文字列から鍵を読み込む

    Args:
        hex_key: 16進数形式の鍵

    Returns:
        鍵のバイト列

    Raises:
        ValueError: 16進数文字列の形式が不正な場合
    """
    try:
        return binascii.unhexlify(hex_key)
    except (binascii.Error, ValueError):
        print(f"エラー: 不正な16進数形式の鍵です: {hex_key}", file=sys.stderr)
        raise


def decrypt_file(file_path: str, key: bytes, output_path: Optional[str] = None) -> str:
    """
    ハニーポットカプセル化されたファイルを復号

    Args:
        file_path: 暗号化ファイルのパス
        key: 復号キー
        output_path: 出力ファイルのパス（省略時は標準出力）

    Returns:
        出力ファイルのパス（標準出力の場合は空文字列）

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        ValueError: 復号に失敗した場合
    """
    try:
        # ファイルを読み込み
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        # タイミング攻撃対策: ランダムな遅延を追加
        time.sleep(random.uniform(0.05, 0.15))

        # 簡略化されたアプローチで試行
        # まず両方のキータイプでデータを取得してみる
        true_data = false_data = None
        true_iv = false_iv = None
        metadata = None

        # 正規キータイプとして試行
        try:
            true_data, metadata = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_TRUE)
            true_iv = base64.b64decode(metadata.get('true_iv', ''))
        except Exception:
            pass

        # 非正規キータイプとして試行
        try:
            false_data, metadata = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_FALSE)
            false_iv = base64.b64decode(metadata.get('false_iv', ''))
        except Exception:
            pass

        if metadata is None:
            raise ValueError("ファイルのフォーマットが不正です")

        # 両方のパスで復号を試行
        true_result = false_result = None

        # 正規パスでの復号
        if true_data is not None and true_iv is not None:
            try:
                true_result = symmetric_decrypt(true_data, key, true_iv)
            except Exception:
                pass

        # 非正規パスでの復号
        if false_data is not None and false_iv is not None:
            try:
                false_result = symmetric_decrypt(false_data, key, false_iv)
            except Exception:
                pass

        # 成功した方の結果を選択
        result = None
        if true_result is not None:
            result = true_result
        elif false_result is not None:
            result = false_result

        if result is None:
            raise ValueError("データの復号に失敗しました。鍵が正しくないか、ファイルが破損しています。")

        # 結果を出力
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(result)
            return output_path
        else:
            # 標準出力に書き込み
            sys.stdout.buffer.write(result)
            return ""

    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise
    except Exception as e:
        print(f"エラー: ファイルの復号に失敗しました: {str(e)}", file=sys.stderr)
        raise


def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="暗号学的ハニーポット方式の復号プログラム")

    parser.add_argument(
        "input_file",
        type=str,
        help=f"復号する暗号化ファイルのパス（{OUTPUT_EXTENSION}形式）"
    )

    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--key-file",
        type=str,
        help="鍵ファイルのパス"
    )
    key_group.add_argument(
        "--key",
        type=str,
        help="16進数形式の鍵"
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="出力ファイルのパス（省略時は標準出力）"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在を確認
    if not os.path.exists(args.input_file):
        print(f"エラー: ファイル '{args.input_file}' が見つかりません。", file=sys.stderr)
        return 1

    # 鍵を取得
    try:
        if args.key_file:
            key = read_key_from_file(args.key_file)
        else:
            key = read_key_from_hex(args.key)
    except Exception as e:
        print(f"エラー: 鍵の読み込みに失敗しました: {e}", file=sys.stderr)
        return 1

    # 出力パスが指定されており、出力ディレクトリが存在しない場合は作成
    if args.output:
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"ディレクトリを作成しました: {output_dir}")
            except OSError as e:
                print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
                return 1

    try:
        # ファイルを復号
        output = decrypt_file(args.input_file, key, args.output)

        if args.output:
            print(f"復号が成功しました: {output}")

        return 0

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
