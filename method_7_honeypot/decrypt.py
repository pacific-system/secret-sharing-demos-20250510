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

        # メタデータを取得（ここでは鍵タイプを評価せず、単に読み込むだけ）
        # カプセルから適切なデータを抽出
        # トラップドア関数とブラインドピックを活用するため、まず評価を行わない
        # 正規・非正規いずれの経路も同一の時間で処理を進める

        # ファイルから必要なデータを抽出（key_typeは後で決定）
        key_type = None  # 後で決定
        data, metadata = None, None

        # 例外処理を追加（正規/非正規判定が不可能な場合でも正常終了するため）
        try:
            # まず正規として試行
            data, metadata = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_TRUE)
            key_type = KEY_TYPE_TRUE
        except Exception:
            try:
                # 次に非正規として試行
                data, metadata = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_FALSE)
                key_type = KEY_TYPE_FALSE
            except Exception as e:
                # どちらも失敗した場合
                raise ValueError(f"ファイルの復号に失敗しました: {str(e)}")

        # 鍵検証を行い、正規/非正規を判定
        # 注: 内部的に判定を行いますが、外部からは同一の処理に見えます
        # ハニーポットCID操作を伴う検証
        salt = base64.b64decode(metadata.get('salt', ''))
        iv = base64.b64decode(metadata.get(f'{key_type}_iv', ''))

        # トラップドアパラメータを復元
        # 実際には、ここで必要なパラメータをカプセルから抽出
        trapdoor_params = {}  # 簡略化のため空の辞書を使用

        # 改変耐性機能による鍵検証
        # 注: verify_with_tamper_resistance は改変検知機能を含む
        # この結果に基づいて経路選択が行われるが、外部からは判別不能
        true_token = generate_honey_token(KEY_TYPE_TRUE, trapdoor_params)
        false_token = generate_honey_token(KEY_TYPE_FALSE, trapdoor_params)
        token = true_token if key_type == KEY_TYPE_TRUE else false_token

        verified_key_type = verify_with_tamper_resistance(key, token, trapdoor_params)

        # タイミング攻撃対策: 常に両方の経路を実行し、結果を選択
        # 両方のパスでほぼ同じ時間がかかるようにする
        true_result = None
        false_result = None

        # 正規パス（常に実行）
        try:
            true_iv = base64.b64decode(metadata.get('true_iv', ''))
            true_data = symmetric_decrypt(data, key, true_iv)
            true_result = true_data
        except Exception:
            # エラーが発生しても処理を続行
            pass

        # 非正規パス（常に実行）
        try:
            false_iv = base64.b64decode(metadata.get('false_iv', ''))
            false_data = symmetric_decrypt(data, key, false_iv)
            false_result = false_data
        except Exception:
            # エラーが発生しても処理を続行
            pass

        # 検証結果に基づいて出力を選択
        if verified_key_type == KEY_TYPE_TRUE and true_result is not None:
            result = true_result
        elif verified_key_type == KEY_TYPE_FALSE and false_result is not None:
            result = false_result
        else:
            # どちらも失敗した場合はエラー
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
