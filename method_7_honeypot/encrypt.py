#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 暗号化プログラム

true.textとfalse.textを入力として、ハニーポットカプセル化された
暗号文を生成します。これにより、同一の暗号文から鍵に応じて
異なる平文を復元できるようになります。
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
from typing import Dict, Tuple, Any, Optional, List, Union
from pathlib import Path
from datetime import datetime

# 内部モジュールからのインポート
from .trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, generate_honey_token,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from .config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, SYMMETRIC_KEY_SIZE,
    SALT_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION
)
from .honeypot_capsule import create_honeypot_file


def read_file(file_path: str) -> bytes:
    """
    ファイルをバイナリデータとして読み込む

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        ファイルの内容（バイト列）

    Raises:
        FileNotFoundError: ファイルが存在しない場合
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise


def symmetric_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    対称鍵暗号を使用してデータを暗号化

    Args:
        data: 暗号化するデータ
        key: 暗号化キー

    Returns:
        (encrypted_data, iv): 暗号化されたデータと初期化ベクトル
    """
    # 実装の詳細は省略しますが、ここでは暗号ライブラリを使用して
    # AES-GCM または ChaCha20-Poly1305 などの認証付き暗号を使用することを推奨します

    # 簡易的な実装例（本番環境では適切な暗号ライブラリを使用してください）
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    # 初期化ベクトルを生成
    iv = os.urandom(16)

    # AES-CTRモードで暗号化
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # 認証タグを計算（本番環境では認証付き暗号を使用してください）
    auth_tag = hashlib.sha256(key + iv + ciphertext).digest()[:16]

    # 暗号文と認証タグを結合
    return ciphertext + auth_tag, iv


def encrypt_files(true_file_path: str, false_file_path: str, output_path: str) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    """
    true.textとfalse.textを暗号化し、ハニーポットカプセルを生成

    Args:
        true_file_path: 正規ファイルのパス
        false_file_path: 非正規ファイルのパス
        output_path: 出力ファイルのパス

    Returns:
        (keys, metadata): 鍵ペアとメタデータ
    """
    # ファイル読み込み
    true_data = read_file(true_file_path)
    false_data = read_file(false_file_path)

    # マスター鍵の生成
    master_key = create_master_key()

    # トラップドアパラメータの生成
    trapdoor_params = create_trapdoor_parameters(master_key)

    # 鍵ペアの導出
    keys, salt = derive_keys_from_trapdoor(trapdoor_params)

    # データの対称暗号化
    true_encrypted, true_iv = symmetric_encrypt(true_data, keys[KEY_TYPE_TRUE])
    false_encrypted, false_iv = symmetric_encrypt(false_data, keys[KEY_TYPE_FALSE])

    # タイムスタンプを生成（ファイル名用）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # メタデータの作成
    metadata = {
        "format": OUTPUT_FORMAT,
        "version": "1.0",
        "algorithm": "honeypot",
        "salt": base64.b64encode(salt).decode('ascii'),
        "true_iv": base64.b64encode(true_iv).decode('ascii'),
        "false_iv": base64.b64encode(false_iv).decode('ascii'),
        "timestamp": timestamp,
        "true_file": os.path.basename(true_file_path),
        "false_file": os.path.basename(false_file_path)
    }

    # ハニーポットカプセルの作成
    capsule_data = create_honeypot_file(
        true_encrypted, false_encrypted, trapdoor_params, metadata
    )

    # 出力ファイルの作成
    with open(output_path, 'wb') as f:
        f.write(capsule_data)

    print(f"暗号化完了: '{output_path}' に暗号文を書き込みました。")

    # 鍵情報を返却
    key_info = {
        KEY_TYPE_TRUE: keys[KEY_TYPE_TRUE],
        KEY_TYPE_FALSE: keys[KEY_TYPE_FALSE],
        "master_key": master_key
    }

    return key_info, metadata


def save_keys(key_info: Dict[str, bytes], output_dir: str, base_name: str) -> Dict[str, str]:
    """
    鍵情報をファイルに保存

    Args:
        key_info: 鍵情報辞書
        output_dir: 出力ディレクトリ
        base_name: ベースファイル名

    Returns:
        保存した鍵ファイルのパス辞書
    """
    # 出力ディレクトリを作成（存在しない場合）
    os.makedirs(output_dir, exist_ok=True)

    key_files = {}

    # 各鍵タイプについて
    for key_type, key in key_info.items():
        # 鍵ファイル名を構築
        filename = f"{base_name}.{key_type}.key"
        file_path = os.path.join(output_dir, filename)

        # 鍵を保存
        with open(file_path, 'wb') as f:
            f.write(key)

        key_files[key_type] = file_path
        print(f"{key_type}鍵を保存しました: {file_path}")

    return key_files


def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="暗号学的ハニーポット方式の暗号化プログラム")

    parser.add_argument(
        "--true-file",
        type=str,
        default=TRUE_TEXT_PATH,
        help=f"正規ファイルのパス（デフォルト: {TRUE_TEXT_PATH}）"
    )

    parser.add_argument(
        "--false-file",
        type=str,
        default=FALSE_TEXT_PATH,
        help=f"非正規ファイルのパス（デフォルト: {FALSE_TEXT_PATH}）"
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help=f"出力ファイルのパス（デフォルト: タイムスタンプ付きファイル名）"
    )

    parser.add_argument(
        "--save-keys",
        action="store_true",
        help="鍵をファイルに保存する"
    )

    parser.add_argument(
        "--keys-dir",
        type=str,
        default="keys",
        help="鍵を保存するディレクトリ（デフォルト: keys）"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在を確認
    for file_path in [args.true_file, args.false_file]:
        if not os.path.exists(file_path):
            print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
            return 1

    # タイムスタンプを生成
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 出力パスが指定されていない場合、デフォルトファイル名を生成
    if args.output is None:
        args.output = f"encrypted_{timestamp}{OUTPUT_EXTENSION}"

    # 出力ディレクトリが存在するか確認
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"ディレクトリを作成しました: {output_dir}")
        except OSError as e:
            print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
            return 1

    try:
        # 暗号化の実行
        key_info, metadata = encrypt_files(args.true_file, args.false_file, args.output)

        # 鍵の保存（オプション）
        if args.save_keys:
            base_name = Path(args.output).stem
            save_keys(key_info, args.keys_dir, base_name)
        else:
            # 鍵を表示
            for key_type, key in key_info.items():
                if key_type != "master_key":  # マスター鍵は表示しない
                    print(f"{key_type}鍵: {binascii.hexlify(key).decode()}")

        print(f"暗号化が成功しました: {args.output}")
        return 0

    except Exception as e:
        print(f"エラー: 暗号化中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
