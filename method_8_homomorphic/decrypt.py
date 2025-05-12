#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の復号実行ファイル

このモジュールは、準同型暗号マスキング方式を使用して暗号化されたファイルを復号するための
コマンドラインツールを提供します。
"""

import os
import sys
import time
import json
import base64
import hashlib
import argparse
import binascii
from typing import Dict, Any, Tuple, List, Optional

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES
)
from method_8_homomorphic.homomorphic import PaillierCrypto, ElGamalCrypto
from method_8_homomorphic.crypto_mask import CryptoMask
from method_8_homomorphic.indistinguishable import IndistinguishableWrapper


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数の解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(
        description='準同型暗号マスキング方式による復号ツール'
    )

    parser.add_argument(
        'input_file',
        type=str,
        help='復号する暗号化ファイルのパス'
    )

    parser.add_argument(
        '--key', '-k',
        type=str,
        required=True,
        help='復号に使用する鍵（16進数文字列）'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        default='decrypted.txt',
        help='出力ファイル名 (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='詳細な出力'
    )

    return parser.parse_args()


def parse_key(key_str: str) -> bytes:
    """
    16進数文字列の鍵をバイト列に変換

    Args:
        key_str: 16進数文字列の鍵

    Returns:
        鍵のバイト列
    """
    try:
        key = binascii.unhexlify(key_str)
        if len(key) < KEY_SIZE_BYTES:
            key = key.ljust(KEY_SIZE_BYTES, b'\0')
        elif len(key) > KEY_SIZE_BYTES:
            key = key[:KEY_SIZE_BYTES]
        return key
    except binascii.Error:
        print(f"Error: 無効な鍵形式です。16進数文字列を指定してください。")
        sys.exit(1)


def decrypt_file(args: argparse.Namespace) -> None:
    """
    ファイルを復号

    Args:
        args: コマンドライン引数
    """
    start_time = time.time()

    # 鍵の解析
    key = parse_key(args.key)

    if args.verbose:
        print(f"復号鍵: {binascii.hexlify(key).decode()}")

    # 暗号化ファイルの読み込み
    try:
        with open(args.input_file, 'r') as f:
            encrypted_data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error: 暗号化ファイルの読み込みに失敗しました: {e}")
        sys.exit(1)

    # メタデータの取得
    metadata = encrypted_data['metadata']

    # ソルトをデコード
    try:
        salt = base64.b64decode(metadata['salt'])
    except Exception as e:
        print(f"Error: ソルトのデコードに失敗しました: {e}")
        sys.exit(1)

    # 準同型暗号マスクを準備
    crypto_mask = CryptoMask()

    # 準同型暗号の公開鍵と秘密鍵の設定
    # Paillier暗号の鍵
    paillier_public_key = {
        'n': int(metadata['paillier_public']['n']),
        'g': int(metadata['paillier_public']['g'])
    }
    paillier_private_key = {
        'lambda': int(encrypted_data['paillier_private']['lambda']),
        'mu': int(encrypted_data['paillier_private']['mu']),
        'n': int(encrypted_data['paillier_private']['n'])
    }

    # ElGamal暗号の鍵
    elgamal_public_key = {
        'p': int(metadata['elgamal_public']['p']),
        'g': int(metadata['elgamal_public']['g']),
        'y': int(metadata['elgamal_public']['y'])
    }
    elgamal_private_key = {
        'x': int(encrypted_data['elgamal_private']['x']),
        'p': int(encrypted_data['elgamal_private']['p'])
    }

    # クリプトマスクの初期化と鍵設定
    crypto_mask.paillier.public_key = paillier_public_key
    crypto_mask.paillier.private_key = paillier_private_key
    crypto_mask.elgamal.public_key = elgamal_public_key
    crypto_mask.elgamal.private_key = elgamal_private_key

    # マスクパラメータの設定
    mask_params = metadata['mask_params']

    # 識別不能性ラッパーを準備
    indist = IndistinguishableWrapper()
    indist.generate_seed(key, salt)

    # 鍵の種類を判定（真の鍵か偽の鍵か）
    is_true_key = indist.is_true_path(key, salt)
    key_type = 'true' if is_true_key else 'false'

    if args.verbose:
        print(f"鍵タイプ: {'真の鍵' if is_true_key else '偽の鍵'}")

    # アルゴリズムに応じた暗号文の取得
    algorithm = metadata['algorithm']

    # 復号に使用するデータの選択
    if key_type == 'true':
        # 真の鍵の場合
        if algorithm in ['paillier', 'hybrid']:
            # Paillier暗号を使用
            encrypted_chunks = [int(c) for c in encrypted_data['true_paillier']]
            encrypted_masked = {
                'paillier': encrypted_chunks,
                'chunks': metadata['true_chunks']
            }
        else:
            # ElGamal暗号を使用
            encrypted_chunks = [
                (int(c[0]), int(c[1])) for c in encrypted_data['true_elgamal']
            ]
            encrypted_masked = {
                'elgamal': encrypted_chunks,
                'chunks': metadata['true_chunks']
            }
    else:
        # 偽の鍵の場合
        if algorithm in ['paillier', 'hybrid']:
            # Paillier暗号を使用
            encrypted_chunks = [int(c) for c in encrypted_data['false_paillier']]
            encrypted_masked = {
                'paillier': encrypted_chunks,
                'chunks': metadata['false_chunks']
            }
        else:
            # ElGamal暗号を使用
            encrypted_chunks = [
                (int(c[0]), int(c[1])) for c in encrypted_data['false_elgamal']
            ]
            encrypted_masked = {
                'elgamal': encrypted_chunks,
                'chunks': metadata['false_chunks']
            }

    # マスクを除去してデータを復元
    demasked_data = crypto_mask.remove_mask_from_data(encrypted_masked, mask_params, key_type)

    # 難読化を解除
    try:
        decrypted_data = indist.deobfuscate_data(demasked_data)
    except Exception as e:
        print(f"Error: データの難読化解除に失敗しました: {e}")
        sys.exit(1)

    # 出力ファイルに書き込み
    try:
        with open(args.output, 'wb') as f:
            f.write(decrypted_data)
    except IOError as e:
        print(f"Error: ファイルの書き込みに失敗しました: {e}")
        sys.exit(1)

    end_time = time.time()

    # 結果出力
    print(f"復号が完了しました！")
    print(f"出力ファイル: {args.output}")
    if args.verbose:
        print(f"処理時間: {end_time - start_time:.2f}秒")
        print(f"復号ファイルサイズ: {os.path.getsize(args.output)} バイト")

    # 鍵の種類に応じたメッセージ
    if is_true_key:
        print("✅ 真の鍵で復号されました。これは正規のファイルです。")
    else:
        print("⚠️ 偽の鍵で復号されました。これは非正規のファイルです。")


if __name__ == "__main__":
    args = parse_arguments()
    decrypt_file(args)
