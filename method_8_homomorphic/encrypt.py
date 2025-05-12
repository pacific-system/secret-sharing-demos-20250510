#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の暗号化実行ファイル

このモジュールは、準同型暗号マスキング方式を使用してファイルを暗号化するための
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
import random
from typing import Dict, Any, Tuple, List, Optional

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.config import (
    TRUE_TEXT_PATH,
    FALSE_TEXT_PATH,
    KEY_SIZE_BYTES,
    SALT_SIZE,
    OUTPUT_FORMAT,
    OUTPUT_EXTENSION,
    CRYPTO_ALGORITHM
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
        description='準同型暗号マスキング方式による暗号化ツール'
    )

    parser.add_argument(
        '--true-file', '-t',
        type=str,
        default=TRUE_TEXT_PATH,
        help='真のファイルパス (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--false-file', '-f',
        type=str,
        default=FALSE_TEXT_PATH,
        help='偽のファイルパス (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        default=f'output{OUTPUT_EXTENSION}',
        help=f'出力ファイル名 (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--algorithm', '-a',
        type=str,
        choices=['paillier', 'elgamal', 'hybrid'],
        default=CRYPTO_ALGORITHM,
        help='使用する準同型暗号アルゴリズム (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--key', '-k',
        type=str,
        help='使用する鍵（16進数文字列、省略時はランダム生成）'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='詳細な出力'
    )

    return parser.parse_args()


def generate_key(provided_key: Optional[str] = None) -> bytes:
    """
    暗号化鍵を生成または変換

    Args:
        provided_key: 提供された鍵（16進数文字列）

    Returns:
        生成された鍵
    """
    if provided_key:
        try:
            # 16進数文字列から鍵を復元
            key = binascii.unhexlify(provided_key)
            # 鍵長を調整
            if len(key) < KEY_SIZE_BYTES:
                key = key.ljust(KEY_SIZE_BYTES, b'\0')
            elif len(key) > KEY_SIZE_BYTES:
                key = key[:KEY_SIZE_BYTES]
            return key
        except binascii.Error:
            print(f"Error: 無効な鍵形式です。16進数文字列を指定してください。")
            sys.exit(1)
    else:
        # ランダムな鍵を生成
        return os.urandom(KEY_SIZE_BYTES)


def encrypt_files(args: argparse.Namespace) -> None:
    """
    ファイルを暗号化

    Args:
        args: コマンドライン引数
    """
    start_time = time.time()

    # 鍵の生成または取得
    key = generate_key(args.key)
    salt = os.urandom(SALT_SIZE)

    if args.verbose:
        print(f"暗号化鍵: {binascii.hexlify(key).decode()}")
        print(f"ソルト: {binascii.hexlify(salt).decode()}")

    # ファイルの内容を読み込み
    try:
        with open(args.true_file, 'rb') as f:
            true_content = f.read()
        with open(args.false_file, 'rb') as f:
            false_content = f.read()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # 準同型暗号マスクを準備
    crypto_mask = CryptoMask()
    crypto_params = crypto_mask.initialize()

    # 識別不能性ラッパーを準備
    indist = IndistinguishableWrapper()
    indist.generate_seed(key, salt)

    # マスクパラメータの生成
    mask_params = crypto_mask.generate_mask_params(key, salt)

    # データにマスクを適用
    true_data = indist.obfuscate_data(true_content)
    false_data = indist.obfuscate_data(false_content)

    # 真データと偽データをマスキング
    true_masked = crypto_mask.apply_mask_to_data(true_data, mask_params)
    false_masked = crypto_mask.apply_mask_to_data(false_data, mask_params)

    # メタデータを準備
    metadata = {
        'format': OUTPUT_FORMAT,
        'version': '1.0',
        'salt': base64.b64encode(salt).decode(),
        'algorithm': args.algorithm,
        'true_size': len(true_content),
        'false_size': len(false_content),
        'true_chunks': true_masked['chunks'],
        'false_chunks': false_masked['chunks'],
        'paillier_public': {
            'n': str(crypto_params['paillier_public']['n']),
            'g': str(crypto_params['paillier_public']['g'])
        },
        'elgamal_public': {
            'p': str(crypto_params['elgamal_public']['p']),
            'g': str(crypto_params['elgamal_public']['g']),
            'y': str(crypto_params['elgamal_public']['y'])
        },
        'mask_params': {
            'paillier': {
                'offset': mask_params['paillier']['offset'],
                'scale': mask_params['paillier']['scale'],
                'transform': mask_params['paillier']['transform']
            },
            'elgamal': {
                'multiplier': mask_params['elgamal']['multiplier'],
                'power': mask_params['elgamal']['power'],
                'transform': mask_params['elgamal']['transform']
            }
        }
    }

    # 暗号化データを準備
    encrypted_data = {
        'metadata': metadata,
        'paillier_private': {
            'lambda': str(crypto_params['paillier_private']['lambda']),
            'mu': str(crypto_params['paillier_private']['mu']),
            'n': str(crypto_params['paillier_private']['n'])
        },
        'elgamal_private': {
            'x': str(crypto_params['elgamal_private']['x']),
            'p': str(crypto_params['elgamal_private']['p'])
        }
    }

    # アルゴリズムに基づいて暗号文を追加
    if args.algorithm in ['paillier', 'hybrid']:
        encrypted_data['true_paillier'] = [str(n) for n in true_masked['paillier']]
        encrypted_data['false_paillier'] = [str(n) for n in false_masked['paillier']]

    if args.algorithm in ['elgamal', 'hybrid']:
        # ElGamalの場合、(c1, c2)のタプルを文字列に変換
        encrypted_data['true_elgamal'] = [
            [str(c[0]), str(c[1])] for c in true_masked['elgamal']
        ]
        encrypted_data['false_elgamal'] = [
            [str(c[0]), str(c[1])] for c in false_masked['elgamal']
        ]

    # 出力ファイルに書き込み
    try:
        with open(args.output, 'w') as f:
            json.dump(encrypted_data, f, indent=2)
    except IOError as e:
        print(f"Error: ファイルの書き込みに失敗しました: {e}")
        sys.exit(1)

    end_time = time.time()

    # 結果出力
    print(f"暗号化が完了しました！")
    print(f"出力ファイル: {args.output}")
    print(f"鍵（安全に保管してください）: {binascii.hexlify(key).decode()}")
    if args.verbose:
        print(f"処理時間: {end_time - start_time:.2f}秒")
        print(f"真ファイルサイズ: {len(true_content)} バイト")
        print(f"偽ファイルサイズ: {len(false_content)} バイト")
        print(f"暗号化後ファイルサイズ: {os.path.getsize(args.output)} バイト")


if __name__ == "__main__":
    args = parse_arguments()
    encrypt_files(args)
