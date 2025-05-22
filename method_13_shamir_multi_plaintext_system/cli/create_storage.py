#!/usr/bin/env python3
"""
暗号書庫生成コマンドラインツール

このスクリプトは、シャミア秘密分散法による複数平文復号システムの
暗号書庫を生成するコマンドラインツールです。
"""

import os
import sys
import json
import argparse
from pathlib import Path
from getpass import getpass
import secrets
import time

# プロジェクトのルートディレクトリをPythonパスに追加
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

from method_13_shamir_multi_plaintext_system.shamir.constants import ShamirConstants
from method_13_shamir_multi_plaintext_system.shamir.crypto_storage_creation import (
    create_crypto_storage, restore_partition_distribution, verify_partition_distribution
)


def validate_password_strength(password: str) -> bool:
    """
    パスワードの強度を検証する関数

    Args:
        password: 検証するパスワード

    Returns:
        valid: 検証結果（True=有効、False=無効）
    """
    # 最小長
    if len(password) < 8:
        return False

    # 文字種の多様性（少なくとも2種類以上の文字種を含む）
    char_types = 0
    if any(c.islower() for c in password):
        char_types += 1
    if any(c.isupper() for c in password):
        char_types += 1
    if any(c.isdigit() for c in password):
        char_types += 1
    if any(not c.isalnum() for c in password):
        char_types += 1

    return char_types >= 2


def generate_random_password() -> str:
    """
    安全なランダムパスワードを生成する関数

    Returns:
        password: 生成されたパスワード
    """
    # URL安全なBase64エンコードされたランダムトークンを生成
    # 16バイトのエントロピー（約128ビット）
    return secrets.token_urlsafe(16)


def save_config(storage_file: str, a_partition_map_key: str, b_partition_map_key: str,
               output_dir: str, auto_generated: bool = False) -> str:
    """
    設定情報を保存する関数

    Args:
        storage_file: 暗号書庫ファイルのパス
        a_partition_map_key: A領域のパーティションマップキー
        b_partition_map_key: B領域のパーティションマップキー
        output_dir: 出力ディレクトリ
        auto_generated: パスワードが自動生成されたかどうか

    Returns:
        config_file: 設定ファイルのパス
    """
    # 設定情報
    config = {
        'created_at': int(time.time()),
        'storage_file': os.path.basename(storage_file),
        'a_partition_map_key': a_partition_map_key,
        'b_partition_map_key': b_partition_map_key,
        'auto_generated': auto_generated
    }

    # 設定ファイルのパス
    config_file = os.path.join(output_dir, f"crypto_storage_config_{int(time.time())}.json")

    # 設定ファイルを保存
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

    return config_file


def main():
    """メイン関数"""
    # コマンドライン引数のパース
    parser = argparse.ArgumentParser(description='シャミア秘密分散法による暗号書庫生成ツール')
    parser.add_argument('-o', '--output-dir', type=str, default='./output',
                      help='出力ディレクトリ（デフォルト: ./output）')
    parser.add_argument('-a', '--a-password', type=str, help='A領域用パスワード（指定しない場合は入力を求めます）')
    parser.add_argument('-b', '--b-password', type=str, help='B領域用パスワード（指定しない場合は入力を求めます）')
    parser.add_argument('-g', '--generate-passwords', action='store_true',
                      help='安全なランダムパスワードを自動生成します')
    parser.add_argument('-p', '--partition-size', type=int, default=ShamirConstants.PARTITION_SIZE,
                      help=f'パーティションサイズ（デフォルト: {ShamirConstants.PARTITION_SIZE}）')
    parser.add_argument('-u', '--unassigned-shares', type=int, default=ShamirConstants.UNASSIGNED_SHARES,
                      help=f'未割当シェア数（デフォルト: {ShamirConstants.UNASSIGNED_SHARES}）')
    parser.add_argument('-s', '--active-shares', type=int, default=ShamirConstants.ACTIVE_SHARES,
                      help=f'アクティブシェア数（デフォルト: {ShamirConstants.ACTIVE_SHARES}）')
    parser.add_argument('-v', '--verify', action='store_true',
                      help='生成後にパーティションマップキーを検証します')

    args = parser.parse_args()

    # 出力ディレクトリの作成
    os.makedirs(args.output_dir, exist_ok=True)

    # パスワードの設定
    auto_generated = False
    if args.generate_passwords:
        a_password = generate_random_password()
        b_password = generate_random_password()
        auto_generated = True
        print('パスワードを自動生成しました。設定ファイルに保存されます。')
    else:
        # コマンドライン引数からパスワードを取得
        a_password = args.a_password
        b_password = args.b_password

        # パスワードが指定されていない場合は入力を求める
        if not a_password:
            a_password = getpass('A領域用パスワードを入力してください: ')

            # パスワードの強度を検証
            if not validate_password_strength(a_password):
                print('警告: A領域用パスワードが弱いです。少なくとも8文字以上で、2種類以上の文字種を含めてください。')
                confirm = input('このパスワードを使用しますか？ [y/N]: ')
                if confirm.lower() != 'y':
                    print('暗号書庫の生成を中止します。')
                    return

        if not b_password:
            b_password = getpass('B領域用パスワードを入力してください: ')

            # パスワードの強度を検証
            if not validate_password_strength(b_password):
                print('警告: B領域用パスワードが弱いです。少なくとも8文字以上で、2種類以上の文字種を含めてください。')
                confirm = input('このパスワードを使用しますか？ [y/N]: ')
                if confirm.lower() != 'y':
                    print('暗号書庫の生成を中止します。')
                    return

    # パラメータの設定
    garbage_shares = args.partition_size - args.active_shares
    params = {
        'ACTIVE_SHARES': args.active_shares,
        'GARBAGE_SHARES': garbage_shares,
        'PARTITION_SIZE': args.partition_size,
        'UNASSIGNED_SHARES': args.unassigned_shares,
        'SHARE_ID_SPACE': args.partition_size * 2 + args.unassigned_shares,
    }

    print('暗号書庫を生成しています...')

    # 暗号書庫の生成
    try:
        storage_file, a_partition_map_key, b_partition_map_key = create_crypto_storage(
            a_password, b_password, args.output_dir, params
        )

        print(f'暗号書庫を生成しました: {storage_file}')
        print(f'A領域用パーティションマップキー: {a_partition_map_key}')
        print(f'B領域用パーティションマップキー: {b_partition_map_key}')

        # 検証オプションが指定されている場合は検証を実行
        if args.verify:
            print('パーティションマップキーを検証しています...')

            # パーティションマップキーから第1段階MAPを復元
            a_partition = restore_partition_distribution(a_partition_map_key, a_password)
            b_partition = restore_partition_distribution(b_partition_map_key, b_password)

            # 復元結果を検証
            print(f'A領域用パーティションマップキーから復元: {len(a_partition)}個のシェアID')
            print(f'B領域用パーティションマップキーから復元: {len(b_partition)}個のシェアID')

            # 領域の分離を検証
            is_valid = verify_partition_distribution(a_partition, b_partition, params['PARTITION_SIZE'])
            print(f'パーティション分離検証: {"成功" if is_valid else "失敗"}')

        # 設定ファイルを保存
        config_file = save_config(
            storage_file, a_partition_map_key, b_partition_map_key,
            args.output_dir, auto_generated
        )

        print(f'設定ファイルを保存しました: {config_file}')

        if auto_generated:
            # 自動生成されたパスワードを表示
            print('\n重要: 以下のパスワードを安全な場所に保管してください。')
            print(f'A領域用パスワード: {a_password}')
            print(f'B領域用パスワード: {b_password}')

        print('\n暗号書庫の生成が完了しました。')

    except Exception as e:
        print(f'エラー: 暗号書庫の生成に失敗しました: {e}')
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())