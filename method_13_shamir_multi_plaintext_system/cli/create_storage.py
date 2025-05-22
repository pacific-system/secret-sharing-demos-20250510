#!/usr/bin/env python3
"""
暗号書庫生成コマンドラインツール

【責務】
このスクリプトは、シャミア秘密分散法による複数平文復号システムの
暗号書庫を生成するコマンドラインツールです。
RULE-2.5.1に基づき、責務と依存関係を明記します。

【依存関係】
- shamir.constants: システムパラメータ（PARTITION_SIZEなど）
- shamir.crypto_storage_creation: 暗号書庫生成機能
- shamir.map1_key_manager: 第1段階MAP用パーティションマップキー管理機能

【パラメータ一覧】
-o, --output-dir       出力ディレクトリ（デフォルト: ./output）
-a, --a-password       A領域用パスワード（指定しない場合は入力を求めます）
-b, --b-password       B領域用パスワード（指定しない場合は入力を求めます）
-p, --partition-size   パーティションサイズ（デフォルト: PARTITION_SIZE定数値）
-u, --unassigned-shares 未割当シェア数（デフォルト: UNASSIGNED_SHARES定数値）
-s, --active-shares    アクティブシェア数（デフォルト: ACTIVE_SHARES定数値）
-v, --verify           生成後にパーティションマップキーを検証します
"""

import os
import sys
import json
import argparse
from pathlib import Path
from getpass import getpass
import time

# プロジェクトのルートディレクトリをPythonパスに追加
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

from shamir.constants import ShamirConstants
from shamir.crypto_storage_creation import (
    create_crypto_storage, verify_partition_distribution
)
from shamir.map1_key_manager import restore_partition_distribution


def save_config(storage_file: str, a_partition_map_key: str, b_partition_map_key: str) -> dict:
    """
    設定情報をメモリ上に作成する関数

    Args:
        storage_file: 暗号書庫ファイルのパス
        a_partition_map_key: A領域のパーティションマップキー
        b_partition_map_key: B領域のパーティションマップキー

    Returns:
        config: 設定情報の辞書
    """
    # 設定情報
    config = {
        'created_at': int(time.time()),
        'storage_file': os.path.basename(storage_file),
        'a_partition_map_key': a_partition_map_key,
        'b_partition_map_key': b_partition_map_key
    }

    return config


def main():
    """メイン関数"""
    # コマンドライン引数のパース
    parser = argparse.ArgumentParser(description='シャミア秘密分散法による暗号書庫生成ツール')
    parser.add_argument('-o', '--output-dir', type=str, default='./output',
                      help='出力ディレクトリ（デフォルト: ./output）')
    parser.add_argument('-a', '--a-password', type=str, help='A領域用パスワード（指定しない場合は入力を求めます）')
    parser.add_argument('-b', '--b-password', type=str, help='B領域用パスワード（指定しない場合は入力を求めます）')
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
    a_password = args.a_password
    b_password = args.b_password

    # パスワードが指定されていない場合は入力を求める
    if not a_password:
        a_password = getpass('A領域用パスワードを入力してください: ')

    if not b_password:
        b_password = getpass('B領域用パスワードを入力してください: ')

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
            print(f'A領域パーティションMAP: {a_partition}')

            print(f'B領域用パーティションマップキーから復元: {len(b_partition)}個のシェアID')
            print(f'B領域パーティションMAP: {b_partition}')

            # 領域の分離を検証
            is_valid = verify_partition_distribution(a_partition, b_partition, params['PARTITION_SIZE'])
            print(f'パーティション分離検証: {"成功" if is_valid else "失敗"}')

        # 設定情報をメモリ上に作成
        config = save_config(storage_file, a_partition_map_key, b_partition_map_key)

        # 設定情報の表示（必要に応じて）
        # print(f"設定情報: {json.dumps(config, indent=2)}")

        print('\n暗号書庫の生成が完了しました。')
        print('※パーティションマップキーは表示のみでシステム上には保存していません。安全な方法で確実に保管してください。')

    except Exception as e:
        print(f'エラー: 暗号書庫の生成に失敗しました: {e}')
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())