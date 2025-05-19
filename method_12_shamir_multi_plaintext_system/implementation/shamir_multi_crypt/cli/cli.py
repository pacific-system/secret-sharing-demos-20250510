#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
コマンドラインインターフェースのメインモジュール

このモジュールは、ArgParseを使用してコマンドラインインターフェースを構築し、
各サブコマンドをディスパッチする機能を提供します。
"""

import sys
import argparse
from .commands import generate_command, init_command, decrypt_command, update_command


def create_parser():
    """
    コマンドライン引数パーサーを作成

    Returns:
        argparse.ArgumentParser: 設定されたパーサー
    """
    # トップレベルパーサー
    parser = argparse.ArgumentParser(
        prog='shamir-multi-crypt',
        description='シャミア秘密分散法による複数平文復号システム'
    )

    # サブコマンドのパーサー
    subparsers = parser.add_subparsers(
        title='サブコマンド',
        description='利用可能なサブコマンド',
        help='詳細なヘルプは各サブコマンドの後に --help を追加',
        dest='command'
    )

    # 'generate' コマンド
    generate_parser = subparsers.add_parser(
        'generate',
        help='シェアIDセットを生成'
    )
    generate_parser.add_argument(
        '--size', '-s',
        type=int,
        default=100,
        help='生成するシェアIDの数 (デフォルト: 100)'
    )
    generate_parser.add_argument(
        '--output', '-o',
        type=str,
        help='出力ファイル名 (デフォルト: shares-{timestamp}.json)'
    )
    generate_parser.add_argument(
        '--ratio', '-r',
        type=str,
        default='35:35:30',
        help='A:B:未割当の比率 (デフォルト: "35:35:30")'
    )

    # 'init' コマンド
    init_parser = subparsers.add_parser(
        'init',
        help='新規暗号化ファイルを作成し、複数のJSON文書を暗号化'
    )
    init_parser.add_argument(
        '--file-a', '-a',
        required=True,
        help='A文書のJSONファイル'
    )
    init_parser.add_argument(
        '--file-b', '-b',
        required=True,
        help='B文書のJSONファイル'
    )
    init_parser.add_argument(
        '--password-a', '-pa',
        help='A文書のパスワード（指定しない場合はプロンプト）'
    )
    init_parser.add_argument(
        '--password-b', '-pb',
        help='B文書のパスワード（指定しない場合はプロンプト）'
    )
    init_parser.add_argument(
        '--shares', '-s',
        required=True,
        help='シェアIDセットのJSONファイル'
    )
    init_parser.add_argument(
        '--output', '-o',
        required=True,
        help='出力暗号化ファイル名'
    )
    init_parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=3,
        help='復号に必要な最小シェア数（閾値）(デフォルト: 3)'
    )

    # 'decrypt' コマンド
    decrypt_parser = subparsers.add_parser(
        'decrypt',
        help='暗号化ファイルから特定のJSON文書を復号'
    )
    decrypt_parser.add_argument(
        '--input', '-i',
        required=True,
        help='入力暗号化ファイル'
    )
    decrypt_parser.add_argument(
        '--shares', '-s',
        required=True,
        help='シェアIDリスト'
    )
    decrypt_parser.add_argument(
        '--password', '-p',
        help='パスワード（指定しない場合はプロンプト）'
    )
    decrypt_parser.add_argument(
        '--output', '-o',
        help='出力JSONファイル (デフォルト: decrypted-{timestamp}.json)'
    )

    # 'update' コマンド
    update_parser = subparsers.add_parser(
        'update',
        help='暗号化ファイル内の特定文書を更新'
    )
    update_parser.add_argument(
        '--input', '-i',
        required=True,
        help='入力暗号化ファイル'
    )
    update_parser.add_argument(
        '--file', '-f',
        required=True,
        help='更新データのJSONファイル'
    )
    update_parser.add_argument(
        '--shares', '-s',
        required=True,
        help='シェアIDリスト'
    )
    update_parser.add_argument(
        '--password', '-p',
        help='パスワード（指定しない場合はプロンプト）'
    )
    update_parser.add_argument(
        '--output', '-o',
        help='出力暗号化ファイル（指定しない場合は上書き）'
    )
    update_parser.add_argument(
        '--no-backup', '-n',
        dest='backup',
        action='store_false',
        help='バックアップを作成しない'
    )
    update_parser.set_defaults(backup=True)

    return parser


def main():
    """
    コマンドラインインターフェースのメインエントリーポイント

    Returns:
        int: 終了コード
    """
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # サブコマンドのディスパッチ
    if args.command == 'generate':
        return generate_command(args)
    elif args.command == 'init':
        return init_command(args)
    elif args.command == 'decrypt':
        return decrypt_command(args)
    elif args.command == 'update':
        return update_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
