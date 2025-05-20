"""
シャミア秘密分散法 メインアプリケーション

このモジュールでは、シャミア秘密分散法による複数平文復号システムの
メインアプリケーションを提供します。
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Any, Optional

from .constants import ShamirConstants
from .partition import (
    generate_partition_map_key, PartitionManager,
    verify_statistical_indistinguishability, initialize_system
)
from .core import (
    generate_polynomial, evaluate_polynomial, generate_shares,
    lagrange_interpolation, constant_time_select
)
from .crypto import (
    encrypt_json_document, decrypt_json_document,
    load_encrypted_file, save_encrypted_file,
    secure_decrypt, is_valid_json_result,
    init_encrypted_file
)
from .update import (
    update_encrypted_document, verify_update
)
from .tests import (
    security_self_diagnostic
)

# V3形式のインポート確認
try:
    from .formats.v3 import FileFormatV3
    V3_FORMAT_AVAILABLE = True
except ImportError:
    V3_FORMAT_AVAILABLE = False


def init_command(args):
    """
    システムを初期化し、パーティションマップキーを生成します
    また、設計書に従い全てのシェアIDをガベージシェアで埋めた暗号化ファイルの雛形を生成します

    Args:
        args: コマンドライン引数
    """
    try:
        system_info = initialize_system()

        # 結果を表示
        print("システム初期化が完了しました\n")
        print(f"閾値: {system_info['threshold']}")
        print(f"総シェア数: {system_info['total_shares']}")
        print(f"\nAユーザー用パーティションマップキー（重要な秘密情報）:")
        print(f"{system_info['partition_a_key']}")
        print(f"\nBユーザー用パーティションマップキー（重要な秘密情報）:")
        print(f"{system_info['partition_b_key']}")

        # 保存する場合
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(system_info, f, indent=2)
            print(f"\nシステム情報を {args.output} に保存しました")
            print("警告: このファイルには秘密のパーティションマップキーが含まれています。安全に保管してください。")

        # 暗号化ファイル雛形の生成
        if args.generate_empty_file:
            output_dir = args.output_dir if args.output_dir else './output'
            try:
                # V3形式の初期化ファイル生成
                encrypted_file_path = init_encrypted_file(output_dir)
                print(f"\n初期化された暗号化ファイルを生成しました: {encrypted_file_path}")
                print("このファイルには全てのシェアIDがガベージシェアで埋められています。")
            except Exception as e:
                print(f"\nエラー: 暗号化ファイル雛形の生成に失敗しました - {e}")
                print("警告: パーティションマップキーは生成されましたが、暗号化ファイル雛形は生成されませんでした。")

    except Exception as e:
        print(f"エラー: システム初期化に失敗しました - {e}")
        sys.exit(1)


def encrypt_command(args):
    """
    JSON文書を暗号化します

    Args:
        args: コマンドライン引数
    """
    try:
        # JSONファイルを読み込む
        with open(args.input, 'r') as f:
            json_doc = json.load(f)

        # パーティションマップキーを使用
        partition_key = args.partition_key

        # 暗号化を実行
        # シェアIDは第1段階MAPによって選択される
        encrypted_file = encrypt_json_document(
            json_doc,
            args.password,
            partition_key,
            threshold=args.threshold
        )

        # 結果を保存
        save_encrypted_file(encrypted_file, args.output)

        print(f"JSONファイルを暗号化し、{args.output} に保存しました")

    except Exception as e:
        print(f"エラー: 暗号化に失敗しました - {e}")
        sys.exit(1)


def decrypt_command(args):
    """
    暗号化されたファイルを復号します

    Args:
        args: コマンドライン引数
    """
    try:
        # パーティションマップキーを使用
        partition_key = args.partition_key

        # 暗号化ファイルを読み込み
        encrypted_file = load_encrypted_file(args.input)

        # 復号を実行
        json_doc = decrypt_json_document(encrypted_file, partition_key, args.password)

        # 復号に成功したか確認
        if isinstance(json_doc, dict) and 'error' in json_doc:
            print(f"エラー: 復号に失敗しました - {json_doc.get('error')}")
            sys.exit(1)

        # 結果を保存または表示
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(json_doc, f, indent=2)
            print(f"復号されたJSONを {args.output} に保存しました")
        else:
            print(json.dumps(json_doc, indent=2, ensure_ascii=False))

    except Exception as e:
        print(f"エラー: 復号に失敗しました - {e}")
        sys.exit(1)


def update_command(args):
    """
    暗号化ファイル内の文書を更新します

    Args:
        args: コマンドライン引数
    """
    try:
        # パーティションマップキーを使用
        partition_key = args.partition_key

        # 新しいJSONファイルを読み込む
        with open(args.json_input, 'r') as f:
            new_json_doc = json.load(f)

        # 検証を実行
        verify_result = verify_update(args.encrypted_input, new_json_doc, args.password, partition_key)

        if not verify_result['success']:
            print(f"エラー: 更新前検証に失敗しました - {verify_result.get('error')}")
            print(f"詳細: {verify_result.get('details', '')}")
            sys.exit(1)

        # 検証結果を表示
        print("更新前検証結果:")
        print(f"  現在のチャンク数: {verify_result['current_chunks']}")
        print(f"  新しいチャンク数: {verify_result['new_chunks']}")
        print(f"  サイズ変更: {verify_result['size_change']} チャンク({verify_result['size_change_percent']:.1f}%)")

        if verify_result['warnings']:
            print("\n警告:")
            for warning in verify_result['warnings']:
                print(f"  - {warning}")

        # 更新を実行
        if not args.dry_run:
            print("\n更新を実行中...")
            success, result = update_encrypted_document(
                args.encrypted_input,
                new_json_doc,
                args.password,
                partition_key
            )

            if not success:
                print(f"エラー: 更新に失敗しました - {result.get('error')}")
                print(f"詳細: {result.get('details', '')}")
                sys.exit(1)

            # 出力ファイルに保存
            if args.output:
                save_encrypted_file(result, args.output)
                print(f"更新された暗号化ファイルを {args.output} に保存しました")
            else:
                print("更新が完了しました（同じファイルに上書き保存）")
        else:
            print("\n検証のみ実行しました（ドライラン）")

    except Exception as e:
        print(f"エラー: 更新に失敗しました - {e}")
        sys.exit(1)


def security_test_command(args):
    """
    セキュリティ自己診断を実行します

    Args:
        args: コマンドライン引数
    """
    try:
        results = security_self_diagnostic(show_output=True)

        # 結果を保存
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n診断結果を {args.output} に保存しました")

    except Exception as e:
        print(f"エラー: セキュリティ診断に失敗しました - {e}")
        sys.exit(1)


def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(
        description='シャミア秘密分散法による複数平文復号システム'
    )
    subparsers = parser.add_subparsers(dest='command', help='コマンド')

    # initコマンド
    init_parser = subparsers.add_parser('init', help='システムを初期化し、パーティションマップキーを生成する')
    init_parser.add_argument('--output', '-o', help='初期化情報の出力先ファイル（オプション）')
    init_parser.add_argument('--generate-empty-file', '-g', action='store_true',
                          help='初期化時に全シェアIDをガベージシェアで埋めた暗号化ファイルの雛形を生成する')
    init_parser.add_argument('--output-dir', '-d', help='暗号化ファイル雛形の出力先ディレクトリ（デフォルト: ./output）')

    # encryptコマンド
    encrypt_parser = subparsers.add_parser('encrypt', help='JSON文書を暗号化する')
    encrypt_parser.add_argument('--input', '-i', required=True, help='暗号化するJSONファイル')
    encrypt_parser.add_argument('--output', '-o', required=True, help='暗号化されたファイルの出力先')
    encrypt_parser.add_argument('--password', '-p', required=True, help='暗号化パスワード')
    encrypt_parser.add_argument('--partition-key', required=True, help='パーティションマップキー')
    encrypt_parser.add_argument('--threshold', '-t', type=int, default=ShamirConstants.DEFAULT_THRESHOLD,
                              help=f'閾値（デフォルト: {ShamirConstants.DEFAULT_THRESHOLD}）')

    # decryptコマンド
    decrypt_parser = subparsers.add_parser('decrypt', help='暗号化されたファイルを復号する')
    decrypt_parser.add_argument('--input', '-i', required=True, help='復号する暗号化ファイル')
    decrypt_parser.add_argument('--output', '-o', help='復号されたJSONファイルの出力先（指定しない場合は標準出力）')
    decrypt_parser.add_argument('--password', '-p', required=True, help='復号パスワード')
    decrypt_parser.add_argument('--partition-key', required=True, help='パーティションマップキー')

    # updateコマンド
    update_parser = subparsers.add_parser('update', help='暗号化ファイル内の文書を更新する')
    update_parser.add_argument('--encrypted-input', '-e', required=True, help='更新する暗号化ファイル')
    update_parser.add_argument('--json-input', '-j', required=True, help='新しいJSONファイル')
    update_parser.add_argument('--output', '-o', help='更新された暗号化ファイルの出力先（指定しない場合は上書き）')
    update_parser.add_argument('--password', '-p', required=True, help='パスワード')
    update_parser.add_argument('--partition-key', required=True, help='パーティションマップキー')
    update_parser.add_argument('--dry-run', '-d', action='store_true', help='実際に更新せずに検証のみ行う')

    # security-testコマンド
    security_parser = subparsers.add_parser('security-test', help='セキュリティ自己診断を実行する')
    security_parser.add_argument('--output', '-o', help='診断結果の出力先ファイル（オプション）')

    args = parser.parse_args()

    # コマンドに応じた関数を呼び出す
    if args.command == 'init':
        init_command(args)
    elif args.command == 'encrypt':
        encrypt_command(args)
    elif args.command == 'decrypt':
        decrypt_command(args)
    elif args.command == 'update':
        update_command(args)
    elif args.command == 'security-test':
        security_test_command(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()