#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 主実行モジュール

暗号化と復号を統合的に実行し、動作を確認するためのモジュールです。
"""

import os
import sys
import argparse
import datetime
import binascii
import time
from typing import Dict, List, Tuple, Optional, Any

# 内部モジュールのインポート
try:
    from encrypt import encrypt
    from decrypt import decrypt
except ImportError:
    # パッケージとして実行された場合のインポート
    from .encrypt import encrypt
    from .decrypt import decrypt


def test_encrypt_decrypt(true_file: str, false_file: str) -> None:
    """
    暗号化と復号のテストを実行する

    Args:
        true_file: 正規ファイルのパス
        false_file: 非正規ファイルのパス
    """
    print("------ 不確定性転写暗号化方式のテスト ------")

    # タイムスタンプを取得
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    # 出力ファイル名の設定
    output_file = f"test_output/indeterministic_test_{timestamp}.indet"

    # 暗号化実行
    print(f"\n[1] 暗号化テスト: {true_file} + {false_file} -> {output_file}")
    start_time = time.time()
    key, output_path = encrypt(true_file, false_file, output_file)
    encrypt_time = time.time() - start_time
    key_hex = binascii.hexlify(key).decode('ascii')
    print(f"暗号化完了: 所要時間 {encrypt_time:.2f}秒")
    print(f"生成された鍵: {key_hex}")

    # 正規鍵による復号テスト
    print(f"\n[2] 正規鍵による復号テスト")
    start_time = time.time()
    true_output = decrypt(output_path, key)
    decrypt_time = time.time() - start_time
    print(f"復号完了: 所要時間 {decrypt_time:.2f}秒")
    print(f"出力ファイル: {true_output}")

    # 別の鍵を生成して非正規復号のテスト
    print(f"\n[3] 非正規鍵による復号テスト（ランダム鍵）")
    fake_key = os.urandom(32)
    fake_key_hex = binascii.hexlify(fake_key).decode('ascii')
    print(f"非正規鍵: {fake_key_hex}")
    start_time = time.time()
    false_output = decrypt(output_path, fake_key)
    decrypt_time = time.time() - start_time
    print(f"復号完了: 所要時間 {decrypt_time:.2f}秒")
    print(f"出力ファイル: {false_output}")

    print("\n------ テスト完了 ------")


def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式のテストスクリプト")

    subparsers = parser.add_subparsers(dest="command", help="実行するコマンド")

    # 暗号化コマンド
    encrypt_parser = subparsers.add_parser("encrypt", help="ファイルを暗号化")
    encrypt_parser.add_argument("true_file", help="正規ファイルのパス")
    encrypt_parser.add_argument("false_file", help="非正規ファイルのパス")
    encrypt_parser.add_argument("--output", "-o", help="出力ファイルのパス")
    encrypt_parser.add_argument("--save-key", action="store_true", help="鍵をファイルに保存")

    # 復号コマンド
    decrypt_parser = subparsers.add_parser("decrypt", help="ファイルを復号")
    decrypt_parser.add_argument("input_file", help="暗号化ファイルのパス")
    decrypt_parser.add_argument("key", help="復号鍵（16進数形式）")
    decrypt_parser.add_argument("--output", "-o", help="出力ファイルのパス")

    # テストコマンド
    test_parser = subparsers.add_parser("test", help="暗号化と復号のテストを実行")
    test_parser.add_argument("--true-file", default="common/true-false-text/true.text", help="正規ファイルのパス")
    test_parser.add_argument("--false-file", default="common/true-false-text/false.text", help="非正規ファイルのパス")

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    if args.command == "encrypt":
        # 暗号化モード
        output_file = args.output
        key, output_path = encrypt(args.true_file, args.false_file, output_file, args.save_key)
        key_hex = binascii.hexlify(key).decode('ascii')
        print(f"暗号化完了: {output_path}")
        print(f"鍵: {key_hex}")
        return 0

    elif args.command == "decrypt":
        # 復号モード
        try:
            key = binascii.unhexlify(args.key)
        except binascii.Error:
            print("エラー: 鍵は有効な16進数文字列である必要があります", file=sys.stderr)
            return 1

        output_path = decrypt(args.input_file, key, args.output)
        print(f"復号完了: {output_path}")
        return 0

    elif args.command == "test":
        # テストモード
        test_encrypt_decrypt(args.true_file, args.false_file)
        return 0

    else:
        # コマンドが指定されていない場合はヘルプを表示
        print("コマンドを指定してください。詳細は --help オプションを参照してください。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())