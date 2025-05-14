#!/usr/bin/env python3
"""
準同型暗号マスキング方式の改良テキスト処理ラッパー

多段エンコーディングを使用してテキストファイルを処理し、
暗号化と復号のプロセスを改善するためのラッパースクリプトです。
"""

import os
import sys
import argparse
import tempfile
import subprocess
import base64
from typing import Tuple, Optional, List, Dict, Any, Union

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

# TextAdapterをインポート
from method_8_homomorphic.crypto_adapters import TextAdapter

def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description='改良テキスト処理ラッパー')

    # モード選択
    parser.add_argument('mode', choices=['encrypt', 'decrypt'],
                       help='実行モード (encrypt または decrypt)')

    # 暗号化モード用引数
    parser.add_argument('--true-file', help='真のデータを含むファイル')
    parser.add_argument('--false-file', help='偽のデータを含むファイル')

    # 復号モード用引数
    parser.add_argument('--encrypted-file', help='暗号化されたファイル')
    parser.add_argument('--key-file', help='復号に使用する鍵ファイル')
    parser.add_argument('--key-type', choices=['true', 'false'], default='true',
                      help='使用する鍵のタイプ (true または false)')

    # 共通引数
    parser.add_argument('--output', help='出力ファイル')
    parser.add_argument('--keys-dir', help='鍵を保存/読み込むディレクトリ')
    parser.add_argument('--verbose', action='store_true', help='詳細な出力を表示')

    return parser.parse_args()

def run_command(cmd: List[str], cwd: Optional[str] = None) -> Tuple[str, str, int]:
    """
    コマンドを実行して結果を返す

    Args:
        cmd: 実行するコマンド（引数を含む）
        cwd: 現在の作業ディレクトリ

    Returns:
        (標準出力, 標準エラー, 終了コード)
    """
    print(f"実行コマンド: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=cwd, universal_newlines=True
    )
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"エラー (コード {process.returncode}):")
        print(stderr)

    return stdout, stderr, process.returncode

def preprocess_text_file(file_path: str, verbose: bool = False) -> Tuple[str, bytes]:
    """
    テキストファイルに多段エンコーディングを適用する前処理

    Args:
        file_path: 処理するファイルのパス
        verbose: 詳細な出力を表示するかどうか

    Returns:
        (一時ファイルのパス, 元のデータのバイト列)
    """
    # 元のファイルの内容を読み込む
    with open(file_path, 'rb') as f:
        original_data = f.read()

    if verbose:
        print(f"元のファイル {file_path} を読み込みました ({len(original_data)} バイト)")

    # TextAdapterを使用して多段エンコーディングを適用
    adapter = TextAdapter()
    processed_data = adapter.to_processable(original_data)

    if verbose:
        print(f"多段エンコーディングを適用しました ({len(processed_data)} バイト)")

    # 処理したデータを一時ファイルに書き込む
    with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as temp_file:
        temp_file_path = temp_file.name
        temp_file.write(processed_data)

    if verbose:
        print(f"処理済みデータを一時ファイル {temp_file_path} に書き込みました")

    return temp_file_path, original_data

def postprocess_text_file(file_path: str, original_data_size: int, verbose: bool = False) -> str:
    """
    復号されたテキストファイルに多段エンコーディングの逆変換を適用する後処理

    Args:
        file_path: 処理するファイルのパス
        original_data_size: 元のデータのサイズ（バイト単位）
        verbose: 詳細な出力を表示するかどうか

    Returns:
        処理後のファイルパス
    """
    # 復号されたファイルの内容を読み込む
    with open(file_path, 'rb') as f:
        decrypted_data = f.read()

    if verbose:
        print(f"復号されたファイル {file_path} を読み込みました ({len(decrypted_data)} バイト)")

    # TextAdapterを使用して多段エンコーディングの逆変換を適用
    adapter = TextAdapter()
    try:
        restored_text = adapter.from_processable(decrypted_data)

        if verbose:
            print(f"多段エンコーディングの逆変換を適用しました")
            print(f"復元されたテキスト (先頭50文字): {restored_text[:50]}")

        # 元のサイズと復元後のサイズが大きく異なる場合は警告
        restored_size = len(restored_text.encode('utf-8'))
        if abs(restored_size - original_data_size) > original_data_size * 0.1:
            print(f"警告: 復元後のサイズ ({restored_size} バイト) が元のサイズ ({original_data_size} バイト) と大きく異なります")

        # 処理したデータを一時ファイルに書き込む
        processed_file_path = file_path + '.processed'
        with open(processed_file_path, 'w', encoding='utf-8') as f:
            f.write(restored_text)

        if verbose:
            print(f"復元されたテキストを {processed_file_path} に書き込みました")

        return processed_file_path

    except Exception as e:
        print(f"エラー: テキストの復元中に例外が発生しました: {e}")
        return file_path

def encrypt_text_files(args):
    """
    テキストファイルの暗号化を実行

    Args:
        args: コマンドライン引数
    """
    # 真のファイルを前処理
    true_temp_path, true_original_data = preprocess_text_file(args.true_file, args.verbose)

    # 偽のファイルを前処理
    false_temp_path, false_original_data = preprocess_text_file(args.false_file, args.verbose)

    try:
        # 暗号化コマンドを構築
        encrypt_cmd = [
            "python3", "../encrypt.py",
            "--true-file", true_temp_path,
            "--false-file", false_temp_path,
            "--output", args.output
        ]

        if args.keys_dir:
            encrypt_cmd.extend(["--save-keys", "--keys-dir", args.keys_dir])

        if args.verbose:
            encrypt_cmd.append("--verbose")

        # 暗号化を実行
        stdout, stderr, exit_code = run_command(encrypt_cmd)

        if exit_code == 0:
            print("暗号化が成功しました")
            print(f"出力ファイル: {args.output}")

            # 元のデータサイズを保存（復号時に使用するため）
            metadata_file = args.output + ".metadata"
            with open(metadata_file, 'w') as f:
                f.write(f"{len(true_original_data)}\n")

            if args.verbose:
                print(f"メタデータを {metadata_file} に保存しました")
        else:
            print("暗号化が失敗しました")

    finally:
        # 一時ファイルを削除
        for path in [true_temp_path, false_temp_path]:
            try:
                os.unlink(path)
                if args.verbose:
                    print(f"一時ファイル {path} を削除しました")
            except Exception as e:
                print(f"警告: 一時ファイル {path} の削除に失敗しました: {e}")

def decrypt_text_file(args):
    """
    暗号化されたテキストファイルの復号を実行

    Args:
        args: コマンドライン引数
    """
    # メタデータファイルから元のデータサイズを読み込む
    metadata_file = args.encrypted_file + ".metadata"
    try:
        with open(metadata_file, 'r') as f:
            original_size = int(f.readline().strip())
            if args.verbose:
                print(f"メタデータから元のサイズを読み込みました: {original_size} バイト")
    except (FileNotFoundError, ValueError) as e:
        print(f"警告: メタデータファイルからサイズを読み込めませんでした: {e}")
        original_size = 0

    # 復号コマンドを構築
    decrypt_cmd = [
        "python3", "../decrypt.py",
        args.encrypted_file,
        "--output", args.output,
        "--key", args.key_file,
        "--key-type", args.key_type
    ]

    if args.verbose:
        decrypt_cmd.append("--verbose")

    # 復号を実行
    stdout, stderr, exit_code = run_command(decrypt_cmd)

    if exit_code == 0:
        print("復号が成功しました")

        # 復号されたファイルを後処理
        processed_file = postprocess_text_file(args.output, original_size, args.verbose)

        print(f"最終出力ファイル: {processed_file}")
    else:
        print("復号が失敗しました")

def main():
    """
    メイン関数
    """
    args = parse_arguments()

    if args.mode == 'encrypt':
        # 必須引数のチェック
        if not args.true_file or not args.false_file or not args.output:
            print("エラー: 暗号化モードでは --true-file, --false-file, --output が必須です")
            sys.exit(1)

        encrypt_text_files(args)

    elif args.mode == 'decrypt':
        # 必須引数のチェック
        if not args.encrypted_file or not args.key_file or not args.output:
            print("エラー: 復号モードでは --encrypted-file, --key-file, --output が必須です")
            sys.exit(1)

        decrypt_text_file(args)

if __name__ == "__main__":
    main()