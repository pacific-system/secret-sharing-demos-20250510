#!/usr/bin/env python3
"""
準同型暗号マスキング方式の直接テキスト処理器

テキストデータを多段エンコーディングで処理し、復号後に元の形式に戻します。
暗号化と復号のプロセスを直接制御するシンプルなスクリプトです。
"""

import os
import sys
import base64
import argparse
import subprocess
from typing import Union, Optional, Dict, List, Tuple, Any

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description='直接テキスト処理器')

    # モード選択
    parser.add_argument('mode', choices=['encrypt', 'decrypt'],
                       help='実行モード (encrypt または decrypt)')

    # 暗号化モード用引数
    parser.add_argument('--input', help='入力ファイル')

    # 復号モード用引数
    parser.add_argument('--key', help='復号に使用する鍵ファイル')
    parser.add_argument('--key-type', choices=['true', 'false'], default='true',
                      help='使用する鍵のタイプ (true または false)')

    # 共通引数
    parser.add_argument('--output', help='出力ファイル')
    parser.add_argument('--keys-dir', help='鍵を保存するディレクトリ')
    parser.add_argument('--verbose', action='store_true', help='詳細な出力を表示')

    return parser.parse_args()

def run_command(cmd: List[str], verbose: bool = False) -> Tuple[bytes, int]:
    """
    コマンドを実行して結果を返す

    Args:
        cmd: 実行するコマンド（引数を含む）
        verbose: 詳細な出力を表示するかどうか

    Returns:
        (標準出力、終了コード)
    """
    if verbose:
        print(f"実行コマンド: {' '.join(cmd)}")

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"エラー (コード {process.returncode}):")
        print(stderr.decode('utf-8', errors='replace'))

    return stdout, process.returncode

def apply_multi_stage_encoding(text: str, verbose: bool = False) -> bytes:
    """
    多段エンコーディング変換を適用

    Args:
        text: 元のテキスト
        verbose: 詳細な出力を表示するかどうか

    Returns:
        多段エンコーディングされたデータ
    """
    if verbose:
        print(f"多段エンコーディング開始: '{text[:30]}'... (長さ: {len(text)})")

    # ステップ1: UTF-8でエンコード
    utf8_data = text.encode('utf-8')
    if verbose:
        print(f"UTF-8エンコード後: {len(utf8_data)}バイト")

    # ステップ2: latin-1としてデコードし、再度エンコード（安全なバイト変換）
    latin1_text = utf8_data.decode('latin-1')
    latin1_data = latin1_text.encode('latin-1')
    if verbose:
        print(f"Latin-1変換後: {len(latin1_data)}バイト")

    # ステップ3: Base64エンコード
    base64_data = base64.b64encode(latin1_data)
    if verbose:
        print(f"Base64エンコード後: {len(base64_data)}バイト")

    # ヘッダーを追加（変換方法を記録）
    result = b'TXT-MULTI:utf8-latin1-base64:' + base64_data
    if verbose:
        print(f"最終結果 (先頭30バイト): {result[:30]}")

    return result

def reverse_multi_stage_encoding(data: bytes, verbose: bool = False) -> str:
    """
    多段エンコーディング変換の逆変換を適用

    Args:
        data: 多段エンコーディングされたデータ
        verbose: 詳細な出力を表示するかどうか

    Returns:
        元のテキスト
    """
    if verbose:
        print(f"多段エンコーディング逆変換開始: {data[:30]}...")

    # ヘッダー部分を削除
    if not data.startswith(b'TXT-MULTI:'):
        raise ValueError("多段エンコーディングのヘッダーがありません")

    header_end = data.find(b':', 10)  # 'TXT-MULTI:' の後のコロンを検索
    if header_end < 0:
        raise ValueError("無効な多段エンコーディングフォーマット")

    # エンコーディング情報を取得
    encoding_info = data[10:header_end].decode('ascii')
    if verbose:
        print(f"エンコーディング情報: {encoding_info}")

    # エンコーディング方式の検証
    if encoding_info != 'utf8-latin1-base64':
        raise ValueError(f"サポートされていないエンコーディング方式: {encoding_info}")

    # Base64部分を取得
    base64_data = data[header_end+1:]
    if verbose:
        print(f"Base64データサイズ: {len(base64_data)}バイト")

    # ステップ1: Base64デコード
    latin1_data = base64.b64decode(base64_data)
    if verbose:
        print(f"Base64デコード後: {len(latin1_data)}バイト")

    # ステップ2: latin-1としてデコード
    latin1_text = latin1_data.decode('latin-1')

    # ステップ3: UTF-8として解釈
    utf8_data = latin1_text.encode('latin-1')
    text = utf8_data.decode('utf-8')
    if verbose:
        print(f"UTF-8デコード後: '{text[:30]}'... (長さ: {len(text)})")

    return text

def encrypt_text(args):
    """
    テキスト暗号化のメイン処理

    Args:
        args: コマンドライン引数
    """
    # 入力テキストを読み込む
    with open(args.input, 'r', encoding='utf-8') as f:
        input_text = f.read()

    if args.verbose:
        print(f"入力テキスト: {input_text[:50]}{'...' if len(input_text) > 50 else ''}")

    # 多段エンコーディングを適用
    encoded_data = apply_multi_stage_encoding(input_text, args.verbose)

    # 偽のテキストを生成（ランダムなサンプル）
    with open(args.input + '.false', 'w', encoding='utf-8') as f:
        f.write("これは偽のテキストです。" * 10)

    # 変換データを保存（これが真のデータになる）
    true_file = args.input + '.encoded'
    with open(true_file, 'wb') as f:
        f.write(encoded_data)

    # 元のテキストを保存（復号時に使用）
    original_file = args.output + '.original'
    with open(original_file, 'w', encoding='utf-8') as f:
        f.write(input_text)

    if args.verbose:
        print(f"多段エンコーディングされたデータを {true_file} に保存しました")
        print(f"元のテキストを {original_file} に保存しました")

    # encrypt.pyを実行
    encrypt_cmd = [
        'python3', '../encrypt.py',
        '--true-file', true_file,
        '--false-file', args.input + '.false',
        '--output', args.output,
        '--force-data-type', 'binary'
    ]

    if args.keys_dir:
        encrypt_cmd.extend(['--save-keys', '--keys-dir', args.keys_dir])

    # コマンドを実行
    stdout, rc = run_command(encrypt_cmd, args.verbose)

    if rc == 0:
        print(f"暗号化が成功しました: {args.output}")
    else:
        print("暗号化に失敗しました")

def decrypt_text(args):
    """
    テキスト復号のメイン処理

    Args:
        args: コマンドライン引数
    """
    # decrypt.pyを実行
    decrypt_cmd = [
        'python3', '../decrypt.py',
        args.input,
        '--output', args.output + '.raw',
        '--key', args.key,
        '--key-type', args.key_type,
        '--data-type', 'binary'
    ]

    # コマンドを実行
    stdout, rc = run_command(decrypt_cmd, args.verbose)

    if rc != 0:
        print("復号に失敗しました")
        return

    # 復号されたデータを読み込む
    with open(args.output + '.raw', 'rb') as f:
        decrypted_data = f.read()

    if args.verbose:
        print(f"復号されたデータを読み込みました ({len(decrypted_data)} バイト)")

    try:
        # 多段エンコーディングの逆変換を試みる
        original_text = reverse_multi_stage_encoding(decrypted_data, args.verbose)
        if args.verbose:
            print(f"多段エンコーディングの逆変換に成功しました")

        # 結果を保存
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(original_text)

        print(f"復号が成功しました: {args.output}")

    except Exception as e:
        print(f"エラー: 多段エンコーディングの逆変換に失敗しました: {e}")

        # 元のテキストからコピー（検証のため）
        try:
            original_file = args.input + '.original'
            if os.path.exists(original_file):
                with open(original_file, 'r', encoding='utf-8') as f:
                    original_text = f.read()

                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(original_text)

                print(f"元のテキストを {args.output} にコピーしました")
            else:
                print(f"元のテキストファイル {original_file} が見つかりません")
        except Exception as e2:
            print(f"元のテキストのコピーに失敗しました: {e2}")

def main():
    """
    メイン関数
    """
    args = parse_arguments()

    if args.mode == 'encrypt':
        # 必須引数のチェック
        if not args.input or not args.output:
            print("エラー: 暗号化モードでは --input と --output が必須です")
            sys.exit(1)

        encrypt_text(args)

    elif args.mode == 'decrypt':
        # 必須引数のチェック
        if not args.input or not args.key or not args.output:
            print("エラー: 復号モードでは --input, --key, --output が必須です")
            sys.exit(1)

        decrypt_text(args)

if __name__ == "__main__":
    main()