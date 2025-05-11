#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ラビット復号プログラム

暗号化ファイルからパスワードに応じた平文を復元します。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import binascii
from typing import Tuple, Dict, Any, Optional, Union

# インポートエラーを回避するための処理
if __name__ == "__main__":
    # モジュールとして実行された場合の処理
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        DECRYPT_CHUNK_SIZE,
        DECRYPTED_FILE_PATH,
        VERSION
    )
    from method_6_rabbit.stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
else:
    # パッケージの一部として実行された場合の処理
    from .config import (
        DECRYPT_CHUNK_SIZE,
        DECRYPTED_FILE_PATH,
        VERSION
    )
    from .stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE


def read_encrypted_file(file_path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    暗号化されたファイルを読み込む

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (encrypted_data, metadata): 暗号化データとメタデータ
    """
    try:
        with open(file_path, 'rb') as file:
            # マジックヘッダーを確認
            magic = file.read(len(b'RABBIT_ENCRYPTED_V1\n'))
            if magic != b'RABBIT_ENCRYPTED_V1\n':
                raise ValueError("不正なファイル形式です。Rabbit暗号化ファイルではありません。")

            # メタデータサイズを読み取り
            metadata_size_bytes = file.read(4)
            metadata_size = int.from_bytes(metadata_size_bytes, byteorder='big')

            # メタデータを読み取り
            metadata_bytes = file.read(metadata_size)
            metadata = json.loads(metadata_bytes.decode('utf-8'))

            # バージョン確認
            if metadata.get('version') != VERSION:
                print(f"警告: ファイルバージョン ({metadata.get('version')}) と現在のバージョン ({VERSION}) が一致しません")

            # 暗号化データを読み取り
            encrypted_data = file.read()

            return encrypted_data, metadata

    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません")
        sys.exit(1)
    except Exception as e:
        print(f"エラー: ファイルの読み込みに失敗しました: {e}")
        sys.exit(1)


def read_key_from_file(key_file_path: str) -> str:
    """
    鍵ファイルから鍵を読み込む

    Args:
        key_file_path: 鍵ファイルのパス

    Returns:
        鍵の文字列
    """
    try:
        with open(key_file_path, 'r') as file:
            key = file.read().strip()
        return key
    except FileNotFoundError:
        print(f"エラー: 鍵ファイル '{key_file_path}' が見つかりません")
        sys.exit(1)
    except Exception as e:
        print(f"エラー: 鍵ファイルの読み込みに失敗しました: {e}")
        sys.exit(1)


def process_key_input(key_input: str) -> str:
    """
    様々な形式の鍵入力を処理する

    Args:
        key_input: 鍵入力（パスワード、16進数文字列、ファイルパス）

    Returns:
        処理された鍵文字列
    """
    # ファイルからの読み込み
    if key_input.startswith("file:"):
        key_file_path = key_input[5:]
        return read_key_from_file(key_file_path)

    # 16進数文字列の処理
    elif key_input.startswith("hex:"):
        hex_key = key_input[4:]
        try:
            # 16進数文字列を検証して文字列に変換（UTF-8として復号）
            raw_bytes = binascii.unhexlify(hex_key)
            try:
                # UTF-8として復号可能なら、それをパスワードとして使用
                return raw_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # UTF-8として解釈できない場合は16進数文字列をそのまま使用
                return hex_key
        except ValueError:
            print(f"エラー: 不正な16進数文字列です: {hex_key}")
            sys.exit(1)

    # 通常のパスワードはそのまま返す
    return key_input


def decrypt_data(encrypted_data: bytes, password: str, metadata: Dict[str, Any]) -> Tuple[bytes, str]:
    """
    暗号化データをパスワードを使用して復号

    Args:
        encrypted_data: 暗号化データ
        password: 復号用パスワード
        metadata: メタデータ

    Returns:
        (復号されたデータ, パス種別("true"/"false"/"unknown"))
    """
    try:
        # メタデータからソルトを取得
        salt = base64.b64decode(metadata['salt'])

        # データ長を取得
        data_length = metadata['data_length']

        # 暗号化データが短すぎないか確認
        if len(encrypted_data) < data_length:
            raise ValueError(f"暗号化データが短すぎます（{len(encrypted_data)} < {data_length}）")

        # StreamSelectorを初期化してストリームを取得
        selector = StreamSelector(salt)
        stream = selector.get_stream_for_decryption(password, data_length)

        # 鍵種別を判定（"true"か"false"）
        key_type = selector.determine_key_type_for_decryption(password)

        # 鍵種別に応じて適切な部分を選択
        if key_type == KEY_TYPE_TRUE:
            # 正規パスワードなら前半部分を使用
            encrypted_part = encrypted_data[:data_length]
        else:
            # 非正規パスワードなら後半部分を使用
            if len(encrypted_data) >= 2 * data_length:
                encrypted_part = encrypted_data[data_length:2*data_length]
            else:
                # データが足りない場合は前半部分を使用（エラーを防ぐため）
                encrypted_part = encrypted_data[:data_length]

        # XORによる復号
        decrypted = bytearray(data_length)
        for i in range(data_length):
            # 単純なXOR復号
            if i < len(encrypted_part):
                decrypted[i] = encrypted_part[i] ^ stream[i]

        # 復号結果の検証
        path_type = "unknown"
        if len(decrypted) >= 16:
            data_check = hashlib.sha256(decrypted[:16]).hexdigest()[:8]
            true_check = metadata.get('true_path_check')
            false_check = metadata.get('false_path_check')

            if data_check == true_check:
                path_type = "true"
            elif data_check == false_check:
                path_type = "false"

        return bytes(decrypted), path_type

    except Exception as e:
        print(f"エラー: データの復号に失敗しました: {e}")
        if os.environ.get('DEBUG') == '1':
            import traceback
            traceback.print_exc()
        sys.exit(1)


def save_decrypted_file(decrypted_data: bytes, output_path: str) -> None:
    """
    復号されたデータをファイルに保存

    Args:
        decrypted_data: 復号されたデータ
        output_path: 出力ファイルパス
    """
    try:
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        print(f"復号されたデータを '{output_path}' に保存しました")

    except Exception as e:
        print(f"エラー: 復号ファイルの保存に失敗しました: {e}")
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数を解析

    Returns:
        解析された引数オブジェクト
    """
    parser = argparse.ArgumentParser(
        description="Rabbit復号ツール - 暗号化ファイルを復号します",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        help="暗号化ファイルのパス"
    )

    parser.add_argument(
        "-o", "--output",
        default=DECRYPTED_FILE_PATH,
        help="復号ファイルの出力先"
    )

    # 鍵入力オプショングループ（いずれか一つを必須に）
    key_group = parser.add_mutually_exclusive_group(required=True)

    key_group.add_argument(
        "-p", "--password",
        help="復号用パスワード。通常の文字列として処理されます"
    )

    key_group.add_argument(
        "-k", "--key-hex",
        help="16進数形式の鍵（16進数文字列をASCIIとして解釈）"
    )

    key_group.add_argument(
        "-f", "--key-file",
        help="鍵が保存されたファイルのパス"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細なログ出力"
    )

    return parser.parse_args()


def main():
    """メイン関数"""
    # 引数解析
    args = parse_arguments()

    # 鍵入力の処理
    if args.password:
        key_input = args.password
    elif args.key_hex:
        key_input = f"hex:{args.key_hex}"
    elif args.key_file:
        key_input = f"file:{args.key_file}"
    else:
        # ここには到達しないはずだが、念のため
        print("エラー: 鍵が指定されていません")
        sys.exit(1)

    # 鍵入力を処理
    password = process_key_input(key_input)

    if args.verbose and args.key_hex:
        print(f"16進数鍵 '{args.key_hex}' を処理しました")

    print(f"暗号化ファイル '{args.input}' を読み込んでいます...")
    encrypted_data, metadata = read_encrypted_file(args.input)

    if args.verbose:
        print(f"メタデータ: {json.dumps(metadata, indent=2)}")

    print(f"鍵を使用してデータを復号しています...")
    decrypted_data, path_type = decrypt_data(encrypted_data, password, metadata)

    # 復号結果を表示
    if path_type == "true":
        print("正規データへの復号に成功しました")
    elif path_type == "false":
        print("非正規データへの復号に成功しました")
    else:
        print("警告: 復号データの検証に失敗しました。鍵が正しくない可能性があります。")

    # 復号データをファイルに保存
    save_decrypted_file(decrypted_data, args.output)
    print(f"復号が完了しました！ ({len(decrypted_data)} バイト)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n処理が中断されました")
        sys.exit(1)
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        if os.environ.get('DEBUG') == '1':
            import traceback
            traceback.print_exc()
        sys.exit(1)
