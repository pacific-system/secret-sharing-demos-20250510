#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
改良版ラビット暗号化プログラム

正規キー・非正規キーの概念を排除し、
どのキーでも同様に可読なテキストが復号される方式に改良。
ユーザーの意図によって「どちらが真のデータか」を決定できます。
"""

import os
import sys
import argparse
import json
import secrets
import binascii
import base64
import hashlib
import hmac
import datetime
from typing import Tuple, Dict, Any, List, Optional, Union, Callable

# インポートエラーを回避するための処理
if __name__ == "__main__":
    # モジュールとして実行された場合の処理
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        ENCRYPT_CHUNK_SIZE,
        TRUE_FILE_PATH,
        FALSE_FILE_PATH,
        ENCRYPTED_FILE_PATH,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
    from method_6_rabbit.stream_selector import StreamSelector
    from method_6_rabbit.rabbit_stream import derive_key, RabbitStreamGenerator
else:
    # パッケージの一部として実行された場合の処理
    from .config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        ENCRYPT_CHUNK_SIZE,
        TRUE_FILE_PATH,
        FALSE_FILE_PATH,
        ENCRYPTED_FILE_PATH,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
    from .stream_selector import StreamSelector
    from .rabbit_stream import derive_key, RabbitStreamGenerator

# 暗号化方式
ENCRYPTION_METHOD_SYMMETRIC = "symmetric"

# ソルトサイズの定義
SALT_SIZE = 16

# パス種別の定義 (正規/非正規ではなく中立的な名称に変更)
PATH_A = "path_a"  # 従来の "true" に相当
PATH_B = "path_b"  # 従来の "false" に相当


def generate_master_key() -> bytes:
    """
    強力なランダムマスター鍵を生成

    Returns:
        16バイトのマスター鍵
    """
    return secrets.token_bytes(RABBIT_KEY_SIZE)


def xor_encrypt_data(data: bytes, stream: bytes) -> bytes:
    """
    データをXORストリーム暗号化

    Args:
        data: 暗号化するバイト列
        stream: 暗号化ストリーム

    Returns:
        暗号化されたバイト列
    """
    # データ長とストリーム長が一致することを確認
    if len(data) > len(stream):
        raise ValueError(f"ストリーム長（{len(stream)}バイト）がデータ長（{len(data)}バイト）より小さいです")

    # XORによる暗号化
    encrypted = bytearray(len(data))
    for i in range(len(data)):
        encrypted[i] = data[i] ^ stream[i]

    return bytes(encrypted)


def read_file(file_path: str) -> bytes:
    """
    ファイルの内容を読み込む

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        ファイルの内容
    """
    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except Exception as e:
        print(f"エラー: ファイル '{file_path}' の読み込みに失敗しました: {e}")
        sys.exit(1)


def create_symmetric_encrypted_container(path_a_data: bytes, path_b_data: bytes) -> Tuple[str, str, bytes, Dict[str, Any]]:
    """
    改良型対称暗号化コンテナを作成

    Args:
        path_a_data: パスAのデータ (従来の正規データ)
        path_b_data: パスBのデータ (従来の非正規データ)

    Returns:
        (path_a_password, path_b_password, encrypted_data, metadata)
    """
    # ランダムなパスワードを生成
    path_a_password = secrets.token_hex(16)
    path_b_password = secrets.token_hex(16)

    # ソルトを生成
    salt = os.urandom(SALT_SIZE)

    # データ長を揃える
    max_length = max(len(path_a_data), len(path_b_data))

    # パディングを追加
    if len(path_a_data) < max_length:
        padding_length = max_length - len(path_a_data)
        path_a_data = path_a_data + b'\x00' * padding_length

    if len(path_b_data) < max_length:
        padding_length = max_length - len(path_b_data)
        path_b_data = path_b_data + b'\x00' * padding_length

    # パスワードから鍵とIVを生成
    path_a_key, path_a_iv, _ = derive_key(path_a_password, salt)
    path_b_key, path_b_iv, _ = derive_key(path_b_password, salt)

    # ストリーム生成
    path_a_stream_gen = RabbitStreamGenerator(path_a_key, path_a_iv)
    path_b_stream_gen = RabbitStreamGenerator(path_b_key, path_b_iv)

    # 暗号化ストリーム生成
    path_a_stream = path_a_stream_gen.generate(max_length)
    path_b_stream = path_b_stream_gen.generate(max_length)

    # XOR暗号化
    path_a_encrypted = xor_encrypt_data(path_a_data, path_a_stream)
    path_b_encrypted = xor_encrypt_data(path_b_data, path_b_stream)

    # 暗号化データのハッシュ値を計算 (整合性検証用)
    path_a_hash = hashlib.sha256(path_a_data).hexdigest()[:8]
    path_b_hash = hashlib.sha256(path_b_data).hexdigest()[:8]

    # 暗号化データを連結
    encrypted_data = path_a_encrypted + path_b_encrypted

    # メタデータの作成
    metadata = {
        "version": VERSION,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "data_length": max_length,
        "path_a_hash": path_a_hash,
        "path_b_hash": path_b_hash,
        "encryption_method": ENCRYPTION_METHOD_SYMMETRIC,
        # パスワードは含めない
    }

    return path_a_password, path_b_password, encrypted_data, metadata


def add_timestamp_to_filename(filename: str) -> str:
    """
    ファイル名にタイムスタンプを追加する

    Args:
        filename: 元のファイル名

    Returns:
        タイムスタンプが追加されたファイル名
    """
    # ファイル名と拡張子を分離
    base, ext = os.path.splitext(filename)
    # 現在の日時を取得して文字列に変換（YYYYMMDDhhmmss形式）
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    # ファイル名にタイムスタンプを追加
    return f"{base}_{timestamp}{ext}"


def save_encrypted_file(encrypted_data: bytes, metadata: Dict[str, Any], output_path: str) -> None:
    """
    暗号文ファイルを保存

    Args:
        encrypted_data: 暗号化されたデータ
        metadata: メタデータ辞書
        output_path: 出力ファイルパス
    """
    try:
        # 出力ファイル名にタイムスタンプを追加
        timestamped_output_path = add_timestamp_to_filename(output_path)

        # 出力ディレクトリが存在することを確認
        output_dir = os.path.dirname(timestamped_output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # メタデータをJSON形式に変換
        metadata_json = json.dumps(metadata, indent=2)
        metadata_bytes = metadata_json.encode('utf-8')

        # メタデータサイズの妥当性チェック
        if len(metadata_bytes) > 10 * 1024 * 1024:  # 10MB超過でエラー
            raise ValueError(f"メタデータサイズが大きすぎます: {len(metadata_bytes)} bytes")

        # ヘッダーとデータを結合
        with open(timestamped_output_path, 'wb') as file:
            # マジックヘッダー（形式識別用）
            file.write(b'RABBIT_ENCRYPTED_V2\n')

            # メタデータ部分のサイズ（4バイト）
            file.write(len(metadata_bytes).to_bytes(4, byteorder='big'))

            # メタデータJSON
            file.write(metadata_bytes)

            # 暗号化データ
            file.write(encrypted_data)

        print(f"暗号化ファイルを '{timestamped_output_path}' に保存しました")

        # オリジナルのパス名にもコピー
        with open(output_path, 'wb') as file:
            file.write(b'RABBIT_ENCRYPTED_V2\n')
            file.write(len(metadata_bytes).to_bytes(4, byteorder='big'))
            file.write(metadata_bytes)
            file.write(encrypted_data)
        print(f"暗号化ファイルを '{output_path}' に保存しました")
    except Exception as e:
        print(f"エラー: 暗号化ファイルの保存に失敗しました: {e}")
        raise


def parse_arguments() -> argparse.Namespace:
    """コマンドライン引数を解析"""
    parser = argparse.ArgumentParser(
        description="改良版Rabbit暗号化ツール - ユーザー意図による暗号パス選択",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-a", "--path-a-file",
        default=TRUE_FILE_PATH,
        help="パスAのファイル (従来の正規ファイル)"
    )

    parser.add_argument(
        "-b", "--path-b-file",
        default=FALSE_FILE_PATH,
        help="パスBのファイル (従来の非正規ファイル)"
    )

    parser.add_argument(
        "-o", "--output",
        default=ENCRYPTED_FILE_PATH,
        help="暗号化ファイルの出力先"
    )

    parser.add_argument(
        "--path-a-password",
        help="パスAのパスワード（指定がなければランダム生成）"
    )

    parser.add_argument(
        "--path-b-password",
        help="パスBのパスワード（指定がなければランダム生成）"
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

    # ファイルの読み込み
    print(f"パスAのファイル '{args.path_a_file}' を読み込んでいます...")
    path_a_data = read_file(args.path_a_file)

    print(f"パスBのファイル '{args.path_b_file}' を読み込んでいます...")
    path_b_data = read_file(args.path_b_file)

    # 対称的な暗号化
    print("暗号化方式: 対称的XOR暗号化")
    print("データを暗号化しています...")

    # ユーザー指定のパスワードがあればそれを使用
    if args.path_a_password and args.path_b_password:
        # パスワードを指定された場合の処理
        path_a_password = args.path_a_password
        path_b_password = args.path_b_password

        # ソルトを生成
        salt = os.urandom(SALT_SIZE)

        # パスワードから鍵とIVを生成
        path_a_key, path_a_iv, _ = derive_key(path_a_password, salt)
        path_b_key, path_b_iv, _ = derive_key(path_b_password, salt)

        # データ長を揃える
        max_length = max(len(path_a_data), len(path_b_data))

        # パディングを追加
        if len(path_a_data) < max_length:
            padding_length = max_length - len(path_a_data)
            path_a_data = path_a_data + b'\x00' * padding_length

        if len(path_b_data) < max_length:
            padding_length = max_length - len(path_b_data)
            path_b_data = path_b_data + b'\x00' * padding_length

        # ストリーム生成
        path_a_stream_gen = RabbitStreamGenerator(path_a_key, path_a_iv)
        path_b_stream_gen = RabbitStreamGenerator(path_b_key, path_b_iv)

        # 暗号化ストリーム生成
        path_a_stream = path_a_stream_gen.generate(max_length)
        path_b_stream = path_b_stream_gen.generate(max_length)

        # XOR暗号化
        path_a_encrypted = xor_encrypt_data(path_a_data, path_a_stream)
        path_b_encrypted = xor_encrypt_data(path_b_data, path_b_stream)

        # 暗号化データのハッシュ値を計算 (整合性検証用)
        path_a_hash = hashlib.sha256(path_a_data).hexdigest()[:8]
        path_b_hash = hashlib.sha256(path_b_data).hexdigest()[:8]

        # 暗号化データを連結
        encrypted_data = path_a_encrypted + path_b_encrypted

        # メタデータの作成
        metadata = {
            "version": VERSION,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "data_length": max_length,
            "path_a_hash": path_a_hash,
            "path_b_hash": path_b_hash,
            "encryption_method": ENCRYPTION_METHOD_SYMMETRIC,
        }
    else:
        # ランダムパスワードを生成
        path_a_password, path_b_password, encrypted_data, metadata = create_symmetric_encrypted_container(
            path_a_data, path_b_data
        )

    print(f"パスAのパスワード: {path_a_password}")
    print(f"パスBのパスワード: {path_b_password}")

    # 暗号化データをファイルに保存
    save_encrypted_file(encrypted_data, metadata, args.output)

    # 復号方法の案内
    print("\n復号方法:")
    print(f'  パスAのデータを取得: python -m method_6_rabbit.improved_decrypt -p "{path_a_password}" -i "{args.output}" -o decrypted_path_a.text')
    print(f'  パスBのデータを取得: python -m method_6_rabbit.improved_decrypt -p "{path_b_password}" -i "{args.output}" -o decrypted_path_b.text')

    print("\n暗号化が完了しました！")

    # 重要な注意点
    print("\n重要な注意:")
    print("このバージョンでは「正規」「非正規」の概念はユーザーの意図によって決まります。")
    print("つまり、あなたにとって重要なデータをパスAとパスBのどちらに配置するかはあなた次第です。")
    print("攻撃者はどちらが本当のデータなのか暗号方式や実装からは判断できません。")


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