#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ラビット暗号化プログラム

同一の暗号文から異なる平文（真/偽）を復元可能な特殊な暗号化を提供します。
"""

import os
import sys
import argparse
import json
import secrets
import binascii
import base64
import hashlib
from typing import Tuple, Dict, Any, List, Optional, Union

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
    from method_6_rabbit.stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
    from method_6_rabbit.rabbit_stream import derive_key
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
    from .stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
    from .rabbit_stream import derive_key


def generate_master_key() -> bytes:
    """
    強力なランダムマスター鍵を生成

    Returns:
        16バイトのマスター鍵
    """
    return secrets.token_bytes(RABBIT_KEY_SIZE)


def encrypt_data(data: bytes, stream: bytes) -> bytes:
    """
    データをストリーム暗号化

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


def create_encrypted_container(true_data: bytes, false_data: bytes, master_key: bytes,
                              true_password: str, false_password: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    暗号化コンテナを作成

    Args:
        true_data: 正規の平文データ
        false_data: 非正規の平文データ
        master_key: マスター鍵
        true_password: 正規のパスワード
        false_password: 非正規のパスワード

    Returns:
        (encrypted_data, metadata): 暗号化データとメタデータの辞書
    """
    # データ長を揃える（短い方にパディング追加）
    max_length = max(len(true_data), len(false_data))

    # パディングを追加
    if len(true_data) < max_length:
        padding_length = max_length - len(true_data)
        true_data = true_data + os.urandom(padding_length)

    if len(false_data) < max_length:
        padding_length = max_length - len(false_data)
        false_data = false_data + os.urandom(padding_length)

    # StreamSelectorを初期化
    selector = StreamSelector()
    salt = selector.get_salt()

    # 両方のパス用のストリームを生成
    true_key, true_iv, true_salt = derive_key(true_password, salt)
    false_key, false_iv, false_salt = derive_key(false_password, salt)

    # 正規データ用ストリーム生成
    true_stream_gen = StreamSelector(salt)
    true_stream = true_stream_gen.get_stream_for_decryption(true_password, max_length)

    # 非正規データ用ストリーム生成
    false_stream_gen = StreamSelector(salt)
    false_stream = false_stream_gen.get_stream_for_decryption(false_password, max_length)

    # データを暗号化
    true_encrypted = encrypt_data(true_data, true_stream)
    false_encrypted = encrypt_data(false_data, false_stream)

    # 両方の暗号化データを連結
    final_encrypted = true_encrypted + false_encrypted

    # 暗号化データのハッシュ値を計算
    true_hash = hashlib.sha256(true_data[:16]).hexdigest()[:8]
    false_hash = hashlib.sha256(false_data[:16]).hexdigest()[:8]

    # メタデータ作成（復号に必要な情報を含む）
    metadata = {
        "version": VERSION,
        "salt": base64.b64encode(salt).decode('ascii'),
        "data_length": max_length,
        "true_path_check": true_hash,
        "false_path_check": false_hash,
        # あえて紛らわしくするための偽情報を追加
        "encryption_method": "AES-256-GCM",  # 実際はRabbitだが、分析者を混乱させる
        "verification_hash": hashlib.sha256(final_encrypted).hexdigest(),
    }

    return bytes(final_encrypted), metadata


def save_encrypted_file(encrypted_data: bytes, metadata: Dict[str, Any], output_path: str) -> None:
    """
    暗号文ファイルを保存

    Args:
        encrypted_data: 暗号化されたデータ
        metadata: メタデータ辞書
        output_path: 出力ファイルパス
    """
    try:
        # メタデータをJSON形式に変換
        metadata_json = json.dumps(metadata, indent=2)

        # ヘッダーとデータを結合
        with open(output_path, 'wb') as file:
            # マジックヘッダー（形式識別用）
            file.write(b'RABBIT_ENCRYPTED_V1\n')

            # メタデータ部分（JSON形式）
            metadata_bytes = metadata_json.encode('utf-8')
            file.write(len(metadata_bytes).to_bytes(4, byteorder='big'))
            file.write(metadata_bytes)

            # 暗号化データ
            file.write(encrypted_data)

        print(f"暗号化ファイルを '{output_path}' に保存しました")
    except Exception as e:
        print(f"エラー: 暗号化ファイルの保存に失敗しました: {e}")
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数を解析

    Returns:
        解析された引数オブジェクト
    """
    parser = argparse.ArgumentParser(
        description="Rabbit暗号化ツール - 多重暗号化機能を提供",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-t", "--true-file",
        default=TRUE_FILE_PATH,
        help="正規の平文ファイルパス"
    )

    parser.add_argument(
        "-f", "--false-file",
        default=FALSE_FILE_PATH,
        help="非正規の平文ファイルパス"
    )

    parser.add_argument(
        "-o", "--output",
        default=ENCRYPTED_FILE_PATH,
        help="暗号化ファイルの出力先"
    )

    parser.add_argument(
        "--true-password",
        default=None,
        help="正規パスワード（指定しない場合はランダム生成）"
    )

    parser.add_argument(
        "--false-password",
        default=None,
        help="非正規パスワード（指定しない場合はランダム生成）"
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

    # 平文ファイル読み込み
    print(f"正規ファイル '{args.true_file}' を読み込んでいます...")
    true_data = read_file(args.true_file)

    print(f"非正規ファイル '{args.false_file}' を読み込んでいます...")
    false_data = read_file(args.false_file)

    # パスワード設定
    true_password = args.true_password or secrets.token_hex(16)
    false_password = args.false_password or secrets.token_hex(16)

    if args.true_password is None:
        print(f"正規パスワードを生成しました: {true_password}")

    if args.false_password is None:
        print(f"非正規パスワードを生成しました: {false_password}")

    # マスター鍵生成
    master_key = generate_master_key()

    print("データを暗号化しています...")
    encrypted_data, metadata = create_encrypted_container(
        true_data, false_data, master_key, true_password, false_password
    )

    # 詳細表示
    if args.verbose:
        print(f"\n暗号化データサイズ: {len(encrypted_data)} バイト")
        print(f"メタデータ: {json.dumps(metadata, indent=2)}")

    # 暗号化ファイル保存
    save_encrypted_file(encrypted_data, metadata, args.output)

    # 復号方法のガイダンス表示
    print("\n復号方法:")
    print(f"  正規データを取得: python decrypt.py -p \"{true_password}\" -i \"{args.output}\" -o decrypted_true.text")
    print(f"  非正規データを取得: python decrypt.py -p \"{false_password}\" -i \"{args.output}\" -o decrypted_false.text")
    print("\n暗号化が完了しました！")


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
