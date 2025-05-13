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
import datetime
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
    from method_6_rabbit.rabbit_stream import derive_key, RabbitStreamGenerator
    # 多重データカプセル化モジュールをインポート
    from method_6_rabbit.capsule import (
        create_multipath_capsule,
        extract_from_multipath_capsule,
        test_multipath_capsule
    )
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
    from .rabbit_stream import derive_key, RabbitStreamGenerator
    # 多重データカプセル化モジュールをインポート
    from .capsule import (
        create_multipath_capsule,
        extract_from_multipath_capsule,
        test_multipath_capsule
    )

# 暗号化方式の選択肢
ENCRYPTION_METHOD_CLASSIC = "classic"  # 旧来の単純連結方式
ENCRYPTION_METHOD_CAPSULE = "capsule"  # 新しい多重データカプセル化方式

# ソルトサイズの定義
SALT_SIZE = 16


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


def create_encrypted_container_classic(true_data: bytes, false_data: bytes, master_key: bytes,
                              true_password: str, false_password: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    従来方式での暗号化コンテナを作成（単純連結方式）

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
    true_encrypted = xor_encrypt_data(true_data, true_stream)
    false_encrypted = xor_encrypt_data(false_data, false_stream)

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
        # 暗号化方式を明示
        "encryption_method": ENCRYPTION_METHOD_CLASSIC,
        "verification_hash": hashlib.sha256(final_encrypted).hexdigest(),
    }

    return bytes(final_encrypted), metadata


def create_encrypted_container_capsule(true_data: bytes, false_data: bytes,
                                      master_key: bytes,
                                      true_password: str, false_password: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    多重データカプセル化方式での暗号化コンテナを作成

    Args:
        true_data: 正規の平文データ
        false_data: 非正規の平文データ
        master_key: マスター鍵
        true_password: 正規のパスワード
        false_password: 非正規のパスワード

    Returns:
        (encrypted_data, metadata): 暗号化データとメタデータの辞書
    """
    # StreamSelectorを初期化してソルトを取得
    selector = StreamSelector()
    salt = selector.get_salt()

    # 鍵を決定するためのマスターパスワードを生成
    master_password = base64.b64encode(master_key).decode('ascii')

    # 多重パスカプセルを作成（このマスターパスワードは実際の復号には使用されない）
    capsule, capsule_metadata = create_multipath_capsule(true_data, false_data, master_password)

    # 暗号化データのハッシュ値を計算
    true_hash = hashlib.sha256(true_data[:16]).hexdigest()[:8]
    false_hash = hashlib.sha256(false_data[:16]).hexdigest()[:8]

    # メタデータをマージ
    metadata = {
        "version": VERSION,
        "salt": base64.b64encode(salt).decode('ascii'),
        "data_length": max(len(true_data), len(false_data)),
        "true_path_check": true_hash,
        "false_path_check": false_hash,
        # 暗号化方式を明示
        "encryption_method": ENCRYPTION_METHOD_CAPSULE,
        "verification_hash": hashlib.sha256(capsule).hexdigest(),
        # カプセル固有のメタデータを追加
        "capsule": capsule_metadata
    }

    return capsule, metadata


def create_encrypted_container(true_data: bytes, false_data: bytes, master_key: bytes,
                              true_password: str, false_password: str,
                              method: str = ENCRYPTION_METHOD_CAPSULE) -> Tuple[bytes, Dict[str, Any]]:
    """
    暗号化コンテナを作成（方式を選択可能）

    Args:
        true_data: 正規の平文データ
        false_data: 非正規の平文データ
        master_key: マスター鍵
        true_password: 正規のパスワード
        false_password: 非正規のパスワード
        method: 暗号化方式 ("classic" または "capsule")

    Returns:
        (encrypted_data, metadata): 暗号化データとメタデータの辞書
    """
    if method == ENCRYPTION_METHOD_CLASSIC:
        return create_encrypted_container_classic(true_data, false_data, master_key, true_password, false_password)
    elif method == ENCRYPTION_METHOD_CAPSULE:
        return create_encrypted_container_capsule(true_data, false_data, master_key, true_password, false_password)
    else:
        raise ValueError(f"未対応の暗号化方式: {method}")


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
            file.write(b'RABBIT_ENCRYPTED_V1\n')

            # メタデータ部分のサイズ（4バイト）
            file.write(len(metadata_bytes).to_bytes(4, byteorder='big'))

            # メタデータJSON
            file.write(metadata_bytes)

            # 暗号化データ
            file.write(encrypted_data)

        print(f"暗号化ファイルを '{timestamped_output_path}' に保存しました")
    except Exception as e:
        print(f"エラー: 暗号化ファイルの保存に失敗しました: {e}")
        # sys.exit(1) は例外を発生させるのみに変更（テスト環境で終了しないように）
        raise


def encrypt_file(true_file: str, false_file: str, output_file: str, key: str,
                method: str = ENCRYPTION_METHOD_CAPSULE) -> None:
    """
    ファイルを暗号化する

    Args:
        true_file: 正規の平文ファイルパス
        false_file: 非正規の平文ファイルパス
        output_file: 出力ファイルパス
        key: 暗号化に使用する鍵
        method: 暗号化方式
    """
    # ファイルを読み込む
    true_data = read_file(true_file)
    false_data = read_file(false_file)

    # 鍵から派生したマスター鍵を生成
    master_key = hashlib.sha256(key.encode('utf-8')).digest()[:RABBIT_KEY_SIZE]

    # 暗号化する
    encrypted_data, metadata = create_encrypted_container(
        true_data, false_data, master_key, key, key, method
    )

    # 暗号化したデータを保存する
    save_encrypted_file(encrypted_data, metadata, output_file)


def encrypt_data(true_data: bytes, false_data: bytes, true_password: str, false_password: str,
                method: str = ENCRYPTION_METHOD_CLASSIC) -> Tuple[bytes, Dict[str, Any]]:
    """
    データを暗号化する (シンプルなXOR方式)

    Args:
        true_data: 正規の平文データ
        false_data: 非正規の平文データ
        true_password: 正規パスワード
        false_password: 非正規パスワード
        method: 暗号化方式 (今回は使用しない)

    Returns:
        (暗号化データ, メタデータ)
    """
    # ソルト生成
    salt = os.urandom(SALT_SIZE)

    # パスワードから鍵を生成
    true_key, true_iv, _ = derive_key(true_password, salt)
    false_key, false_iv, _ = derive_key(false_password, salt)

    # ランダム鍵生成
    master_key = generate_master_key()

    # 両方のデータを同じ長さにするためパディング
    max_length = max(len(true_data), len(false_data))
    if len(true_data) < max_length:
        true_data = true_data + b'\x00' * (max_length - len(true_data))
    if len(false_data) < max_length:
        false_data = false_data + b'\x00' * (max_length - len(false_data))

    # 両方のデータのチェックサム
    true_checksum = hashlib.sha256(true_data).hexdigest()[:8]
    false_checksum = hashlib.sha256(false_data).hexdigest()[:8]

    # ストリーム生成
    true_stream_gen = RabbitStreamGenerator(true_key, true_iv)
    false_stream_gen = RabbitStreamGenerator(false_key, false_iv)

    # 暗号化ストリーム生成
    true_stream = true_stream_gen.generate(max_length)
    false_stream = false_stream_gen.generate(max_length)

    # XOR暗号化
    true_encrypted = xor_encrypt_data(true_data, true_stream)
    false_encrypted = xor_encrypt_data(false_data, false_stream)

    # 両方を連結
    encrypted_data = true_encrypted + false_encrypted

    # メタデータ
    metadata = {
        "version": VERSION,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "data_length": max_length,
        "true_checksum": true_checksum,
        "false_checksum": false_checksum,
        "encryption_method": "simple_xor",
    }

    # 組み立て
    result = bytearray()
    result.extend(b'RABBIT_ENCRYPTED_V1\n')

    # メタデータをJSON形式に変換
    metadata_json = json.dumps(metadata, indent=2)
    metadata_bytes = metadata_json.encode('utf-8')

    # メタデータサイズ
    result.extend(len(metadata_bytes).to_bytes(4, byteorder='big'))

    # メタデータ
    result.extend(metadata_bytes)

    # 暗号化データ
    result.extend(encrypted_data)

    return bytes(result), metadata


# encrypt_data_simple関数は不正なバックドア実装のため削除されました


def parse_arguments() -> argparse.Namespace:
    """コマンドライン引数を解析"""
    parser = argparse.ArgumentParser(
        description="Rabbit暗号化ツール - 同一の暗号文から複数の平文を復元可能",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-t", "--true-file",
        default=TRUE_FILE_PATH,
        help="正規ファイルのパス"
    )

    parser.add_argument(
        "-f", "--false-file",
        default=FALSE_FILE_PATH,
        help="非正規ファイルのパス"
    )

    parser.add_argument(
        "-o", "--output",
        default=ENCRYPTED_FILE_PATH,
        help="暗号化ファイルの出力先"
    )

    parser.add_argument(
        "--true-password",
        help="正規パスワード（指定がなければランダム生成）"
    )

    parser.add_argument(
        "--false-password",
        help="非正規パスワード（指定がなければランダム生成）"
    )

    parser.add_argument(
        "--method",
        choices=["classic", "capsule"],
        default="capsule",
        help="暗号化方式（classic: 単純連結方式, capsule: 多重データカプセル化）"
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="テストモードの有効化（実際のファイルを生成せず結果を表示）"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細なログ出力"
    )

    return parser.parse_args()


def simpler_encrypt(true_data: bytes, false_data: bytes) -> Tuple[str, str, bytes, Dict[str, Any]]:
    """
    より単純な暗号化実装。
    正規データと非正規データを1つのファイルにカプセル化し、
    それぞれ専用のパスワードで復号できるようにします。

    Args:
        true_data: 正規データ（trueの場合に復号されるデータ）
        false_data: 非正規データ（falseの場合に復号されるデータ）

    Returns:
        (true_password, false_password, encrypted_data, metadata)
    """
    # ランダムなパスワードを生成
    true_password = secrets.token_hex(16)
    false_password = secrets.token_hex(16)

    # ソルトを生成
    salt = os.urandom(SALT_SIZE)

    # データ長を揃える
    max_length = max(len(true_data), len(false_data))

    # パディングを追加
    if len(true_data) < max_length:
        true_data = true_data + b'\x00' * (max_length - len(true_data))
    if len(false_data) < max_length:
        false_data = false_data + b'\x00' * (max_length - len(false_data))

    # StreamSelectorを使用して安全に鍵を処理
    selector = StreamSelector(salt)

    # 正規データ用ストリームを生成
    true_stream = selector.get_stream_for_decryption(true_password, max_length)

    # 非正規データ用ストリームを生成
    false_stream = selector.get_stream_for_decryption(false_password, max_length)

    # データを暗号化
    true_encrypted = xor_encrypt_data(true_data, true_stream)
    false_encrypted = xor_encrypt_data(false_data, false_stream)

    # 暗号化データを連結
    encrypted_data = true_encrypted + false_encrypted

    # メタデータの作成（パスワードは含めない）
    metadata = {
        "version": VERSION,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "data_length": max_length,
        "true_hash": hashlib.sha256(true_data).hexdigest()[:8],
        "false_hash": hashlib.sha256(false_data).hexdigest()[:8],
        "encryption_method": "simple_separate_xor",
    }

    return true_password, false_password, encrypted_data, metadata


def main():
    """メイン関数"""
    # 引数解析
    args = parse_arguments()

    # ファイルの読み込み
    print(f"正規ファイル '{args.true_file}' を読み込んでいます...")
    true_data = read_file(args.true_file)

    print(f"非正規ファイル '{args.false_file}' を読み込んでいます...")
    false_data = read_file(args.false_file)

    # シンプルな暗号化
    print("暗号化方式: シンプルなXOR暗号化")
    print("データを暗号化しています...")
    true_password, false_password, encrypted_data, metadata = simpler_encrypt(true_data, false_data)

    print(f"正規パスワードを生成しました: {true_password}")
    print(f"非正規パスワードを生成しました: {false_password}")

    # テストモードの場合は実際にファイルに書き込まず結果を表示
    if args.test:
        print("\n=== テスト結果 ===")
        print(f"暗号化データサイズ: {len(encrypted_data)}バイト")
        print(f"メタデータ: {json.dumps(metadata, indent=2)}")
        # 最初の数バイトを表示
        print(f"暗号化データの冒頭: {encrypted_data[:16].hex()}")
    else:
        # 暗号化データをファイルに保存
        save_encrypted_file(encrypted_data, metadata, args.output)
        print(f"暗号化ファイルを '{args.output}' に保存しました")

        # 復号方法の案内
        print("\n復号方法:")
        print(f'  正規データを取得: python -m decrypt -p "{true_password}" -i "{args.output}" -o decrypted_true.text')
        print(f'  非正規データを取得: python -m decrypt -p "{false_password}" -i "{args.output}" -o decrypted_false.text')

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
