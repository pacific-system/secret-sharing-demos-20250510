#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ラビット復号プログラム

同一の暗号文から与えられた鍵に応じて異なる平文を復元する機能を提供します。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import datetime
from typing import Dict, Any, Tuple, Optional, Union

# インポートエラーを回避するための処理
if __name__ == "__main__":
    # モジュールとして実行された場合の処理
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        DECRYPT_CHUNK_SIZE,
        ENCRYPTED_FILE_PATH,
        DECRYPTED_FILE_PATH,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
    from method_6_rabbit.stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
    from method_6_rabbit.rabbit_stream import derive_key
    # 多重データカプセル化モジュールをインポート
    from method_6_rabbit.capsule import extract_from_multipath_capsule, is_multipath_capsule
else:
    # パッケージの一部として実行された場合の処理
    from .config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        DECRYPT_CHUNK_SIZE,
        ENCRYPTED_FILE_PATH,
        DECRYPTED_FILE_PATH,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
    from .stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
    from .rabbit_stream import derive_key
    # 多重データカプセル化モジュールをインポート
    from .capsule import extract_from_multipath_capsule, is_multipath_capsule

# 暗号化方式の選択肢
ENCRYPTION_METHOD_CLASSIC = "classic"  # 旧来の単純連結方式
ENCRYPTION_METHOD_CAPSULE = "capsule"  # 新しい多重データカプセル化方式


def decrypt_xor(encrypted_data: bytes, stream: bytes) -> bytes:
    """
    XOR暗号化されたデータを復号

    Args:
        encrypted_data: 復号するデータ
        stream: 復号ストリーム

    Returns:
        復号されたデータ
    """
    # データ長とストリーム長が一致することを確認
    if len(encrypted_data) > len(stream):
        raise ValueError(f"ストリーム長（{len(stream)}バイト）がデータ長（{len(encrypted_data)}バイト）より小さいです")

    # XORによる復号（暗号化と同じ処理）
    decrypted = bytearray(len(encrypted_data))
    for i in range(len(encrypted_data)):
        decrypted[i] = encrypted_data[i] ^ stream[i]

    return bytes(decrypted)


def read_encrypted_file(file_path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    暗号化ファイルを読み込み、データとメタデータに分解

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (encrypted_data, metadata): データとメタデータの辞書
    """
    try:
        with open(file_path, 'rb') as file:
            # マジックヘッダーを確認
            expected_magic = b'RABBIT_ENCRYPTED_V1\n'
            magic = file.read(len(expected_magic))
            if magic != expected_magic:
                raise ValueError("無効なファイル形式: Rabbit暗号化ファイルではありません")

            # メタデータのサイズを読み取り
            meta_size_bytes = file.read(4)
            meta_size = int.from_bytes(meta_size_bytes, byteorder='big')

            # メタデータサイズの妥当性チェック
            if meta_size <= 0 or meta_size > 10 * 1024 * 1024:  # 10MB超過でエラー
                raise ValueError(f"無効なメタデータサイズ: {meta_size}バイト")

            # メタデータを読み取り
            meta_bytes = file.read(meta_size)
            try:
                meta_json = meta_bytes.decode('utf-8')
                metadata = json.loads(meta_json)
            except UnicodeDecodeError:
                raise ValueError("メタデータのUTF-8デコードに失敗しました")
            except json.JSONDecodeError:
                raise ValueError("メタデータのJSON解析に失敗しました")

            # 残りのデータ（暗号化済み）を読み取り
            encrypted_data = file.read()

            return encrypted_data, metadata
    except FileNotFoundError:
        raise ValueError(f"ファイル '{file_path}' が見つかりません")
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"暗号化ファイルの読み込みに失敗しました: {e}")


def decrypt_classic(encrypted_data: bytes, metadata: Dict[str, Any], password: str) -> bytes:
    """
    従来方式（単純連結）で暗号化されたデータを復号

    Args:
        encrypted_data: 暗号化データ
        metadata: メタデータ辞書
        password: 復号パスワード

    Returns:
        復号されたデータ
    """
    # メタデータを取得
    salt = base64.b64decode(metadata["salt"])
    data_length = metadata["data_length"]

    # StreamSelectorを初期化
    selector = StreamSelector(salt)

    # 鍵種別を判定（正規/非正規）
    key_type = selector.determine_key_type_for_decryption(password)

    # 適切なストリームを生成
    stream = selector.get_stream_for_decryption(password, data_length)

    # 適切な暗号文の部分を選択
    if key_type == KEY_TYPE_TRUE:
        offset = 0
    else:  # KEY_TYPE_FALSE
        offset = data_length

    # データを復号
    encrypted_portion = encrypted_data[offset:offset + data_length]
    decrypted = decrypt_xor(encrypted_portion, stream)

    return decrypted


def decrypt_capsule(encrypted_data: bytes, metadata: Dict[str, Any], password: str) -> bytes:
    """
    多重データカプセル化方式で暗号化されたデータを復号

    Args:
        encrypted_data: 暗号化データ
        metadata: メタデータ辞書
        password: 復号パスワード

    Returns:
        復号されたデータ
    """
    # メタデータを取得
    salt = base64.b64decode(metadata["salt"])
    capsule_metadata = metadata.get("capsule", {})

    # StreamSelectorを初期化
    selector = StreamSelector(salt)

    # 鍵種別を判定（正規/非正規）
    key_type = selector.determine_key_type_for_decryption(password)

    # 多重パスカプセルから復号
    decrypted = extract_from_multipath_capsule(
        encrypted_data,
        password,
        key_type,  # "true" または "false" の文字列を渡す
        capsule_metadata
    )

    return decrypted


def decrypt_container(encrypted_data: bytes, metadata: Dict[str, Any], password: str) -> bytes:
    """
    暗号化コンテナを復号

    Args:
        encrypted_data: 暗号化データ
        metadata: メタデータ辞書
        password: 復号パスワード

    Returns:
        復号されたデータ
    """
    # 暗号化方式を確認
    encryption_method = metadata.get("encryption_method", ENCRYPTION_METHOD_CLASSIC)

    # 通常の復号処理
    if encryption_method == ENCRYPTION_METHOD_CLASSIC:
        return decrypt_classic(encrypted_data, metadata, password)
    elif encryption_method == ENCRYPTION_METHOD_CAPSULE:
        return decrypt_capsule(encrypted_data, metadata, password)
    else:
        raise ValueError(f"未対応の暗号化方式: {encryption_method}")


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


def save_decrypted_file(decrypted_data: bytes, output_path: str) -> None:
    """
    復号したデータをファイルに保存

    Args:
        decrypted_data: 復号データ
        output_path: 出力ファイルパス
    """
    try:
        # 出力ファイル名にタイムスタンプを追加
        timestamped_output_path = add_timestamp_to_filename(output_path)

        # 出力ディレクトリが存在することを確認
        output_dir = os.path.dirname(timestamped_output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(timestamped_output_path, 'wb') as file:
            file.write(decrypted_data)
        print(f"復号データを '{timestamped_output_path}' に保存しました")
    except Exception as e:
        print(f"エラー: 復号ファイルの保存に失敗しました: {e}")
        raise


def decrypt_file(input_file: str, output_file: str, key: str) -> bytes:
    """
    暗号化ファイルを復号する

    Args:
        input_file: 暗号化ファイルのパス
        output_file: 出力ファイルパス
        key: 復号に使用する鍵

    Returns:
        復号されたデータ
    """
    try:
        # 暗号化ファイルを読み込む
        encrypted_data, metadata = read_encrypted_file(input_file)

        # データを復号する
        decrypted_data = decrypt_container(encrypted_data, metadata, key)

        # 復号したデータを保存する
        save_decrypted_file(decrypted_data, output_file)

        return decrypted_data
    except Exception as e:
        # エラーメッセージを表示して再度例外を発生
        print(f"ファイル復号中にエラー: {e}")
        raise


def decrypt_data(data: bytes, key: str) -> bytes:
    """
    暗号化データを復号する

    Args:
        data: 暗号化されたデータ
        key: 復号に使用する鍵

    Returns:
        復号されたデータ
    """
    try:
        # マジックヘッダーを確認
        expected_magic = b'RABBIT_ENCRYPTED_V1\n'
        if not data.startswith(expected_magic):
            raise ValueError("無効なデータ形式: Rabbit暗号化データではありません")

        # ヘッダーの長さを取得
        header_length = len(expected_magic)

        # メタデータのサイズを読み取り
        meta_size = int.from_bytes(data[header_length:header_length+4], byteorder='big')

        # メタデータサイズの妥当性チェック（過大なサイズを防止）
        if meta_size <= 0 or meta_size > 10 * 1024 * 1024:  # 最大10MBのメタデータに制限
            raise ValueError(f"無効なメタデータサイズ: {meta_size}バイト")

        # データの長さチェック
        if len(data) < header_length + 4 + meta_size:
            raise ValueError(f"データサイズが不足: メタデータに{header_length + 4 + meta_size}バイト必要ですが{len(data)}バイトしかありません")

        # メタデータを読み取り
        try:
            meta_json = data[header_length+4:header_length+4+meta_size].decode('utf-8')
            metadata = json.loads(meta_json)
        except UnicodeDecodeError:
            raise ValueError("メタデータのUTF-8デコードに失敗しました")
        except json.JSONDecodeError:
            raise ValueError("メタデータのJSON解析に失敗しました")

        # テスト用簡易フォーマット処理を削除
        # これは暗号化をバイパスするバックドアであり、要件に違反しています

        # 残りのデータ（暗号化済み）を取得
        encrypted_data = data[header_length+4+meta_size:]

        # データを復号する
        return decrypt_container(encrypted_data, metadata, key)
    except Exception as e:
        # エラーを包含して再度発生させる
        raise ValueError(f"データの復号に失敗しました: {e}")


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数を解析

    Returns:
        解析された引数オブジェクト
    """
    parser = argparse.ArgumentParser(
        description="Rabbit復号ツール - 多重復号機能を提供",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-i", "--input",
        default=ENCRYPTED_FILE_PATH,
        help="暗号化ファイルのパス"
    )

    parser.add_argument(
        "-o", "--output",
        default=DECRYPTED_FILE_PATH,
        help="復号ファイルの出力先"
    )

    parser.add_argument(
        "-p", "--password",
        required=True,
        help="復号パスワード"
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

    print(f"暗号化ファイル '{args.input}' を読み込んでいます...")
    encrypted_data, metadata = read_encrypted_file(args.input)

    if args.verbose:
        # 暗号化方式の表示
        method = metadata.get("encryption_method", ENCRYPTION_METHOD_CLASSIC)
        method_desc = "多重データカプセル化" if method == ENCRYPTION_METHOD_CAPSULE else "従来の単純連結"
        print(f"暗号化方式: {method_desc}")
        print(f"ファイルバージョン: {metadata.get('version', '不明')}")

    # StreamSelectorインスタンスを作成
    salt = base64.b64decode(metadata["salt"])
    selector = StreamSelector(salt)

    print("パスワードを検証しています...")
    # 鍵の種類を判定
    key_type = selector.determine_key_type_for_decryption(args.password)
    print(f"鍵の種類: {'正規' if key_type == KEY_TYPE_TRUE else '非正規'}")

    print("データを復号しています...")
    # データを復号
    decrypted_data = decrypt_container(encrypted_data, metadata, args.password)

    # 復号データの署名（最初の数バイト）を確認
    data_check = key_type + "_path_check"
    if data_check in metadata:
        hash_signature = hashlib.sha256(decrypted_data[:16]).hexdigest()[:8]
        if hash_signature == metadata[data_check]:
            if args.verbose:
                print("データ整合性チェック: OK")
        else:
            print("警告: データ整合性チェックが一致しません")

    # 復号結果を保存
    save_decrypted_file(decrypted_data, args.output)
    print("復号が完了しました！")


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
