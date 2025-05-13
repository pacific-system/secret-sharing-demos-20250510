#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
改良版ラビット復号プログラム

正規キー・非正規キーの概念を排除し、
どのキーでも同様に可読なテキストが復号される方式。
ユーザーの意図によって「どちらが真のデータか」を決定できます。
"""

import os
import sys
import argparse
import json
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
        DECRYPT_CHUNK_SIZE,
        ENCRYPTED_FILE_PATH,
        DECRYPTED_FILE_PATH,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
    from method_6_rabbit.rabbit_stream import derive_key, RabbitStreamGenerator
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
    from .rabbit_stream import derive_key, RabbitStreamGenerator

# 暗号化方式
ENCRYPTION_METHOD_SYMMETRIC = "symmetric"

# パス種別の定義
PATH_A = "path_a"  # 従来の "true" に相当
PATH_B = "path_b"  # 従来の "false" に相当


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
            # マジックヘッダーを確認 (V1とV2両方のサポート)
            expected_magic_v1 = b'RABBIT_ENCRYPTED_V1\n'
            expected_magic_v2 = b'RABBIT_ENCRYPTED_V2\n'
            magic = file.read(len(expected_magic_v1))

            if magic != expected_magic_v1 and magic != expected_magic_v2:
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


def determine_path_type(password: Union[str, bytes], salt: bytes) -> Tuple[str, bytes, bytes]:
    """
    パスワードからパスタイプを判定し、必要な鍵とIVを生成

    Args:
        password: 入力されたパスワード
        salt: ソルト値

    Returns:
        (path_type, key, iv): パスタイプと鍵・IV
    """
    # 文字列の場合はUTF-8エンコード
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password

    # 鍵とIVを導出
    key, iv, _ = derive_key(password, salt)

    # パスAとパスBの判定は特定の手法で行わない
    # 代わりに、復号結果を両方試して判断する

    return None, key, iv


def symmetric_decrypt(encrypted_data: bytes, metadata: Dict[str, Any], password: str) -> Tuple[bytes, str]:
    """
    対称的な復号処理

    Args:
        encrypted_data: 暗号化データ
        metadata: メタデータ
        password: 復号パスワード

    Returns:
        (復号データ, パスタイプ)
    """
    # メタデータから情報を取得
    salt = base64.b64decode(metadata["salt"])
    data_length = metadata["data_length"]

    # パスワードから鍵とIVを導出
    key, iv, _ = derive_key(password, salt)

    # ストリームジェネレータを作成
    stream_gen = RabbitStreamGenerator(key, iv)

    # 復号に使用するストリームを生成
    stream = stream_gen.generate(data_length)

    # パスAとパスBの両方で復号を試みる
    # パスAの復号
    path_a_encrypted = encrypted_data[:data_length]
    path_a_decrypted = decrypt_xor(path_a_encrypted, stream)
    path_a_hash = hashlib.sha256(path_a_decrypted).hexdigest()[:8]

    # パスBの復号
    if len(encrypted_data) >= 2 * data_length:
        path_b_encrypted = encrypted_data[data_length:2 * data_length]
        path_b_decrypted = decrypt_xor(path_b_encrypted, stream)
        path_b_hash = hashlib.sha256(path_b_decrypted).hexdigest()[:8]
    else:
        path_b_decrypted = None
        path_b_hash = None

    # ハッシュ検証でパスを判定
    path_a_expected = metadata.get("path_a_hash", "")
    path_b_expected = metadata.get("path_b_hash", "")

    # パスAに一致する場合
    if path_a_hash == path_a_expected:
        return path_a_decrypted, PATH_A

    # パスBに一致する場合
    if path_b_hash == path_b_expected:
        return path_b_decrypted, PATH_B

    # どちらにも一致しない場合、より可能性が高い方を返す
    # この場合、通常はパスAと見なします（デフォルトの挙動）
    return path_a_decrypted, "unknown"


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


def save_decrypted_file(decrypted_data: bytes, output_path: str, path_type: str) -> str:
    """
    復号したデータをファイルに保存

    Args:
        decrypted_data: 復号データ
        output_path: 出力ファイルパス
        path_type: パス種別

    Returns:
        保存したファイルのパス
    """
    try:
        # 出力ファイル名にタイムスタンプとパスタイプを追加
        base, ext = os.path.splitext(output_path)
        timestamped_output_path = f"{base}_{path_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

        # 出力ディレクトリが存在することを確認
        output_dir = os.path.dirname(timestamped_output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # NULL終端文字があれば取り除く（必要な場合のみ）
        cleaned_data = decrypted_data.rstrip(b'\x00')

        with open(timestamped_output_path, 'wb') as file:
            file.write(cleaned_data)
        print(f"復号データを '{timestamped_output_path}' に保存しました")
        return timestamped_output_path
    except Exception as e:
        print(f"エラー: 復号ファイルの保存に失敗しました: {e}")
        raise


def parse_arguments() -> argparse.Namespace:
    """コマンドライン引数を解析"""
    parser = argparse.ArgumentParser(
        description="改良版Rabbit復号ツール - ユーザー意図による暗号パス選択",
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

    parser.add_argument(
        "--path-info",
        action="store_true",
        help="復号したパスの情報を表示"
    )

    return parser.parse_args()


def main():
    """メイン関数"""
    # 引数解析
    args = parse_arguments()

    print(f"暗号化ファイル '{args.input}' を読み込んでいます...")
    encrypted_data, metadata = read_encrypted_file(args.input)

    # 暗号化方式を確認
    encryption_method = metadata.get("encryption_method", "unknown")
    if args.verbose:
        print(f"暗号化方式: {encryption_method}")
        print(f"ファイルバージョン: {metadata.get('version', '不明')}")

    # 対称的復号
    print("データを復号しています...")
    decrypted_data, path_type = symmetric_decrypt(encrypted_data, metadata, args.password)

    # パス情報の表示
    if path_type == "unknown":
        print("警告: 既知のパスタイプに一致しませんでした。データが破損している可能性があります。")
    else:
        print(f"パス種別: {path_type}")

        # 復号したデータの整合性チェック
        hash_key = f"{path_type}_hash"
        if hash_key in metadata:
            hash_signature = hashlib.sha256(decrypted_data).hexdigest()[:8]
            if hash_signature == metadata[hash_key]:
                if args.verbose:
                    print("データ整合性チェック: OK")
            else:
                print("警告: データ整合性チェックが一致しません")

    # 復号結果を保存
    saved_path = save_decrypted_file(decrypted_data, args.output, path_type)

    print("復号が完了しました！")

    # パスに関する追加情報（--path-infoが指定された場合）
    if args.path_info or args.verbose:
        print("\n追加情報:")
        print("このプログラムは「正規」「非正規」の区別をしていません。")
        print("パスAとパスBはどちらも同等に扱われ、どちらが重要なデータかはユーザーの意図によって決まります。")
        print("これにより、復号されたファイルが「本物」か「偽物」かを攻撃者が判断することはできません。")


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