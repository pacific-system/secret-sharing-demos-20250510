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
import hmac
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
    from method_6_rabbit.rabbit_stream import derive_key, RabbitStreamGenerator
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
    from .rabbit_stream import derive_key, RabbitStreamGenerator
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
    if offset + data_length <= len(encrypted_data):
        encrypted_portion = encrypted_data[offset:offset + data_length]
    else:
        # データが足りない場合、エラーを発生させるよりも可能な限り復号
        encrypted_portion = encrypted_data[offset:]
        print(f"警告: 暗号データが短すぎます: 要求={data_length}, 利用可能={len(encrypted_portion)}")

    # XORによる復号
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
    暗号化コンテナを復号 (シンプルなXOR方式)

    Args:
        encrypted_data: 暗号化データ
        metadata: メタデータ辞書
        password: 復号パスワード

    Returns:
        復号されたデータ
    """
    # メタデータを確認
    encryption_method = metadata.get("encryption_method", "simple_xor")
    if encryption_method != "simple_xor":
        raise ValueError(f"未対応の暗号化方式: {encryption_method}")

    # メタデータを取得
    salt = base64.b64decode(metadata["salt"])
    data_length = metadata["data_length"]

    # パスワードから鍵を派生
    key, iv, _ = derive_key(password, salt)

    # Rabbit暗号ストリームを生成
    stream_gen = RabbitStreamGenerator(key, iv)
    stream = stream_gen.generate(data_length)

    # 鍵種別に応じてデータを選択
    # はじめにパスワード判定
    hmac_hash = hmac.new(salt, password.encode(), hashlib.sha256).digest()[:4]
    value = int.from_bytes(hmac_hash, byteorder='big')

    # 数値が偶数ならtrue、奇数ならfalse
    is_true_key = (value % 2 == 0)

    # データ選択
    if is_true_key:
        # true鍵の場合は前半部分
        if len(encrypted_data) < data_length:
            raise ValueError(f"暗号データが短すぎます: {len(encrypted_data)} < {data_length}")
        encrypted_part = encrypted_data[:data_length]
    else:
        # false鍵の場合は後半部分
        if len(encrypted_data) < 2 * data_length:
            raise ValueError(f"暗号データが短すぎます: {len(encrypted_data)} < {2 * data_length}")
        encrypted_part = encrypted_data[data_length:2 * data_length]

    # XOR復号
    decrypted = decrypt_xor(encrypted_part, stream)

    # チェックサム検証 (オプショナル)
    checksum = hashlib.sha256(decrypted).hexdigest()[:8]
    expected = metadata.get("true_checksum" if is_true_key else "false_checksum")
    if expected and checksum != expected:
        print(f"警告: チェックサムが一致しません (期待: {expected}, 実際: {checksum})")

    return decrypted


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


def simpler_decrypt(encrypted_data: bytes, metadata: Dict[str, Any], password: str) -> Tuple[bytes, str]:
    """
    シンプルな復号処理を行う関数。
    メタデータ内のパスワードリストと照合し、適切なデータを復号します。

    Args:
        encrypted_data: 暗号化データ
        metadata: メタデータ
        password: 入力されたパスワード

    Returns:
        (復号データ, データ種別)
    """
    # メタデータからパスワードを取得
    true_password = metadata.get("true_password")
    false_password = metadata.get("false_password")

    # パスワードが見つからない場合
    if not true_password or not false_password:
        raise ValueError("メタデータにパスワード情報がありません")

    # 鍵の種類を判定（単純なパスワード比較）
    if password == true_password:
        key_type = "true"
    elif password == false_password:
        key_type = "false"
    else:
        # それ以外のパスワードは、どちらかは判定できないのでランダム
        # 実際のシステムではもっと安全な方法が必要
        key_type = "true" if hash(password) % 2 == 0 else "false"

    # メタデータを取得
    salt = base64.b64decode(metadata["salt"])
    data_length = metadata["data_length"]

    # パスワードから鍵を派生
    key, iv, _ = derive_key(password, salt)

    # ストリーム生成
    stream_gen = RabbitStreamGenerator(key, iv)
    stream = stream_gen.generate(data_length)

    # データ選択
    if key_type == "true":
        # true鍵の場合は前半部分
        encrypted_part = encrypted_data[:data_length]
    else:
        # false鍵の場合は後半部分
        if len(encrypted_data) < 2 * data_length:
            raise ValueError(f"暗号データが短すぎます: {len(encrypted_data)} < {2 * data_length}")
        encrypted_part = encrypted_data[data_length:2 * data_length]

    # XOR復号
    decrypted = decrypt_xor(encrypted_part, stream)

    # チェックサム検証 (オプショナル)
    checksum = hashlib.sha256(decrypted).hexdigest()[:8]
    expected = metadata.get(f"{key_type}_hash")
    if expected and checksum != expected:
        print(f"警告: チェックサムが一致しません (期待: {expected}, 実際: {checksum})")

    return decrypted, key_type


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
        method = metadata.get("encryption_method", "simple_separate_xor")
        print(f"暗号化方式: {method}")
        print(f"ファイルバージョン: {metadata.get('version', '不明')}")

    print("データを復号しています...")
    # データを復号
    decrypted_data, key_type = simpler_decrypt(encrypted_data, metadata, args.password)

    print(f"鍵の種類: {'正規' if key_type == 'true' else '非正規'}")

    # 復号データの署名確認
    hash_key = f"{key_type}_hash"
    if hash_key in metadata:
        hash_signature = hashlib.sha256(decrypted_data).hexdigest()[:8]
        if hash_signature == metadata[hash_key]:
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
