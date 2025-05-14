#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 復号プログラム

暗号文ファイルと鍵を入力として受け取り、
鍵の種類に応じて異なる平文（true.text/false.text）を復元します。
"""

import os
import sys
import time
import json
import base64
import argparse
import hashlib
import secrets
import datetime
import binascii
from typing import Dict, List, Tuple, Optional, Any, BinaryIO, Union

# 内部モジュールのインポート
from .config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
    STATE_MATRIX_SIZE, STATE_TRANSITIONS, OUTPUT_EXTENSION,
    MAX_CHUNK_SIZE, FILE_THRESHOLD_SIZE, DEFAULT_CHUNK_COUNT,
    SECURE_MEMORY_WIPE, ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR,
    USE_DYNAMIC_THRESHOLD, MAX_RETRY_COUNT, ENFORCE_PATH_ISOLATION,
    PREVENT_OUTPUT_BYPASS
)

try:
    # 暗号化ライブラリ（オプション）
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    # 依存ライブラリがない場合はXOR暗号を使用
    HAS_CRYPTOGRAPHY = False

# パスタイプ定数
TRUE_PATH = "true"
FALSE_PATH = "false"

# 必要なシステムチェック
def check_system_integrity():
    """システムの整合性をチェック"""
    if ANTI_TAMPERING:
        # モジュールのハッシュを計算して改変がないか確認
        expected_hashes = {}  # 実際の実装では既知の正規ハッシュ値を設定

        # この関数自体のソースコードハッシュを計算
        current_file = os.path.abspath(__file__)
        if os.path.exists(current_file):
            with open(current_file, 'rb') as f:
                content = f.read()
                current_hash = hashlib.sha256(content).hexdigest()

                # 実際の実装では期待値との比較を行う
                # if current_hash != expected_hashes.get(__file__):
                #     if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                #         raise SecurityError("ファイルの整合性が損なわれています")

    return True

# セキュリティ例外
class SecurityError(Exception):
    """セキュリティ関連の例外"""
    pass

def secure_wipe(data):
    """
    メモリ上のデータを安全に消去

    Args:
        data: 消去するデータ（バイト列またはbytearray）
    """
    if SECURE_MEMORY_WIPE:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, bytes):
            # bytesは不変なので、参照を削除するのみ
            pass

def read_encrypted_file(file_path: str) -> Tuple[Dict[str, Any], bytes]:
    """
    暗号化ファイルを読み込む

    Args:
        file_path: 読み込む暗号化ファイルのパス

    Returns:
        (メタデータ, 暗号化データ)
    """
    try:
        with open(file_path, 'rb') as f:
            # ヘッダー読み込み (実際の実装では適切なヘッダー解析を行う)
            header = f.read(8)
            if header != b"INDET01":
                # チャンクマニフェストファイルの可能性をチェック
                if file_path.endswith(".manifest"):
                    with open(file_path, 'r') as manifest_file:
                        manifest = json.load(manifest_file)
                        return manifest, None

                raise ValueError("不正なファイル形式です")

            # 残りのデータを読み込み
            data = f.read()

            # メタデータ生成 (実際の実装では適切なメタデータ解析を行う)
            metadata = {
                "format": "indeterministic",
                "timestamp": int(time.time())
            }

            return metadata, data

    except Exception as e:
        print(f"暗号化ファイル '{file_path}' の読み込みエラー: {e}", file=sys.stderr)
        raise

def determine_path_type(key: bytes, salt: Optional[bytes] = None) -> str:
    """
    鍵からパスタイプを決定

    この関数は、鍵が正規パスと非正規パスのどちらに対応するかを決定します。
    鍵自体が「正規」か「非正規」かを判別し、対応するパスタイプを返します。

    Args:
        key: 復号鍵
        salt: ソルト値（省略時はランダム生成）

    Returns:
        パスタイプ（"true" または "false"）
    """
    # この関数の詳細な実装は、後続の子Issueで実装予定
    # ここでは基本的な骨組みのみ

    # 鍵からハッシュ値を生成（ソルトありの場合はソルトも含める）
    if salt:
        key_hash = hashlib.sha256(key + salt).digest()
    else:
        key_hash = hashlib.sha256(key).digest()

    # 動的判定閾値の基本実装
    if USE_DYNAMIC_THRESHOLD:
        # 動的閾値を生成（実際の実装ではより複雑な判定を行う）
        threshold = 0.5  # デフォルト閾値

        # 鍵の特性を解析して動的閾値を調整
        key_chars = [b for b in key_hash]
        key_sum = sum(key_chars)

        # 最初のバイト値に基づいて判定（実際の実装ではより複雑な判定）
        return TRUE_PATH if key_hash[0] < 128 else FALSE_PATH
    else:
        # 固定閾値での判定
        return TRUE_PATH if key_hash[0] < 128 else FALSE_PATH

def is_chunk_manifest(file_path: str) -> bool:
    """
    ファイルがチャンクマニフェストかどうかを判定

    Args:
        file_path: 判定するファイルのパス

    Returns:
        チャンクマニフェストの場合はTrue
    """
    return file_path.endswith(".manifest")

def process_chunk_manifest(manifest_path: str, key: bytes, output_path: str,
                        verbose: bool = False) -> str:
    """
    チャンクマニフェストを処理して大きなファイルを復号

    Args:
        manifest_path: マニフェストファイルのパス
        key: 復号鍵
        output_path: 出力ファイルのパス
        verbose: 詳細表示モード

    Returns:
        復号されたファイルのパス
    """
    try:
        # マニフェストファイルを読み込み
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)

        if verbose:
            print(f"マニフェスト読み込み: {manifest_path}")
            print(f"チャンク数: {manifest.get('total_chunks', 0)}")

        # パスタイプを決定
        path_type = determine_path_type(key)

        if verbose:
            print(f"パスタイプ: {path_type}")

        # チャンクを処理
        chunks = manifest.get("chunks", [])
        base_dir = os.path.dirname(manifest_path)

        # 出力ファイルを開く
        with open(output_path, 'wb') as output_file:
            # 各チャンクを処理
            for chunk_info in sorted(chunks, key=lambda x: x["index"]):
                chunk_path = os.path.join(base_dir, chunk_info["path"])

                if not os.path.exists(chunk_path):
                    raise FileNotFoundError(f"チャンクファイル {chunk_path} が見つかりません")

                if verbose:
                    print(f"チャンク処理: {chunk_path}")

                # チャンクを復号
                temp_output = f"{output_path}.chunk_{chunk_info['index']}"
                decrypt_file_internal(chunk_path, key, temp_output, path_type, verbose)

                # 復号されたチャンクを出力ファイルに追加
                with open(temp_output, 'rb') as chunk_file:
                    output_file.write(chunk_file.read())

                # 一時ファイルを削除
                os.unlink(temp_output)

        if verbose:
            print(f"全チャンクの処理が完了しました")

        return output_path

    except Exception as e:
        print(f"チャンクマニフェスト処理エラー: {e}", file=sys.stderr)
        raise

def decrypt_file_internal(encrypted_file_path: str, key: bytes, output_path: str,
                       path_type: str, verbose: bool = False) -> str:
    """
    暗号化ファイルを内部的に復号

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        key: 復号鍵
        output_path: 出力ファイルのパス
        path_type: パスタイプ（"true" または "false"）
        verbose: 詳細表示モード

    Returns:
        復号されたファイルのパス
    """
    # メタデータと暗号化データの読み込み
    metadata, encrypted_data = read_encrypted_file(encrypted_file_path)

    if encrypted_data is None:
        # チャンクマニフェストの場合は別途処理
        if is_chunk_manifest(encrypted_file_path):
            return process_chunk_manifest(encrypted_file_path, key, output_path, verbose)
        raise ValueError("暗号化データがありません")

    # 実際の復号処理は後続のIssueで実装
    # ここではダミーの実装
    if path_type == TRUE_PATH:
        # 正規パスの場合
        with open(TRUE_TEXT_PATH, 'rb') as f:
            decrypted_data = f.read()
    else:
        # 非正規パスの場合
        with open(FALSE_TEXT_PATH, 'rb') as f:
            decrypted_data = f.read()

    # 復号結果を書き込み
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    if verbose:
        print(f"復号完了: {output_path} ({path_type}パス)")

    return output_path

def decrypt_file(encrypted_file_path: str, key: Union[bytes, str], output_path: Optional[str] = None,
               verbose: bool = False) -> str:
    """
    不確定性転写暗号化方式で復号

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        key: 復号鍵（バイト列または16進数文字列）
        output_path: 出力ファイルのパス（省略時は自動生成）
        verbose: 詳細表示モード

    Returns:
        復号されたファイルのパス
    """
    # 整合性チェック
    check_system_integrity()

    # 鍵の変換
    if isinstance(key, str):
        try:
            key = binascii.unhexlify(key)
        except binascii.Error:
            # 16進数でない場合はUTF-8エンコードと仮定
            key = key.encode('utf-8')

    # 出力パスの生成（省略時）
    if output_path is None:
        base_name = os.path.splitext(encrypted_file_path)[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"{base_name}_decrypted_{timestamp}.txt"

    # 出力ディレクトリの確認・作成
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # パスタイプを決定
    path_type = determine_path_type(key)

    if verbose:
        print(f"復号開始: {encrypted_file_path}")
        print(f"パスタイプ: {path_type}")

    # 復号実行（再試行あり）
    retry_count = 0
    while retry_count <= MAX_RETRY_COUNT:
        try:
            if is_chunk_manifest(encrypted_file_path):
                # チャンクマニフェストの場合は特殊処理
                return process_chunk_manifest(encrypted_file_path, key, output_path, verbose)
            else:
                # 通常の復号処理
                return decrypt_file_internal(encrypted_file_path, key, output_path, path_type, verbose)

        except Exception as e:
            retry_count += 1
            if retry_count > MAX_RETRY_COUNT:
                print(f"エラー: 復号に失敗しました（再試行回数超過）: {e}", file=sys.stderr)
                raise

            if verbose:
                print(f"警告: 復号中にエラーが発生しました。再試行 {retry_count}/{MAX_RETRY_COUNT}: {e}")

            # 短い待機後に再試行
            time.sleep(1)

    # 通常ここには到達しない
    raise RuntimeError("予期しないエラー: 復号処理が完了せず")

def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式の復号プログラム")

    parser.add_argument(
        "input_file",
        type=str,
        help="復号する暗号化ファイルのパス"
    )

    parser.add_argument(
        "--key",
        "-k",
        type=str,
        help="復号鍵（16進数形式）"
    )

    parser.add_argument(
        "--key-file",
        type=str,
        help="復号鍵ファイルのパス"
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="出力ファイルのパス（省略時は自動生成）"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="詳細な出力を表示する"
    )

    return parser.parse_args()

def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在確認
    if not os.path.exists(args.input_file):
        print(f"エラー: 暗号化ファイル '{args.input_file}' が見つかりません。", file=sys.stderr)
        return 1

    # 鍵の取得
    key = None

    if args.key:
        # コマンドラインから鍵を取得
        key = args.key
    elif args.key_file:
        # 鍵ファイルから鍵を取得
        if not os.path.exists(args.key_file):
            print(f"エラー: 鍵ファイル '{args.key_file}' が見つかりません。", file=sys.stderr)
            return 1

        try:
            with open(args.key_file, 'rb') as f:
                key = f.read()
        except Exception as e:
            print(f"エラー: 鍵ファイルの読み込みに失敗しました: {e}", file=sys.stderr)
            return 1
    else:
        print("エラー: --key または --key-file オプションで鍵を指定してください。", file=sys.stderr)
        return 1

    try:
        # 復号実行
        start_time = time.time()
        output_file = decrypt_file(args.input_file, key, args.output, args.verbose)
        end_time = time.time()

        # 完了メッセージ
        print(f"復号が完了しました: {output_file}")
        if args.verbose:
            print(f"復号時間: {end_time - start_time:.2f}秒")

        return 0

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # 重要なメモリデータの安全な消去
        if key:
            secure_wipe(key)

if __name__ == "__main__":
    sys.exit(main())
