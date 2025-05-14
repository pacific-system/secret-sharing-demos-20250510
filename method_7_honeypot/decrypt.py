#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 復号プログラム

ハニーポットカプセル化された暗号文を復号し、提供された鍵に応じて
正規または非正規の平文を出力します。このプログラムは、攻撃者が
ソースコードを解析しても、復号結果の真偽を判定できないよう設計されています。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import time
import secrets
import binascii
import random
from typing import Dict, Tuple, Any, Optional, List, Union, BinaryIO
from pathlib import Path
from datetime import datetime
import io
import hmac
import tempfile
import logging

# 内部モジュールからのインポート
from .trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, evaluate_key_type,
    derive_user_key_material, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from .key_verification import verify_key_and_select_path, verify_key_type, get_signature_key
from .honeypot_capsule import (
    HoneypotCapsule, extract_data_from_capsule,
    read_data_from_honeypot_file, extract_data_from_honeypot, validate_honeypot_signature
)
from .config import (
    OUTPUT_EXTENSION, SYMMETRIC_KEY_SIZE, SALT_SIZE,
    KDF_ITERATIONS, DECISION_THRESHOLD, RANDOMIZATION_FACTOR,
    TOKEN_SIZE, OUTPUT_FORMAT, DEFAULT_OUTPUT_DIR, DEFAULT_PREFIX, DEFAULT_CHUNK_SIZE,
    USE_DYNAMIC_THRESHOLD
)
from .deception import (
    verify_with_tamper_resistance,
    create_redundant_verification_pattern,
    DynamicPathSelector
)

# 暗号化モジュールからのインポート
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def symmetric_decrypt(encrypted_data: bytes, key: bytes, iv: bytes, is_chunk: bool = False) -> bytes:
    """
    対称鍵暗号を使用してデータを復号

    Args:
        encrypted_data: 復号するデータ（暗号文 + 認証タグ）
        key: 復号キー
        iv: 初期化ベクトル
        is_chunk: データがチャンクであるかどうか（大きなファイルの処理時）

    Returns:
        復号されたデータ

    Raises:
        ValueError: 認証に失敗した場合や暗号化パラメータが不正な場合
        RuntimeError: 復号に失敗した場合
    """
    try:
        # cryptographyライブラリを使用した実装
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        # データが小さすぎる場合はエラー
        if len(encrypted_data) < 16 and not is_chunk:  # 認証タグサイズ
            raise ValueError("データサイズが小さすぎます")

        # 大きなファイルを処理する場合、チャンクごとの認証は行わない
        if is_chunk:
            ciphertext = encrypted_data
        else:
            # 暗号文と認証タグを分離
            ciphertext_len = len(encrypted_data) - 16  # 認証タグは16バイト
            ciphertext = encrypted_data[:ciphertext_len]
            auth_tag = encrypted_data[ciphertext_len:]

            # 認証タグを検証
            expected_tag = hashlib.sha256(key + iv + ciphertext).digest()[:16]
            if not secrets.compare_digest(auth_tag, expected_tag):
                raise ValueError("認証に失敗しました。データが改ざんされている可能性があります。")

        # AES-CTRモードで復号
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # ランダムなスリープを追加（タイミング攻撃対策）
        time.sleep(random.uniform(0.001, 0.005))

        return plaintext

    except Exception as e:
        # 暗号化に失敗した場合は例外を送出
        raise RuntimeError(f"復号に失敗しました: {str(e)}")


def read_key_from_file(key_path: str) -> bytes:
    """
    ファイルから鍵を読み込む

    Args:
        key_path: 鍵ファイルのパス

    Returns:
        鍵のバイト列

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        PermissionError: ファイルへのアクセス権がない場合
        OSError: その他のファイル関連エラーが発生した場合
    """
    try:
        with open(key_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"エラー: 鍵ファイル '{key_path}' が見つかりません。", file=sys.stderr)
        raise
    except PermissionError:
        print(f"エラー: 鍵ファイル '{key_path}' にアクセスする権限がありません。", file=sys.stderr)
        raise
    except OSError as e:
        print(f"エラー: 鍵ファイル '{key_path}' の読み込み中にエラーが発生しました: {e}", file=sys.stderr)
        raise


def read_key_from_hex(hex_key: str) -> bytes:
    """
    16進数文字列から鍵を読み込む

    Args:
        hex_key: 16進数形式の鍵

    Returns:
        鍵のバイト列

    Raises:
        ValueError: 16進数文字列の形式が不正な場合
    """
    try:
        return binascii.unhexlify(hex_key)
    except (binascii.Error, ValueError):
        print(f"エラー: 不正な16進数形式の鍵です: {hex_key}", file=sys.stderr)
        raise


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    パスワードから鍵を導出

    Args:
        password: 鍵導出に使用するパスワード
        salt: ソルト値

    Returns:
        導出された鍵
    """
    key_material, _ = derive_user_key_material(password, salt)
    return key_material


def read_encrypted_file(file_path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    暗号化ファイルを読み込み、メタデータとカプセルデータに分離

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (data, metadata): カプセルデータとメタデータのタプル

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        ValueError: ファイル形式が不正な場合
    """
    try:
        # ファイルを読み込み
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        # ファイルサイズを確認
        if len(encrypted_data) < 256:  # 最小サイズの確認
            raise ValueError("ファイルサイズが小さすぎます。有効な暗号化ファイルではありません。")

        # メタデータを抽出（最初に両方のキータイプで試行）
        metadata = None
        try:
            _, metadata = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_TRUE)
        except Exception:
            try:
                _, metadata = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_FALSE)
            except Exception as e:
                raise ValueError(f"メタデータの抽出に失敗しました: {str(e)}")

        if metadata is None:
            raise ValueError("ファイルにメタデータが含まれていません。")

        return encrypted_data, metadata

    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise
    except OSError as e:
        print(f"エラー: ファイル '{file_path}' の読み込み中にエラーが発生しました: {e}", file=sys.stderr)
        raise


def determine_key_type(key: bytes, encrypted_data: bytes, metadata: Dict[str, Any]) -> str:
    """
    鍵の種類（正規/非正規）を判定

    Args:
        key: 判定する鍵
        encrypted_data: 暗号化データ
        metadata: メタデータ

    Returns:
        鍵のタイプ（"true" または "false"）
    """
    # 開始時間を記録（タイミング攻撃対策）
    start_time = time.perf_counter()

    # salt値を取得
    salt_base64 = metadata.get('salt')
    if not salt_base64:
        # メタデータにsaltがない場合はデフォルト値を使用
        salt = os.urandom(SALT_SIZE)
    else:
        # Base64デコード
        salt = base64.b64decode(salt_base64)

    # 動的判定閾値の計算
    dynamic_threshold = DECISION_THRESHOLD
    if RANDOMIZATION_FACTOR > 0:
        dynamic_threshold += (random.random() * RANDOMIZATION_FACTOR - RANDOMIZATION_FACTOR/2)

    # トラップドアパラメータの復元（このコードは実際には使用されない偽装）
    dummy_master_key = hashlib.sha256(key + salt).digest()
    dummy_params = {"seed": dummy_master_key}

    # 両方のキータイプでデータ取得を試行（タイミング攻撃対策）
    try:
        _ = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_TRUE)
    except Exception:
        pass

    try:
        _ = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_FALSE)
    except Exception:
        pass

    # ダミー演算（タイミング攻撃対策）
    _ = hashlib.sha256(key + salt).digest()

    # 最小検証時間を確保（タイミング攻撃対策）
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    min_time_ms = 15  # 最小検証時間（ミリ秒）
    if elapsed_ms < min_time_ms:
        time.sleep((min_time_ms - elapsed_ms) / 1000)

    # 処理時間にランダムな変動を追加
    time.sleep(random.uniform(0.001, 0.01))

    # 暗号化されたデータを解析してみて判断
    # 注: これは意図的に複雑にしていますが、実際には単純な判定が行われます
    # 攻撃者がこれを解析しないよう複雑に見せる作戦です
    try:
        # 仮にTRUEタイプとして処理を試行
        try:
            true_data, _ = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_TRUE)
            try:
                # IVを取得
                true_iv = base64.b64decode(metadata.get('true_iv', ''))
                # 復号を試行
                _ = symmetric_decrypt(true_data, key, true_iv)
                return KEY_TYPE_TRUE
            except Exception:
                pass
        except Exception:
            pass

        # 仮にFALSEタイプとして処理を試行
        try:
            false_data, _ = read_data_from_honeypot_file(encrypted_data, KEY_TYPE_FALSE)
            try:
                # IVを取得
                false_iv = base64.b64decode(metadata.get('false_iv', ''))
                # 復号を試行
                _ = symmetric_decrypt(false_data, key, false_iv)
                return KEY_TYPE_FALSE
            except Exception:
                pass
        except Exception:
            pass
    except Exception:
        # 何かエラーが起きても処理を継続
        pass

    # どちらも失敗した場合は、デフォルトのキータイプを返す
    # この値は使用されませんが、攻撃者を混乱させるために存在します
    return KEY_TYPE_TRUE


def decrypt_file(file_path: str, key: bytes, output_path: Optional[str] = None,
                verbose: bool = False) -> str:
    """
    ハニーポットカプセル化されたファイルを復号

    Args:
        file_path: 暗号化ファイルのパス
        key: 復号キー
        output_path: 出力ファイルのパス（省略時は標準出力）
        verbose: 詳細表示モード

    Returns:
        出力ファイルのパス（標準出力の場合は空文字列）

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        ValueError: 復号に失敗した場合
    """
    try:
        if verbose:
            print("復号処理を開始します...")

        # 暗号化ファイルを読み込み
        encrypted_data, metadata = read_encrypted_file(file_path)

        if verbose:
            print(f"暗号化ファイル '{file_path}' を読み込みました（{len(encrypted_data)} バイト）")
            print(f"フォーマット: {metadata.get('format', '不明')}")
            print(f"バージョン: {metadata.get('version', '不明')}")

        # 鍵のタイプを判定
        key_type = determine_key_type(key, encrypted_data, metadata)

        if verbose:
            # 注: 実際には判定結果そのものは表示しない（セキュリティ上の理由から）
            print("鍵の検証が完了しました")

        # Base64エンコードされたIVを取得
        iv_key = 'true_iv' if key_type == KEY_TYPE_TRUE else 'false_iv'
        iv_base64 = metadata.get(iv_key, '')

        if not iv_base64:
            raise ValueError(f"メタデータに必要なIV情報がありません。")

        iv = base64.b64decode(iv_base64)

        if verbose:
            print("初期化ベクトル（IV）を取得しました")

        # 暗号化データを取得
        encrypted_content, _ = read_data_from_honeypot_file(encrypted_data, key_type)

        if verbose:
            print(f"ハニーポットカプセルからデータを抽出しました（{len(encrypted_content)} バイト）")

        # データを復号
        decrypted_data = symmetric_decrypt(encrypted_content, key, iv)

        if verbose:
            print("データの復号が完了しました")

        # 復号結果を出力
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            if verbose:
                print(f"復号データを '{output_path}' に保存しました")

            return output_path
        else:
            # 標準出力に書き込み
            if verbose:
                print("復号データを標準出力に書き込みます:")

            # バイナリデータを標準出力に書き込む
            sys.stdout.buffer.write(decrypted_data)
            return ""

    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise
    except ValueError as e:
        print(f"エラー: 値が不正です: {str(e)}", file=sys.stderr)
        raise
    except RuntimeError as e:
        print(f"エラー: 実行時エラー: {str(e)}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"エラー: ファイルの復号に失敗しました: {str(e)}", file=sys.stderr)
        raise


def process_large_file(file_path: str, key: bytes, output_path: str,
                     max_chunk_size: int = 10 * 1024 * 1024, verbose: bool = False) -> None:
    """
    大きなファイルを分割して処理

    Args:
        file_path: 暗号化ファイルのパス
        key: 復号キー
        output_path: 出力ファイルのパス
        max_chunk_size: 最大チャンクサイズ（バイト）
        verbose: 詳細表示モード

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        ValueError: 復号に失敗した場合
    """
    try:
        # ファイルサイズを取得
        file_size = os.path.getsize(file_path)

        if file_size <= max_chunk_size:
            # 小さいファイルは通常の復号処理
            decrypt_file(file_path, key, output_path, verbose)
            return

        if verbose:
            print(f"大きなファイル（{file_size} バイト）を分割処理します...")

        # 暗号化ファイルを読み込み
        encrypted_data, metadata = read_encrypted_file(file_path)

        # 鍵のタイプを判定
        key_type = determine_key_type(key, encrypted_data, metadata)

        # Base64エンコードされたIVを取得
        iv_key = 'true_iv' if key_type == KEY_TYPE_TRUE else 'false_iv'
        iv_base64 = metadata.get(iv_key, '')

        if not iv_base64:
            raise ValueError(f"メタデータに必要なIV情報がありません。")

        iv = base64.b64decode(iv_base64)

        # 暗号化データを取得
        encrypted_content, _ = read_data_from_honeypot_file(encrypted_data, key_type)

        # 出力ファイルを開く
        with open(output_path, 'wb') as output_file:
            # データを分割して処理
            total_chunks = (len(encrypted_content) + max_chunk_size - 1) // max_chunk_size

            for i in range(total_chunks):
                chunk_start = i * max_chunk_size
                chunk_end = min((i + 1) * max_chunk_size, len(encrypted_content))

                if verbose:
                    print(f"チャンク {i+1}/{total_chunks} 処理中... ({chunk_end-chunk_start} バイト)")

                # チャンクを取得
                chunk = encrypted_content[chunk_start:chunk_end]

                # チャンクを復号（チャンクとしてマーク）
                decrypted_chunk = symmetric_decrypt(chunk, key, iv, is_chunk=True)

                # 復号結果を書き込み
                output_file.write(decrypted_chunk)

                if verbose:
                    print(f"チャンク {i+1} を処理しました")

        if verbose:
            print(f"大きなファイルの処理が完了しました。結果を '{output_path}' に保存しました。")

    except Exception as e:
        print(f"エラー: 大きなファイルの処理に失敗しました: {str(e)}", file=sys.stderr)
        raise


def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(
        description="暗号学的ハニーポット方式の復号プログラム",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # 鍵ファイルを使用して復号
  python -m method_7_honeypot.decrypt encrypted.hpot --key-file key.true.key --output decrypted.txt

  # 16進数形式の鍵を使用して復号
  python -m method_7_honeypot.decrypt encrypted.hpot --key ABCDEF0123456789 --output decrypted.txt

  # パスワードを使用して復号
  python -m method_7_honeypot.decrypt encrypted.hpot --password "my-secret-password" --output decrypted.txt

  # 詳細表示モード
  python -m method_7_honeypot.decrypt encrypted.hpot --key-file key.true.key --output decrypted.txt --verbose
        """
    )

    # 入力ファイル
    parser.add_argument(
        "input_file",
        type=str,
        help=f"復号する暗号化ファイルのパス（{OUTPUT_EXTENSION}形式）"
    )

    # 鍵オプション（相互排他）
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--key-file",
        type=str,
        help="鍵ファイルのパス"
    )
    key_group.add_argument(
        "--key",
        type=str,
        help="16進数形式の鍵"
    )
    key_group.add_argument(
        "--password",
        type=str,
        help="パスワード（ソルトはメタデータから取得）"
    )

    # 出力オプション
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="出力ファイルのパス（省略時は標準出力）"
    )

    # 出力ディレクトリ
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="出力ディレクトリのパス（--outputが省略されている場合のみ使用）"
    )

    # 大きなファイル処理オプション
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=10 * 1024 * 1024,  # デフォルト: 10MB
        help="大きなファイル処理時のチャンクサイズ（バイト）"
    )

    # その他のオプション
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細な処理情報を表示する"
    )
    parser.add_argument(
        "--dump-metadata",
        action="store_true",
        help="メタデータを表示する"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在を確認
    if not os.path.exists(args.input_file):
        print(f"エラー: ファイル '{args.input_file}' が見つかりません。", file=sys.stderr)
        return 1

    # 鍵を取得
    try:
        if args.key_file:
            key = read_key_from_file(args.key_file)
            if args.verbose:
                print(f"鍵ファイル '{args.key_file}' から鍵を読み込みました")
        elif args.key:
            key = read_key_from_hex(args.key)
            if args.verbose:
                print("16進数形式から鍵を読み込みました")
        elif args.password:
            # メタデータからソルトを取得
            try:
                _, metadata = read_encrypted_file(args.input_file)
                salt_base64 = metadata.get('salt')
                if not salt_base64:
                    print("エラー: メタデータにソルト情報がありません。", file=sys.stderr)
                    return 1
                salt = base64.b64decode(salt_base64)
                key = derive_key_from_password(args.password, salt)
                if args.verbose:
                    print("パスワードから鍵を導出しました")
            except Exception as e:
                print(f"エラー: パスワードからの鍵導出に失敗しました: {e}", file=sys.stderr)
                return 1
    except Exception as e:
        print(f"エラー: 鍵の読み込みに失敗しました: {e}", file=sys.stderr)
        return 1

    # メタデータのダンプ（オプション）
    if args.dump_metadata:
        try:
            _, metadata = read_encrypted_file(args.input_file)
            print("\nメタデータ:")
            for key, value in metadata.items():
                # ソルトとIVはBase64エンコードされた値を表示
                print(f"  {key}: {value}")
        except Exception as e:
            print(f"エラー: メタデータの表示に失敗しました: {e}", file=sys.stderr)
            return 1

    # 出力パスの設定
    output_path = args.output
    if output_path is None and sys.stdout.isatty():
        # 標準出力がターミナルで、出力パスが指定されていない場合は自動生成
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        input_filename = os.path.basename(args.input_file)
        output_filename = f"decrypted_{input_filename.rsplit('.', 1)[0]}_{timestamp}.txt"
        output_path = os.path.join(args.output_dir, output_filename)

        if args.verbose:
            print(f"出力ファイルを自動生成しました: {output_path}")

    # 出力ディレクトリの確認と作成
    if output_path:
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                if args.verbose:
                    print(f"ディレクトリを作成しました: {output_dir}")
            except OSError as e:
                print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
                return 1

    try:
        # ファイルのサイズを確認
        file_size = os.path.getsize(args.input_file)

        if file_size > args.chunk_size:
            # 大きなファイルは分割して処理
            if args.verbose:
                print(f"大きなファイル（{file_size} バイト）を分割して処理します")

            process_large_file(args.input_file, key, output_path, args.chunk_size, args.verbose)
        else:
            # 通常サイズのファイルは一括処理
            decrypt_file(args.input_file, key, output_path, args.verbose)

        if output_path:
            print(f"復号が成功しました: {output_path}")

        return 0

    except FileNotFoundError as e:
        print(f"エラー: ファイルが見つかりません: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"エラー: ファイルアクセス権限がありません: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"エラー: 不正な値またはパラメータです: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"エラー: 実行時エラーが発生しました: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"エラー: ファイル操作エラーが発生しました: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"エラー: 復号中に予期しない問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
