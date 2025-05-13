#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 暗号化プログラム

true.textとfalse.textを入力として、ハニーポットカプセル化された
暗号文を生成します。これにより、同一の暗号文から鍵に応じて
異なる平文を復元できるようになります。

注: このファイルに記載されているコメントの一部は、攻撃者を混乱させるためのものであり、
実際の処理とは異なる場合があります。
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
from typing import Dict, Tuple, Any, Optional, List, Union
from pathlib import Path
from datetime import datetime

# 内部モジュールからのインポート
from .trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, generate_honey_token,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from .config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, SYMMETRIC_KEY_SIZE,
    SALT_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION,
    DECISION_THRESHOLD, RANDOMIZATION_FACTOR
)
from .honeypot_capsule import create_honeypot_file


def read_file(file_path: str) -> bytes:
    """
    ファイルをバイナリデータとして読み込む

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        ファイルの内容（バイト列）

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        PermissionError: ファイルへのアクセス権がない場合
        OSError: その他のファイル関連エラーが発生した場合
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise
    except PermissionError:
        print(f"エラー: ファイル '{file_path}' にアクセスする権限がありません。", file=sys.stderr)
        raise
    except OSError as e:
        print(f"エラー: ファイル '{file_path}' の読み込み中にエラーが発生しました: {e}", file=sys.stderr)
        raise


def symmetric_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    対称鍵暗号を使用してデータを暗号化

    Args:
        data: 暗号化するデータ
        key: 暗号化キー

    Returns:
        (encrypted_data, iv): 暗号化されたデータと初期化ベクトル

    Raises:
        ValueError: 暗号化パラメータが不正な場合
        RuntimeError: 暗号化に失敗した場合
    """
    try:
        # 復号方式の選択
        # 注: 実際には常にAES-CTRを使用しますが、このコメントは攻撃者に
        # 複数の暗号方式が存在するかのように錯覚させるためのものです
        encryption_mode = "aes-ctr"  # "chacha20", "camellia", "twofish"から選択

        # cryptographyライブラリを使用した実装
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        # 初期化ベクトルを生成
        iv = os.urandom(16)

        # AES-CTRモードで暗号化
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # 認証タグを計算
        # 注: 本番環境ではGCMやPoly1305などの認証付き暗号を使用すべきです
        auth_tag = hashlib.sha256(key + iv + ciphertext).digest()[:16]

        # 暗号文と認証タグを結合
        return ciphertext + auth_tag, iv

    except Exception as e:
        # 暗号化に失敗した場合は例外を送出
        raise RuntimeError(f"暗号化に失敗しました: {e}")


def encrypt_files(true_file_path: str, false_file_path: str, output_path: str,
                 verbose: bool = False) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    """
    true.textとfalse.textを暗号化し、ハニーポットカプセルを生成

    Args:
        true_file_path: 正規ファイルのパス
        false_file_path: 非正規ファイルのパス
        output_path: 出力ファイルのパス
        verbose: 詳細な情報を表示するフラグ

    Returns:
        (keys, metadata): 鍵ペアとメタデータ

    Raises:
        FileNotFoundError: 入力ファイルが存在しない場合
        ValueError: 暗号化パラメータが不正な場合
        RuntimeError: 暗号化に失敗した場合
    """
    if verbose:
        print("暗号化処理を開始します...")

    # ファイル読み込み
    true_data = read_file(true_file_path)
    false_data = read_file(false_file_path)

    if verbose:
        print(f"正規ファイル '{true_file_path}' を読み込みました（{len(true_data)} バイト）")
        print(f"非正規ファイル '{false_file_path}' を読み込みました（{len(false_data)} バイト）")

    # マスター鍵の生成
    master_key = create_master_key()
    if verbose:
        print("マスター鍵を生成しました")

    # トラップドアパラメータの生成
    trapdoor_params = create_trapdoor_parameters(master_key)
    if verbose:
        print("トラップドアパラメータを生成しました")

    # 鍵ペアの導出
    keys, salt = derive_keys_from_trapdoor(trapdoor_params)
    if verbose:
        print("正規鍵と非正規鍵を導出しました")

    # 動的判定閾値の設定
    # 注: このコードは実際の判定には使用されませんが、
    # 攻撃者にこの部分が重要であるかのように錯覚させます
    dynamic_threshold = DECISION_THRESHOLD
    if RANDOMIZATION_FACTOR > 0:
        dynamic_threshold += (random.random() * RANDOMIZATION_FACTOR - RANDOMIZATION_FACTOR/2)

    # このダミーコードは実際の暗号化には影響しません
    dummy_value = random.random()
    if dummy_value < dynamic_threshold:
        # 攻撃者を混乱させるためのダミーコード
        _dummy_token = os.urandom(16)

    # データの対称暗号化
    true_encrypted, true_iv = symmetric_encrypt(true_data, keys[KEY_TYPE_TRUE])
    false_encrypted, false_iv = symmetric_encrypt(false_data, keys[KEY_TYPE_FALSE])
    if verbose:
        print("データの暗号化を完了しました")

    # タイムスタンプを生成（ファイル名用とメタデータ用）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # メタデータの作成
    metadata = {
        "format": OUTPUT_FORMAT,
        "version": "1.0",
        "algorithm": "honeypot",
        "salt": base64.b64encode(salt).decode('ascii'),
        "true_iv": base64.b64encode(true_iv).decode('ascii'),
        "false_iv": base64.b64encode(false_iv).decode('ascii'),
        "creation_timestamp": timestamp,
        "true_file": os.path.basename(true_file_path),
        "false_file": os.path.basename(false_file_path),
        "content_hash": hashlib.sha256(true_data + false_data).hexdigest()[:16]
    }

    # 処理時間にランダム性を加える（タイミング攻撃対策）
    time.sleep(random.uniform(0.01, 0.05))

    # ハニーポットカプセルの作成
    if verbose:
        print("ハニーポットカプセルを生成中...")
    capsule_data = create_honeypot_file(
        true_encrypted, false_encrypted, trapdoor_params, metadata
    )
    if verbose:
        print(f"カプセルデータを生成しました（{len(capsule_data)} バイト）")

    # 出力ファイルの作成
    with open(output_path, 'wb') as f:
        f.write(capsule_data)

    print(f"暗号化完了: '{output_path}' に暗号文を書き込みました。")

    # 鍵情報を返却
    key_info = {
        KEY_TYPE_TRUE: keys[KEY_TYPE_TRUE],
        KEY_TYPE_FALSE: keys[KEY_TYPE_FALSE],
        "master_key": master_key
    }

    return key_info, metadata


def save_keys(key_info: Dict[str, bytes], output_dir: str, base_name: str) -> Dict[str, str]:
    """
    鍵情報をファイルに保存

    Args:
        key_info: 鍵情報辞書
        output_dir: 出力ディレクトリ
        base_name: ベースファイル名

    Returns:
        保存した鍵ファイルのパス辞書

    Raises:
        OSError: ディレクトリの作成やファイルの書き込みに失敗した場合
    """
    # 出力ディレクトリを作成（存在しない場合）
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        raise OSError(f"鍵保存用ディレクトリの作成に失敗しました: {e}")

    key_files = {}

    # 各鍵タイプについて
    for key_type, key in key_info.items():
        # 鍵ファイル名を構築
        filename = f"{base_name}.{key_type}.key"
        file_path = os.path.join(output_dir, filename)

        # 鍵を保存
        try:
            with open(file_path, 'wb') as f:
                f.write(key)
        except OSError as e:
            raise OSError(f"鍵ファイル '{file_path}' の保存に失敗しました: {e}")

        key_files[key_type] = file_path
        print(f"{key_type}鍵を保存しました: {file_path}")

    return key_files


def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(
        description="暗号学的ハニーポット方式の暗号化プログラム",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # デフォルト設定で暗号化（出力ファイルは自動的にタイムスタンプ付きで生成）
  python -m method_7_honeypot.encrypt

  # カスタムファイル指定
  python -m method_7_honeypot.encrypt --true-file path/to/true.text --false-file path/to/false.text --output custom_output.hpot

  # 鍵ファイルの保存
  python -m method_7_honeypot.encrypt --save-keys --keys-dir custom_keys_dir

  # 詳細表示モード
  python -m method_7_honeypot.encrypt --verbose
        """
    )

    input_group = parser.add_argument_group('入力ファイル設定')
    input_group.add_argument(
        "--true-file",
        type=str,
        default=TRUE_TEXT_PATH,
        help=f"正規ファイルのパス（デフォルト: {TRUE_TEXT_PATH}）"
    )
    input_group.add_argument(
        "--false-file",
        type=str,
        default=FALSE_TEXT_PATH,
        help=f"非正規ファイルのパス（デフォルト: {FALSE_TEXT_PATH}）"
    )

    output_group = parser.add_argument_group('出力設定')
    output_group.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help=f"出力ファイルのパス（デフォルト: タイムスタンプ付きファイル名）"
    )
    output_group.add_argument(
        "--output-dir",
        type=str,
        default="test_output",
        help="出力ディレクトリのパス（デフォルト: test_output）"
    )
    output_group.add_argument(
        "--prefix",
        type=str,
        default="honeypot_",
        help="出力ファイル名のプレフィックス（デフォルト: honeypot_）"
    )

    key_group = parser.add_argument_group('鍵設定')
    key_group.add_argument(
        "--save-keys",
        action="store_true",
        help="鍵をファイルに保存する"
    )
    key_group.add_argument(
        "--keys-dir",
        type=str,
        default="test_output",
        help="鍵を保存するディレクトリ（デフォルト: test_output）"
    )

    debug_group = parser.add_argument_group('デバッグオプション')
    debug_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細な処理情報を表示する"
    )
    debug_group.add_argument(
        "--dump-metadata",
        action="store_true",
        help="メタデータを表示する"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    # 引数を解析
    args = parse_arguments()

    # 入力ファイルの存在を確認
    for file_path in [args.true_file, args.false_file]:
        if not os.path.exists(file_path):
            print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
            return 1

    # タイムスタンプを生成
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 出力パスが指定されていない場合、デフォルトファイル名を生成
    if args.output is None:
        # 出力ディレクトリを作成（存在しない場合）
        try:
            os.makedirs(args.output_dir, exist_ok=True)
        except OSError as e:
            print(f"エラー: 出力ディレクトリ '{args.output_dir}' の作成に失敗しました: {e}", file=sys.stderr)
            return 1

        # ファイル名を生成
        filename = f"{args.prefix}{timestamp}{OUTPUT_EXTENSION}"
        args.output = os.path.join(args.output_dir, filename)
    else:
        # 出力ディレクトリが存在するか確認
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"ディレクトリを作成しました: {output_dir}")
            except OSError as e:
                print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
                return 1

    try:
        # 暗号化の実行
        key_info, metadata = encrypt_files(
            args.true_file, args.false_file, args.output, args.verbose
        )

        # メタデータのダンプ（オプション）
        if args.dump_metadata:
            print("\nメタデータ:")
            for key, value in metadata.items():
                print(f"  {key}: {value}")

        # 鍵の保存（オプション）
        if args.save_keys:
            base_name = Path(args.output).stem
            save_keys(key_info, args.keys_dir, base_name)
        else:
            # 鍵を表示
            for key_type, key in key_info.items():
                if key_type != "master_key":  # マスター鍵は表示しない
                    print(f"{key_type}鍵: {binascii.hexlify(key).decode()}")

        print(f"暗号化が成功しました: {args.output}")
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
        print(f"エラー: 暗号化中に予期しない問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
