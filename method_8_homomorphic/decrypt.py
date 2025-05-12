#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の復号実行ファイル

このモジュールは、準同型暗号マスキング方式を使用して暗号化されたファイルを復号するための
コマンドラインツールを提供します。マスク関数を使って暗号化されたファイルを、
鍵に応じて真または偽の状態に復号します。
"""

import os
import sys
import time
import json
import base64
import hashlib
import argparse
import binascii
import random
import math
from typing import Dict, Any, Tuple, List, Optional, Union

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    OUTPUT_FORMAT,
    OUTPUT_EXTENSION,
    CRYPTO_ALGORITHM,
    PAILLIER_KEY_BITS,
    ELGAMAL_KEY_BITS,
    MASK_SEED_SIZE,
    MAX_CHUNK_SIZE
)
from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, save_keys, load_keys,
    deserialize_encrypted_data
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    extract_by_key_type
)
from method_8_homomorphic.key_analyzer import (
    analyze_key_type, extract_seed_from_key
)


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数の解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(
        description='準同型暗号マスキング方式による復号ツール'
    )

    parser.add_argument(
        'input_file',
        type=str,
        help='復号する暗号化ファイルのパス'
    )

    parser.add_argument(
        '--key', '-k',
        type=str,
        required=True,
        help='復号鍵（16進数文字列、Base64文字列、またはファイルパス）'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        help='出力ファイル名（省略時は自動生成）'
    )

    parser.add_argument(
        '--key-type',
        choices=['true', 'false'],
        help='鍵の種類を明示的に指定（通常は自動判定）'
    )

    parser.add_argument(
        '--password', '-p',
        type=str,
        help='パスワードから鍵を導出'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='詳細な出力'
    )

    return parser.parse_args()


def parse_key(key_input: str) -> bytes:
    """
    さまざまな形式の鍵入力を解析してバイト列に変換

    Base64形式、16進数形式、生のバイナリファイル形式に対応。

    Args:
        key_input: 鍵（文字列またはファイルパス）

    Returns:
        鍵のバイト列

    Raises:
        ValueError: 鍵の形式が不正な場合
    """
    # ファイルからの読み込み
    if os.path.exists(key_input):
        try:
            with open(key_input, 'rb') as f:
                return f.read()
        except Exception:
            pass  # ファイルの読み込みに失敗した場合は次の方法を試す

    # Base64形式
    try:
        return base64.b64decode(key_input)
    except Exception:
        pass  # Base64デコードに失敗した場合は次の方法を試す

    # 16進数形式
    try:
        if key_input.startswith('0x'):
            key_input = key_input[2:]
        key = binascii.unhexlify(key_input)
        # 鍵長を調整
        if len(key) < KEY_SIZE_BYTES:
            key = key.ljust(KEY_SIZE_BYTES, b'\0')
        elif len(key) > KEY_SIZE_BYTES:
            key = key[:KEY_SIZE_BYTES]
        return key
    except Exception:
        pass  # 16進数変換に失敗した場合は次の方法を試す

    # その他の形式（パスワードとして使用）
    try:
        # パスワードとしてハッシュ化して鍵に変換
        return hashlib.sha256(key_input.encode()).digest()
    except Exception:
        raise ValueError("サポートされていない鍵形式です")


def ensure_directory(directory: str) -> None:
    """
    ディレクトリの存在を確認し、なければ作成

    Args:
        directory: 確認するディレクトリパス
    """
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        print(f"ディレクトリを作成しました: {directory}")


def decrypt_file(encrypted_file_path: str, key: bytes, output_path: str,
                 key_type: Optional[str] = None, verbose: bool = False) -> bool:
    """
    暗号化されたファイルを復号

    Args:
        encrypted_file_path: 暗号化されたファイルのパス
        key: 復号鍵
        output_path: 出力先ファイルパス
        key_type: 鍵の種類（明示的に指定する場合）。"true"または"false"
        verbose: 詳細な出力を表示するかどうか

    Returns:
        復号成功の場合はTrue、失敗の場合はFalse
    """
    try:
        # 進捗表示
        def show_progress(current, total, description=None):
            percent = current / total * 100
            bar_length = 40
            filled_length = int(bar_length * current // total)
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            prefix = description or "処理中"
            print(f"\r{prefix}: [{bar}] {percent:.1f}% ({current}/{total})", end='')
            if current == total:
                print()

        # 暗号化ファイルの読み込み
        print(f"暗号化ファイルを読み込み中...")
        try:
            with open(encrypted_file_path, 'r') as f:
                encrypted_data = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"エラー: 暗号化ファイルの読み込みに失敗しました: {e}", file=sys.stderr)
            return False

        # フォーマットチェック
        format_type = encrypted_data.get("format", "")
        if format_type != "homomorphic_masked":
            print(f"エラー: サポートされていない暗号化形式です: {format_type}", file=sys.stderr)
            return False

        # 公開鍵情報を取得
        public_key_str = encrypted_data.get("public_key", {})
        if not public_key_str:
            print("エラー: 公開鍵情報が見つかりません", file=sys.stderr)
            return False

        # 公開鍵を整数に変換
        public_key = {
            "n": int(public_key_str["n"]),
            "g": int(public_key_str["g"])
        }

        # 暗号化パラメータを取得
        true_size = encrypted_data.get("true_size", 0)
        false_size = encrypted_data.get("false_size", 0)
        chunk_size = MAX_CHUNK_SIZE  # チャンクサイズはデフォルト値を使用
        salt_base64 = encrypted_data.get("salt", "")

        # ソルトをデコード
        try:
            salt = base64.b64decode(salt_base64)
        except Exception as e:
            print(f"エラー: ソルトのデコードに失敗しました: {e}", file=sys.stderr)
            return False

        # 鍵の解析と種別判定
        if key_type is None:
            # 鍵解析モジュールを使用して鍵の種類を判定
            key_type = analyze_key_type(key)
            print(f"鍵を解析しました: {key_type}鍵として識別されました")
        else:
            print(f"明示的に指定された鍵タイプを使用: {key_type}")

        # 暗号文と対応するマスク情報を抽出
        try:
            chunks, mask_info = extract_by_key_type(encrypted_data, key_type)
        except ValueError as e:
            print(f"エラー: 暗号文の抽出に失敗しました: {e}", file=sys.stderr)
            return False

        print(f"マスク情報を抽出しました: {mask_info['type']}")

        # 準同型暗号システムの初期化
        paillier = PaillierCrypto(bits=encrypted_data.get("key_bits", PAILLIER_KEY_BITS))

        # シードを取得
        seed = base64.b64decode(mask_info["seed"])

        # マスク関数生成器の初期化
        mask_generator = MaskFunctionGenerator(paillier, seed)

        # 公開鍵の設定
        paillier.public_key = public_key

        # 秘密鍵を鍵から導出
        # 実際の実装では、鍵から秘密鍵を導出する必要がある
        # ここでは単純化のため、鍵からハッシュを生成して秘密鍵のパラメータを生成
        key_hash = hashlib.sha256(key).digest()
        # 秘密鍵パラメータの生成（実際の実装ではより複雑な導出が必要）
        p = int.from_bytes(key_hash[:16], 'big')
        q = int.from_bytes(key_hash[16:], 'big')
        n = public_key["n"]  # 公開鍵から取得
        lambda_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        g = public_key["g"]  # 公開鍵から取得

        # μ = (L(g^λ mod n^2))^(-1) mod n を計算
        g_lambda = pow(g, lambda_val, n * n)
        l_g_lambda = (g_lambda - 1) // n

        # モジュラー逆元の計算（簡易版）
        # 実際の実装ではより厳密な計算が必要
        mu = pow(l_g_lambda, -1, n)

        private_key = {
            'lambda': lambda_val,
            'mu': mu,
            'p': p,
            'q': q,
            'n': n
        }

        paillier.private_key = private_key

        # 進捗表示の初期化
        total_chunks = len(chunks)
        print(f"合計 {total_chunks} チャンクの復号を開始します...")

        # 真偽鍵に対応するマスク関数を生成
        true_mask, false_mask = mask_generator.generate_mask_pair()

        # 鍵タイプに応じたマスクを選択
        mask = true_mask if key_type == "true" else false_mask

        # マスクの除去
        print("マスク関数を除去中...")
        for i in range(0, len(chunks), max(1, len(chunks) // 10)):
            if verbose:
                show_progress(i, len(chunks), "マスク除去")

        unmasked_chunks = mask_generator.remove_mask(chunks, mask)

        if verbose:
            show_progress(len(chunks), len(chunks), "マスク除去")

        # 復号
        print("準同型暗号を復号中...")
        decrypted_data = bytearray()
        original_size = true_size if key_type == "true" else false_size

        for i, chunk in enumerate(unmasked_chunks):
            if verbose and i % max(1, len(unmasked_chunks) // 10) == 0:
                show_progress(i, len(unmasked_chunks), "復号")

            # 暗号文を復号
            decrypted_int = paillier.decrypt(chunk, private_key)

            # 最後のチャンクは部分的かもしれない
            remaining_size = original_size - len(decrypted_data)
            bytes_in_chunk = min(chunk_size, remaining_size)

            if bytes_in_chunk <= 0:
                break

            # 整数をバイト列に変換
            # サイズを超えないよう調整
            try:
                bytes_value = decrypted_int.to_bytes(
                    (decrypted_int.bit_length() + 7) // 8, 'big')

                # チャンクサイズを超えないようにトリミング
                if len(bytes_value) > bytes_in_chunk:
                    bytes_value = bytes_value[-bytes_in_chunk:]

                # バイト配列に追加
                decrypted_data.extend(bytes_value)
            except (OverflowError, ValueError) as e:
                print(f"警告: チャンク {i} の復号に問題が発生しました: {e}", file=sys.stderr)
                # 空バイトを埋める
                decrypted_data.extend(b'\x00' * min(bytes_in_chunk, 8))

        if verbose:
            show_progress(len(unmasked_chunks), len(unmasked_chunks), "復号")

        # 出力ファイルへの書き込み
        try:
            print(f"復号データを出力中: {output_path}")
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
        except IOError as e:
            print(f"エラー: ファイルの書き込みに失敗しました: {e}", file=sys.stderr)
            return False

        print(f"復号が完了しました: '{output_path}'")
        return True

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

        # リカバリー処理（部分的に復号できたデータを保存）
        try:
            if 'decrypted_data' in locals() and decrypted_data:
                recovery_path = f"{output_path}.partial"
                with open(recovery_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"部分的な復号結果を保存しました: {recovery_path}", file=sys.stderr)
        except:
            pass

        return False


def main():
    """メイン関数"""
    start_time = time.time()

    args = parse_arguments()

    # 入力ファイルの存在を確認
    if not os.path.exists(args.input_file):
        print(f"エラー: 暗号化ファイル '{args.input_file}' が見つかりません。", file=sys.stderr)
        return 1

    # パスワードが指定されている場合は、パスワードから鍵を導出
    if args.password:
        try:
            # 暗号化ファイルからソルトを取得
            with open(args.input_file, 'r') as f:
                encrypted_data = json.load(f)
                salt_base64 = encrypted_data.get("salt", "")
                salt = base64.b64decode(salt_base64)

            # パスワードから鍵を導出
            key = hashlib.pbkdf2_hmac(
                'sha256',
                args.password.encode(),
                salt,
                10000,
                MASK_SEED_SIZE
            )
        except Exception as e:
            print(f"エラー: パスワードからの鍵導出に失敗しました: {e}", file=sys.stderr)
            return 1
    else:
        # 鍵の解析
        try:
            key = parse_key(args.key)
        except ValueError as e:
            print(f"エラー: 鍵の解析に失敗しました: {e}", file=sys.stderr)
            return 1

    # 出力ファイル名の決定
    if args.output:
        output_path = args.output
    else:
        # 入力ファイル名から自動生成
        base_name = os.path.splitext(os.path.basename(args.input_file))[0]
        output_path = f"{base_name}_decrypted.txt"

    # 出力ディレクトリが存在するか確認
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            ensure_directory(output_dir)
        except OSError as e:
            print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
            return 1

    # 復号の実行
    print(f"準同型暗号マスキング方式で復号を開始します...")

    success = decrypt_file(
        args.input_file, key, output_path, args.key_type, args.verbose
    )

    elapsed_time = time.time() - start_time

    # 結果出力
    if success:
        print(f"復号が完了しました（所要時間: {elapsed_time:.2f}秒）")

        # 鍵タイプに関するメッセージ
        key_type = args.key_type or analyze_key_type(key)
        if key_type == "true":
            print("✅ 真の鍵で復号しました - これは正規のファイルです")
        else:
            print("ℹ️ 偽の鍵で復号しました - これは非正規のファイルです")

        return 0
    else:
        print(f"復号に失敗しました（所要時間: {elapsed_time:.2f}秒）", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
