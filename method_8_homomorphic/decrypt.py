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
import secrets
import sympy
import string
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
    MAX_CHUNK_SIZE,
    KDF_ITERATIONS
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

    parser.add_argument(
        '--force-binary',
        action='store_true',
        help='復号結果を強制的にバイナリとして扱う'
    )

    parser.add_argument(
        '--force-text',
        action='store_true',
        help='復号結果を強制的にテキストとして扱う'
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
                key_data = f.read()
                if len(key_data) > 0:
                    # 鍵長を調整
                    if len(key_data) < KEY_SIZE_BYTES:
                        key_data = key_data.ljust(KEY_SIZE_BYTES, b'\0')
                    elif len(key_data) > KEY_SIZE_BYTES:
                        key_data = key_data[:KEY_SIZE_BYTES]
                    return key_data
        except Exception as e:
            print(f"警告: ファイルからの鍵読み込みに失敗しました: {e}", file=sys.stderr)
            # ファイルの読み込みに失敗した場合は次の方法を試す

    # Base64形式
    try:
        key_data = base64.b64decode(key_input)
        # 鍵長を調整
        if len(key_data) < KEY_SIZE_BYTES:
            key_data = key_data.ljust(KEY_SIZE_BYTES, b'\0')
        elif len(key_data) > KEY_SIZE_BYTES:
            key_data = key_data[:KEY_SIZE_BYTES]
        return key_data
    except Exception as e:
        print(f"警告: Base64からの鍵変換に失敗しました: {e}", file=sys.stderr)
        # Base64デコードに失敗した場合は次の方法を試す

    # 16進数形式
    try:
        if key_input.startswith('0x'):
            key_input = key_input[2:]
        key_data = binascii.unhexlify(key_input)
        # 鍵長を調整
        if len(key_data) < KEY_SIZE_BYTES:
            key_data = key_data.ljust(KEY_SIZE_BYTES, b'\0')
        elif len(key_data) > KEY_SIZE_BYTES:
            key_data = key_data[:KEY_SIZE_BYTES]
        return key_data
    except Exception as e:
        print(f"警告: 16進数からの鍵変換に失敗しました: {e}", file=sys.stderr)
        # 16進数変換に失敗した場合は次の方法を試す

    # その他の形式（パスワードとして使用）
    try:
        # パスワードとしてハッシュ化して鍵に変換
        return hashlib.sha256(key_input.encode()).digest()
    except Exception as e:
        raise ValueError(f"サポートされていない鍵形式です: {e}")


def ensure_directory(directory: str) -> None:
    """
    ディレクトリの存在を確認し、なければ作成

    Args:
        directory: 確認するディレクトリパス
    """
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        print(f"ディレクトリを作成しました: {directory}")


def mod_inverse(a: int, m: int) -> int:
    """
    モジュラー逆元を計算: a^(-1) mod m

    拡張ユークリッドアルゴリズムを使用（非再帰的実装）

    Args:
        a: 逆元を求める数
        m: 法

    Returns:
        aのモジュラー逆元

    Raises:
        ValueError: 逆元が存在しない場合
    """
    if m == 0:
        raise ValueError("法が0であってはなりません")

    if m == 1:
        return 0

    # aとmの最大公約数が1でなければ逆元は存在しない
    if math.gcd(a, m) != 1:
        raise ValueError(f"{a}と{m}は互いに素ではないため、逆元が存在しません")

    # 非再帰的な拡張ユークリッドアルゴリズム
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # 逆元の計算
    # old_s < 0 の場合は法に対して正にする
    if old_s < 0:
        old_s += m

    return old_s


def derive_homomorphic_keys(master_key: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    マスター鍵から準同型暗号用の鍵ペアを導出

    暗号化時と同じ方法で鍵を導出する必要があります。

    Args:
        master_key: マスター鍵

    Returns:
        (public_key, private_key): 公開鍵と秘密鍵
    """
    # マスター鍵からシード値を生成
    seed = hashlib.sha256(master_key).digest()
    seed_int = int.from_bytes(seed, 'big')

    # 暗号化と同じロジックを使用して鍵を再現
    random.seed(seed_int)

    # PaillierCryptoのインスタンスを作成し、同じシード値で初期化
    paillier = PaillierCrypto()

    # 暗号化時と同じビット数を使用
    paillier.bits = PAILLIER_KEY_BITS

    try:
        # 鍵ペアを生成（暗号化時と同じシードを使用するため同じ鍵が生成される）
        public_key, private_key = paillier.generate_keys()
        return public_key, private_key
    except Exception as e:
        print(f"鍵ペア生成中にエラーが発生しました: {e}", file=sys.stderr)
        # ランダム生成を一旦リセットしてから再試行
        random.seed(seed_int)
        p = sympy.randprime(2**(PAILLIER_KEY_BITS//2-1), 2**(PAILLIER_KEY_BITS//2))
        q = sympy.randprime(2**(PAILLIER_KEY_BITS//2-1), 2**(PAILLIER_KEY_BITS//2))

        n = p * q
        lambda_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        g = n + 1

        try:
            # L(g^λ mod n^2) の逆元を計算
            n_squared = n * n
            g_lambda = pow(g, lambda_val, n_squared)
            l_g_lambda = (g_lambda - 1) // n
            mu = mod_inverse(l_g_lambda, n)
        except Exception as e2:
            print(f"μの計算に失敗しました: {e2}", file=sys.stderr)
            # 代替手段として単純な値を使用
            mu = 1

        public_key = {'n': n, 'g': g}
        private_key = {'lambda': lambda_val, 'mu': mu, 'p': p, 'q': q, 'n': n}

        return public_key, private_key


def is_text_data(data: bytes, threshold: float = 0.5) -> bool:
    """
    データがテキストかバイナリかを判定する

    Args:
        data: 判定するバイトデータ
        threshold: テキストと判断する可読文字の割合の閾値 (0.0-1.0)

    Returns:
        テキストの場合はTrue、バイナリの場合はFalse
    """
    if not data:
        return False

    # 表示可能文字と空白の割合を直接計算
    printable_count = sum(1 for b in data if b in range(32, 127) or b in (9, 10, 13))  # タブ、改行、復帰も含む
    text_ratio = printable_count / len(data)

    # 閾値を超えていればテキストと判断
    if text_ratio >= threshold:
        # UTF-8としてデコードを試みる
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            # 他のエンコーディングを試す
            for encoding in ['utf-16', 'latin-1', 'shift-jis', 'euc-jp']:
                try:
                    data.decode(encoding)
                    return True
                except (UnicodeDecodeError, LookupError):
                    continue

    return False


def try_decode_text(data: bytes) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    バイトデータをさまざまなエンコーディングで復号化を試みる

    Args:
        data: デコードするバイトデータ

    Returns:
        (成功したかどうか, デコードされたテキスト, 使用したエンコーディング)
    """
    if not data:
        return False, None, None

    # よく使われるエンコーディング順に試す
    encodings = ['utf-8', 'latin-1', 'utf-16', 'shift-jis', 'euc-jp']

    for encoding in encodings:
        try:
            text = data.decode(encoding)
            return True, text, encoding
        except (UnicodeDecodeError, LookupError):
            continue

    return False, None, None


def decrypt_file_with_progress(encrypted_file_path: str, key: bytes, output_path: str,
                              key_type: Optional[str] = None,
                              verbose: bool = True,
                              force_binary: bool = False,
                              force_text: bool = False) -> bool:
    """
    進捗表示付きで暗号化されたファイルを復号

    Args:
        encrypted_file_path: 暗号化されたファイルのパス
        key: 復号鍵
        output_path: 出力先ファイルパス
        key_type: 鍵の種類（明示的に指定する場合）。"true"または"false"
        verbose: 詳細な出力を表示するかどうか
        force_binary: 強制的にバイナリとして扱うかどうか
        force_text: 強制的にテキストとして扱うかどうか

    Returns:
        復号成功の場合はTrue、失敗の場合はFalse
    """
    try:
        # 進捗表示関数
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

        # 鍵の解析と種別判定
        if key_type is None:
            # 鍵解析モジュールを使用して鍵の種類を判定
            key_type = analyze_key_type(key)
            print(f"鍵を解析しました: {key_type}鍵として識別されました")
        else:
            print(f"明示的に指定された鍵タイプを使用: {key_type}")

        # 公開鍵情報の取得
        public_key_str = encrypted_data.get("public_key", {})
        if not public_key_str:
            print(f"エラー: 公開鍵情報が見つかりません", file=sys.stderr)
            return False

        # 公開鍵を整数に変換
        public_key = {
            "n": int(public_key_str["n"]),
            "g": int(public_key_str["g"])
        }

        # オリジナルサイズとチャンクサイズの取得
        # ファイル形式に応じてサイズ情報を取得
        true_size = encrypted_data.get("true_size", 0)
        false_size = encrypted_data.get("false_size", 0)
        # 鍵タイプに応じて適切なサイズを選択
        original_size = true_size if key_type == "true" else false_size

        chunk_size = encrypted_data.get("chunk_size", MAX_CHUNK_SIZE)

        if verbose:
            print(f"元のファイルサイズ: {original_size} バイト")
            print(f"チャンクサイズ: {chunk_size} バイト")

        # 暗号文とマスク情報の抽出
        print("暗号文とマスク情報を抽出中...")
        chunks, mask_info = extract_by_key_type(encrypted_data, key_type)
        total_chunks = len(chunks)

        if verbose:
            print(f"チャンク数: {total_chunks}")
            print(f"マスク情報: {mask_info.get('type', 'unknown')}")

        # 準同型暗号システムの初期化
        print("準同型暗号システムを初期化中...")
        paillier = PaillierCrypto()

        # 鍵の導出と設定
        print("鍵データから秘密鍵を導出中...")
        _, private_key = derive_homomorphic_keys(key)
        paillier.public_key = public_key
        paillier.private_key = private_key

        # マスク生成器の初期化
        print("マスク生成器を初期化中...")
        seed = base64.b64decode(mask_info.get("seed", ""))
        mask_generator = MaskFunctionGenerator(paillier, seed)

        # マスク関数のペアを生成
        true_mask, false_mask = mask_generator.generate_mask_pair()

        # 鍵タイプに応じたマスクを選択
        mask = true_mask if key_type == "true" else false_mask

        # マスクの除去
        print("マスク関数を除去中...")
        unmasked_chunks = []
        for i, chunk in enumerate(chunks):
            if i % 10 == 0 or i == len(chunks) - 1:
                show_progress(i, total_chunks, "マスク除去中")
            unmasked_chunk = mask_generator.remove_mask([chunk], mask)[0]
            unmasked_chunks.append(unmasked_chunk)

        show_progress(total_chunks, total_chunks, "マスク除去完了")

        # 復号
        print("\n復号中...")
        decrypted_data = bytearray()
        for i, chunk in enumerate(unmasked_chunks):
            if i % 10 == 0 or i == len(unmasked_chunks) - 1:
                show_progress(i, total_chunks, "復号中")

            try:
                # チャンクを復号
                decrypted_value = paillier.decrypt(chunk, private_key)

                # 整数をバイト列に変換
                byte_length = (decrypted_value.bit_length() + 7) // 8
                chunk_bytes = decrypted_value.to_bytes(byte_length, 'big')

                # チャンクサイズを超えないように切り詰め
                if len(chunk_bytes) > chunk_size:
                    chunk_bytes = chunk_bytes[-chunk_size:]

                decrypted_data.extend(chunk_bytes)
            except Exception as e:
                print(f"\nエラー: チャンク {i} の復号中に問題が発生しました: {e}", file=sys.stderr)
                if verbose:
                    import traceback
                    traceback.print_exc()

        show_progress(total_chunks, total_chunks, "復号完了")

        # 元のサイズに合わせる
        if original_size > 0 and len(decrypted_data) > original_size:
            decrypted_data = decrypted_data[:original_size]

        # バイトデータをテキストかバイナリとして判断して保存
        is_text = False
        if force_binary:
            is_text = False
            print("\nバイナリデータとして処理します（force-binary指定）")
        elif force_text:
            is_text = True
            print("\nテキストデータとして処理します（force-text指定）")
        else:
            is_text = is_text_data(decrypted_data)
            print(f"\nデータタイプ自動判定: {'テキスト' if is_text else 'バイナリ'}")

        # 出力ファイルへの書き込み
        try:
            if is_text:
                # テキストとして保存
                success, decoded_text, encoding = try_decode_text(decrypted_data)
                if success:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(decoded_text)
                    print(f"テキストファイルとして保存しました: {output_path} (検出されたエンコーディング: {encoding})")
                else:
                    print(f"警告: テキストとして判定されましたが、デコードできないためバイナリとして保存します")
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"バイナリファイルとして保存しました: {output_path}")
            else:
                # バイナリとして保存
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"バイナリファイルとして保存しました: {output_path}")

            return True

        except IOError as e:
            print(f"エラー: ファイルの書き込みに失敗しました: {e}", file=sys.stderr)
            return False

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def main():
    """
    メイン関数
    """
    # コマンドライン引数の解析
    args = parse_arguments()

    # 入力ファイルの存在確認
    if not os.path.exists(args.input_file):
        print(f"エラー: 暗号化ファイル '{args.input_file}' が見つかりません", file=sys.stderr)
        return 1

    try:
        # 鍵の解析
        if args.password:
            # パスワードから鍵を導出
            print(f"パスワードから鍵を導出します...")
            key = hashlib.sha256(args.password.encode()).digest()
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

        # 出力ディレクトリの存在確認
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"ディレクトリを作成しました: {output_dir}")
            except OSError as e:
                print(f"エラー: 出力ディレクトリの作成に失敗しました: {e}", file=sys.stderr)
                return 1

        # 復号の実行
        print(f"準同型暗号マスキング方式で復号を開始します...")
        start_time = time.time()

        success = decrypt_file_with_progress(
            args.input_file,
            key,
            output_path,
            args.key_type,
            args.verbose,
            args.force_binary,
            args.force_text
        )

        elapsed_time = time.time() - start_time

        if success:
            print(f"復号が完了しました（所要時間: {elapsed_time:.2f}秒）")
            return 0
        else:
            print(f"復号に失敗しました（所要時間: {elapsed_time:.2f}秒）", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"エラー: 予期しない問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
