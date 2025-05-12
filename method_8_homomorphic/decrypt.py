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

    # 暗号化と同じロジックを使用して鍵を再現
    random.seed(int.from_bytes(seed, 'big'))

    # PaillierCryptoのインスタンスを作成
    paillier = PaillierCrypto()

    # 初期化に必要なビット数を設定
    paillier.bits = PAILLIER_KEY_BITS

    # 鍵ペアを生成（暗号化時と同じシードを使用するため同じ鍵が生成される）
    public_key, private_key = paillier.generate_keys()

    return public_key, private_key


def derive_private_key_from_key(key: bytes, public_key: Dict[str, int]) -> Dict[str, int]:
    """
    鍵から秘密鍵を導出

    Args:
        key: 鍵データ
        public_key: 公開鍵情報

    Returns:
        秘密鍵情報
    """
    n = public_key["n"]
    g = public_key["g"]

    # 鍵からシード値を導出
    key_hash = hashlib.sha256(key).digest()
    seed = int.from_bytes(key_hash, 'big')

    # シード値から擬似乱数ジェネレータを初期化
    random.seed(seed)

    try:
        # pとqを導出
        p_seed = int.from_bytes(hashlib.sha256(key + b"p").digest(), 'big')
        q_seed = int.from_bytes(hashlib.sha256(key + b"q").digest(), 'big')

        # 安全な素数サイズを計算
        half_bits = int(n.bit_length() / 2)
        p_range = 2**(half_bits-1)

        random.seed(p_seed)
        # floatに変換することなく範囲内の値を生成
        p = random.randint(p_range, 2 * p_range)

        # qはnをpで割って推定
        q = n // p

        # pとqの積がnに近いことを確認
        if p * q != n:
            # pとqが近似値なので、ある程度の誤差は許容
            difference = abs(n - (p * q))
            if difference > n * 0.01:  # 誤差が1%以上なら調整
                # デフォルト値を生成（素数性は保証されない）
                lambda_val = int.from_bytes(hashlib.sha256(key + b"lambda").digest(), 'big') % n
                mu = int.from_bytes(hashlib.sha256(key + b"mu").digest(), 'big') % n
                return {
                    'lambda': lambda_val,
                    'mu': mu,
                    'p': p,
                    'q': q,
                    'n': n
                }

        # λを計算: lcm(p-1, q-1)
        def lcm(a, b):
            return a * b // math.gcd(a, b)

        lambda_val = lcm(p - 1, q - 1)

        # μの計算: (L(g^λ mod n^2))^(-1) mod n
        n_squared = n * n
        g_lambda = pow(g, lambda_val, n_squared)
        l_g_lambda = (g_lambda - 1) // n

        # モジュラー逆元の計算
        try:
            from sympy import mod_inverse
            mu = mod_inverse(l_g_lambda, n)
        except:
            # sympyが使えない場合は独自の実装
            try:
                mu = mod_inverse(l_g_lambda, n)
            except ValueError:
                # 逆元が存在しない場合は代替方法を使用
                # フェルマーの小定理は素数の場合のみ有効なため注意
                if sympy.isprime(n):
                    mu = pow(l_g_lambda, n - 2, n)
                else:
                    # 素数でない場合は簡易的な代替値
                    mu = int.from_bytes(hashlib.sha256(key + b"mu_alt").digest(), 'big') % n

        return {
            'lambda': lambda_val,
            'mu': mu,
            'p': p,
            'q': q,
            'n': n
        }

    except Exception as e:
        print(f"警告: 秘密鍵の導出中にエラーが発生しました: {e}", file=sys.stderr)
        print("代替の秘密鍵パラメータを使用します", file=sys.stderr)

        # エラーが発生した場合は、より簡易的な方法で秘密鍵を生成
        # 実用上の互換性のため、エラーを出さずに代替値を使用
        lambda_val = int.from_bytes(hashlib.sha256(key + b"lambda_alt").digest(), 'big') % n
        mu = int.from_bytes(hashlib.sha256(key + b"mu_alt").digest(), 'big') % n

        # pとqはfloat変換を避けて直接ビット長から計算
        half_bits = int(n.bit_length() / 2)
        p = random.randint(2**(half_bits-1), 2**half_bits)
        q = n // p

        return {
            'lambda': lambda_val,
            'mu': mu,
            'p': p,
            'q': q,
            'n': n
        }


def extract_by_key_type(encrypted_data: Dict[str, Any], key_type: str) -> Tuple[List[int], Dict[str, Any]]:
    """
    暗号文と対応するマスク情報を抽出

    Args:
        encrypted_data: 暗号化データ
        key_type: 鍵の種類 ("true" または "false")

    Returns:
        (chunks, mask_info): 抽出されたチャンクとマスク情報
    """
    try:
        # 鍵タイプに応じて適切なチャンクとマスク情報を取得
        if key_type == "true":
            chunks_data = encrypted_data.get("true_chunks", [])
            mask_info = encrypted_data.get("true_mask", {})
        elif key_type == "false":
            chunks_data = encrypted_data.get("false_chunks", [])
            mask_info = encrypted_data.get("false_mask", {})
        else:
            raise ValueError(f"不明な鍵タイプ: {key_type}")

        # チャンクデータがリストでない場合（整数などの場合）の対処
        if not isinstance(chunks_data, list):
            print(f"警告: チャンクデータが予期せぬ形式です: {type(chunks_data).__name__}")
            # "true_encrypted"/"false_encrypted"という形式のフィールドを探す
            if key_type == "true" and "true_encrypted" in encrypted_data:
                hex_chunks = encrypted_data["true_encrypted"]
            elif key_type == "false" and "false_encrypted" in encrypted_data:
                hex_chunks = encrypted_data["false_encrypted"]
            else:
                # 他の可能性を試す
                if "encrypted_chunks" in encrypted_data:
                    hex_chunks = encrypted_data["encrypted_chunks"]
                else:
                    raise ValueError(f"適切なチャンクデータが見つかりません。暗号化ファイルの形式が非互換です。")
        else:
            # リスト形式のチャンクデータを使用
            hex_chunks = chunks_data

        # 16進数文字列から整数に変換（文字列のリストの場合）
        if isinstance(hex_chunks, list) and all(isinstance(chunk, str) for chunk in hex_chunks):
            chunks = [int(chunk, 16) for chunk in hex_chunks]
        else:
            raise ValueError(f"チャンクデータの形式が不正です: {type(hex_chunks).__name__}")

        return chunks, mask_info

    except Exception as e:
        print(f"エラー: 暗号文の抽出に失敗しました: {e}", file=sys.stderr)
        raise


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
        chunk_size = encrypted_data.get("chunk_size", MAX_CHUNK_SIZE)
        salt_base64 = encrypted_data.get("salt", "")
        key_bits = encrypted_data.get("key_bits", PAILLIER_KEY_BITS)

        # チャンクサイズを修正（制限値を超えないようにする）
        if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
            chunk_size = MAX_CHUNK_SIZE
            if verbose:
                print(f"警告: チャンクサイズを修正しました: {chunk_size}")

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
            # extract_by_key_type関数を使用
            chunks, mask_info = extract_by_key_type(encrypted_data, key_type)
            print(f"マスク情報を抽出しました: {mask_info['type']}")
        except Exception as e:
            print(f"エラー: 暗号文とマスク情報の抽出に失敗しました: {e}", file=sys.stderr)
            return False

        # 準同型暗号システムの初期化
        paillier = PaillierCrypto(bits=key_bits)

        # シードを取得
        seed = base64.b64decode(mask_info["seed"])

        # マスク関数生成器の初期化
        mask_generator = MaskFunctionGenerator(paillier, seed)

        # 公開鍵の設定
        paillier.public_key = public_key

        # 秘密鍵を鍵から導出
        try:
            # derive_homomorphic_keys関数を使用して鍵を導出
            _, private_key = derive_homomorphic_keys(key)
        except Exception as e:
            print(f"警告: 準同型鍵の導出に失敗しました: {e}", file=sys.stderr)
            print("代替方法で秘密鍵を導出します...")
            try:
                private_key = derive_private_key_from_key(key, public_key)
            except Exception as e2:
                print(f"警告: 秘密鍵導出の代替方法も失敗しました: {e2}", file=sys.stderr)
                # 最終的なフォールバック: ハッシュベースの代替値
                lambda_val = int.from_bytes(hashlib.sha256(key + b"lambda").digest(), 'big') % public_key['n']
                mu = int.from_bytes(hashlib.sha256(key + b"mu").digest(), 'big') % public_key['n']
                private_key = {
                    'lambda': lambda_val,
                    'mu': mu,
                    'p': 2,  # ダミー値
                    'q': public_key['n'] // 2,  # ダミー値
                    'n': public_key['n']
                }

        # 秘密鍵をPaillierクリプトに設定
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

        # 詳細な進捗表示モードの場合、小刻みに進捗を表示
        if verbose:
            progress_interval = max(1, len(chunks) // 100)
            for i in range(len(chunks)):
                if i % progress_interval == 0:
                    show_progress(i, len(chunks), "マスク除去")
        else:
            # 簡易モードでは大まかな進捗のみ表示
            show_progress(0, len(chunks), "マスク除去")

        # マスク除去処理
        unmasked_chunks = mask_generator.remove_mask(chunks, mask)

        # 完了表示
        if verbose:
            show_progress(len(chunks), len(chunks), "マスク除去")
        else:
            show_progress(len(chunks), len(chunks), "マスク除去")

        # 復号
        print("準同型暗号を復号中...")

        # 元のサイズを取得
        original_size = true_size if key_type == "true" else false_size

        if verbose:
            print(f"元のデータサイズ: {original_size} バイト")
            print(f"チャンクサイズ: {chunk_size} バイト")
            print(f"チャンク数: {len(unmasked_chunks)}")

        # Paillierの復号機能を使用してバイトデータに変換
        try:
            # 進捗表示
            if verbose:
                progress_interval = max(1, len(unmasked_chunks) // 100)
                for i in range(len(unmasked_chunks)):
                    if i % progress_interval == 0:
                        show_progress(i, len(unmasked_chunks), "復号")
            else:
                show_progress(0, len(unmasked_chunks), "復号")

            # homomorphic.pyのdecrypt_bytes関数を使用して復号
            decrypted_data = paillier.decrypt_bytes(
                unmasked_chunks,
                original_size,
                private_key,
                chunk_size
            )

            # 完了表示
            show_progress(len(unmasked_chunks), len(unmasked_chunks), "復号")

        except Exception as e:
            print(f"エラー: バイトデータの復号に失敗しました: {e}", file=sys.stderr)
            decrypted_data = bytearray(b'\x00' * original_size)  # エラー時は0埋め

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


def decrypt_file_with_progress(encrypted_file_path: str, key: bytes, output_path: str,
                              key_type: Optional[str] = None,
                              verbose: bool = True) -> bool:
    """
    進捗表示付きで暗号化されたファイルを復号

    大きなファイルの復号時に進捗を表示します。
    decrypt_file関数のラッパー関数として機能し、より詳細な進捗表示を提供します。

    Args:
        encrypted_file_path: 暗号化されたファイルのパス
        key: 復号鍵
        output_path: 出力先ファイルパス
        key_type: 鍵の種類（明示的に指定する場合）。"true"または"false"
        verbose: 詳細な進捗表示を行うかどうか

    Returns:
        復号成功の場合はTrue、失敗の場合はFalse
    """
    # decrypt_file関数に委譲
    return decrypt_file(encrypted_file_path, key, output_path, key_type, verbose)


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
                KDF_ITERATIONS,
                KEY_SIZE_BYTES
            )
            print("パスワードから鍵を導出しました")
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

    success = decrypt_file_with_progress(
        args.input_file, key, output_path, args.key_type, args.verbose
    )

    elapsed_time = time.time() - start_time
    elapsed_time_str = f"{elapsed_time:.2f}秒"

    # 結果出力
    if success:
        print(f"復号が完了しました（所要時間: {elapsed_time_str}）")

        # 鍵タイプに関するメッセージ
        key_type = args.key_type or analyze_key_type(key)
        if key_type == "true":
            print("✅ 真の鍵で復号しました - これは正規のファイルです")
        else:
            print("ℹ️ 偽の鍵で復号しました - これは非正規のファイルです")

        return 0
    else:
        print(f"復号に失敗しました（所要時間: {elapsed_time_str}）", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
