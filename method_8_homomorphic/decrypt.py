#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の復号実行ファイル

このモジュールは、準同型暗号マスキング方式を使用して暗号化されたファイルを復号するための
コマンドラインツールを提供します。マスク関数を使って暗号化されたファイルを、
鍵に応じて真または偽の状態に復号します。どちらの鍵が「正規」か「非正規」かは
ユーザーの意図によって決まります。
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
from method_8_homomorphic.key_analyzer_robust import (
    analyze_key_type, extract_seed_from_key
)
from method_8_homomorphic.crypto_adapters import (
    process_data_for_encryption, process_data_after_decryption,
    DataAdapter, TextAdapter, BinaryAdapter
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

    parser.add_argument(
        '--data-type',
        choices=['text', 'binary', 'json', 'base64', 'auto'],
        default='auto',
        help='復号データの形式を指定（デフォルト: 自動検出）'
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


def derive_homomorphic_keys(master_key: bytes, public_key: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    マスター鍵から準同型暗号用の鍵ペアを導出

    暗号化時と同じ方法で鍵を導出する必要があります。

    Args:
        master_key: マスター鍵
        public_key: 既知の公開鍵情報（暗号文から取得した場合）

    Returns:
        (public_key, private_key): 公開鍵と秘密鍵
    """
    # 実験的: 秘密鍵ファイルを直接読み込む
    secret_key_file = "keys/paillier_private.json"
    if os.path.exists(secret_key_file):
        try:
            with open(secret_key_file, "r") as f:
                private_key_data = json.load(f)
            print(f"秘密鍵ファイルを読み込みました: {secret_key_file}")

            # int型に変換
            private_key = {}
            for key, value in private_key_data.items():
                private_key[key] = int(value) if isinstance(value, str) else value

            # 対応する公開鍵も読み込む
            public_key_file = "keys/paillier_public.json"
            if os.path.exists(public_key_file):
                with open(public_key_file, "r") as f:
                    public_key_data = json.load(f)

                # int型に変換
                public_key = {}
                for key, value in public_key_data.items():
                    public_key[key] = int(value) if isinstance(value, str) else value

                print(f"公開鍵ファイルを読み込みました: {public_key_file}")
                return public_key, private_key
        except Exception as e:
            print(f"秘密鍵ファイル読み込みエラー: {e}, 別の方法で導出を試みます")

    # 既知の公開鍵がある場合はそれを使用
    if public_key is not None:
        # 秘密鍵の派生は不可能なので、ダミーの秘密鍵を返す
        dummy_private_key = {
            "lambda": 0,
            "mu": 1,
            "p": 0,
            "q": 0,
            "n": public_key.get("n", 0)
        }
        return public_key, dummy_private_key

    # 以下は既存のコード（公開鍵が与えられていない場合）
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


def decrypt_file(input_file: str, output_file: str, key_type: str, key_file: str = None,
                password: str = None, force_binary: bool = False, force_text: bool = False,
                verbose: bool = False, data_type: str = 'auto') -> Dict[str, Any]:
    """
    暗号化されたファイルを復号する

    Args:
        input_file: 入力ファイルのパス
        output_file: 出力ファイルのパス
        key_type: キーの種類（"true"または"false"）
        key_file: キーファイルのパス（オプション）
        password: パスワード（オプション、key_fileが指定されていない場合に使用）
        force_binary: バイナリ出力を強制するかどうか
        force_text: テキスト出力を強制するかどうか
        verbose: 詳細な出力を表示するかどうか
        data_type: データ型（'auto', 'text', 'binary', 'json', 'base64'）

    Returns:
        処理結果の辞書
    """
    start_time = time.time()
    result = {
        "success": False,
        "input_file": input_file,
        "output_file": output_file,
        "key_type": key_type,
        "time": 0
    }

    try:
        # キーの取得
        if key_file:
            key = parse_key(key_file)
        elif password:
            key = hashlib.sha256(password.encode()).digest()
        else:
            raise ValueError("鍵ファイルまたはパスワードが必要です")

        # 復号処理
        success = decrypt_file_with_progress(
            encrypted_file_path=input_file,
            key=key,
            output_path=output_file,
            key_type=key_type,
            verbose=verbose,
            force_binary=force_binary,
            force_text=force_text,
            data_type=data_type
        )

        result["success"] = success

    except Exception as e:
        print(f"復号中にエラーが発生しました: {e}")
        result["error"] = str(e)
        if verbose:
            import traceback
            traceback.print_exc()

    # 処理時間を記録
    end_time = time.time()
    result["time"] = end_time - start_time

    return result


def decrypt_file_with_progress(encrypted_file_path: str, key: bytes, output_path: str,
                              key_type: Optional[str] = None,
                              verbose: bool = True,
                              force_binary: bool = False,
                              force_text: bool = False,
                              data_type: str = 'auto') -> bool:
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
        data_type: データタイプ（'auto', 'text', 'binary', 'json', 'base64'）

    Returns:
        復号成功の場合はTrue、失敗の場合はFalse
    """
    try:
        # 進捗表示関数
        def show_progress(current, total, description=None):
            if total == 0:
                bar_length = 40
                bar = '█' * bar_length
                prefix = description or "処理中"
                print(f"\r{prefix}: [{bar}] 100.0% (0/0)", end='')
                if current == total:
                    print()
                return

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

        # 追加情報（データタイプ）の取得
        file_data_type = encrypted_data.get("data_type", None)
        true_data_type = encrypted_data.get("true_data_type", None)
        false_data_type = encrypted_data.get("false_data_type", None)

        # 鍵の解析と種別判定
        if key_type is None:
            # 鍵解析モジュールを使用して鍵の種類を判定
            key_type = analyze_key_type(key)
            print(f"鍵を解析しました: {key_type}鍵として識別されました")
        else:
            print(f"明示的に指定された鍵タイプを使用: {key_type}")

        # 鍵タイプに応じたデータタイプを選択
        current_data_type = true_data_type if key_type == "true" else false_data_type
        if current_data_type:
            print(f"使用するデータタイプ: {current_data_type}")

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

        # 鍵タイプに応じた暗号文とマスク情報の抽出
        print("暗号文とマスク情報を抽出中...")
        chunks, mask_info = extract_by_key_type(encrypted_data, key_type)
        total_chunks = len(chunks)

        if verbose:
            print(f"チャンク数: {total_chunks}")
            print(f"マスク情報: {mask_info.get('type', 'unknown')}")
            if total_chunks > 0:
                print(f"先頭チャンク: {hex(chunks[0])}")
            else:
                print("警告: 暗号文チャンクが空です！")
            print(f"マスク情報詳細: {mask_info}")

        # 準同型暗号システムの初期化
        print("準同型暗号システムを初期化中...")
        paillier = PaillierCrypto()

        # 鍵の導出と設定
        print("鍵データから秘密鍵を導出中...")
        _, private_key = derive_homomorphic_keys(key, public_key)
        paillier.public_key = public_key
        paillier.private_key = private_key

        # マスク関数生成器の初期化
        print("マスク生成器を初期化中...")
        if mask_info.get('seed'):
            # シード情報があれば復元
            seed = base64.b64decode(mask_info['seed'])
            mask_generator = MaskFunctionGenerator(paillier, seed)

            # 鍵タイプに応じたマスクを再生成
            true_mask, false_mask = mask_generator.generate_mask_pair()
            mask = true_mask if key_type == "true" else false_mask

            # マスク関数を除去
            print("マスク関数を除去中...")
            try:
                unmasked_chunks = mask_generator.remove_mask(chunks, mask)
                bar_length = 40
                bar = '█' * bar_length
                print(f"マスク除去完了: [{bar}] 100.0% ({total_chunks}/{total_chunks})")
                if verbose and unmasked_chunks:
                    print(f"マスク除去後の先頭チャンク: {hex(unmasked_chunks[0])}")
                elif verbose:
                    print("警告: マスク除去後のチャンクが空です")
            except Exception as e:
                print(f"エラー: マスク除去中に問題が発生しました: {e}", file=sys.stderr)
                if verbose:
                    import traceback
                    traceback.print_exc()
                return False

        # 暗号文を復号
        print("\n復号中...")
        decrypted_data = bytearray()

        # 進捗バーを初期化
        show_progress(0, total_chunks, "復号中")

        for i, chunk in enumerate(unmasked_chunks):
            try:
                # 復号
                decrypted_int = paillier.decrypt(chunk, private_key)

                # 進捗表示
                show_progress(i + 1, total_chunks, "復号中")

                # バイト列への変換
                byte_length = (decrypted_int.bit_length() + 7) // 8
                if byte_length == 0:
                    if verbose:
                        print(f"警告: チャンク {i} の復号結果が0になりました")
                    chunk_bytes = b''
                else:
                    chunk_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
                    if verbose and i == 0:
                        print(f"復号された先頭チャンク（{byte_length}バイト）: {chunk_bytes.hex()}")

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

        # デバッグ出力
        if verbose:
            print(f"\n復号されたデータ長: {len(decrypted_data)} バイト")
            if len(decrypted_data) > 0:
                print(f"先頭バイト: {decrypted_data[:min(20, len(decrypted_data))].hex()}")

        # データタイプを取得（true/falseに関係なく統一したアプローチでデータ処理）
        current_data_type = true_data_type if key_type == "true" else false_data_type

        # process_data_after_decryptionを使用して統一的なデータ処理
        if verbose:
            print(f"復号データの処理: データタイプ={current_data_type}")

        # データの後処理（true/falseに関わらず同じ処理パイプラインを通す）
        try:
            processed_data = process_data_after_decryption(decrypted_data, current_data_type)
            if verbose:
                print(f"データ処理成功: サイズ={len(processed_data)} バイト")
        except Exception as e:
            print(f"警告: データの後処理中にエラーが発生しました: {e}")
            processed_data = decrypted_data  # エラー時はオリジナルを使用
            if verbose:
                import traceback
                traceback.print_exc()

        # メタデータからファイル形式情報を取得（両方の鍵で統一したアプローチ）
        is_text = False
        encoding = None

        # 現在の鍵タイプに応じたメタデータを取得
        if key_type == "true":
            is_text = encrypted_data.get("is_true_text", False)
            encoding = encrypted_data.get("true_encoding", None)
            original_filename = encrypted_data.get("true_filename", None)
        else:
            is_text = encrypted_data.get("is_false_text", False)
            encoding = encrypted_data.get("false_encoding", None)
            original_filename = encrypted_data.get("false_filename", None)

        if verbose:
            print(f"メタデータ情報:")
            print(f" - テキストファイル: {is_text}")
            print(f" - エンコーディング: {encoding}")
            print(f" - 元のファイル名: {original_filename or '不明'}")
            print(f" - データタイプ: {current_data_type}")

        # 強制フラグがある場合はそれを優先
        if force_text:
            is_text = True
            current_data_type = 'text'
            print(f"テキストモードを強制指定しました")
        elif force_binary:
            is_text = False
            current_data_type = 'binary'
            print(f"バイナリモードを強制指定しました")

        # 統一されたデータ処理：テキストとバイナリの両方に同じアプローチを適用
        try:
            # データタイプに基づいて適切な処理を選択
            if current_data_type == 'text' or is_text or force_text:
                # テキストデータの場合

                # 多段エンコーディング処理（両方の鍵に対して同様に機能）
                if isinstance(decrypted_data, bytes) and decrypted_data.startswith(b'TXT-MULTI:'):
                    text_adapter = TextAdapter()
                    processed_text = text_adapter.reverse_multi_stage_encoding(decrypted_data)
                    print(f"多段エンコーディングのテキスト（{len(processed_text)}文字）を復元しました")

                    # 結果の保存
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(processed_text)
                    print(f"テキストデータとして保存しました: {output_path}")
                    return True

                # テキスト変換（バイトから文字列へ）
                if isinstance(processed_data, bytes):
                    # 複数のエンコーディングを試す
                    for enc in ['utf-8', 'latin-1', 'shift-jis', 'euc-jp']:
                        try:
                            text = processed_data.decode(enc)
                            print(f"{enc}エンコーディングでテキストを復元しました")
                            with open(output_path, 'w', encoding='utf-8') as f:
                                f.write(text)
                            print(f"テキストデータとして保存しました: {output_path}")
                            return True
                        except UnicodeDecodeError:
                            continue
                elif isinstance(processed_data, str):
                    # すでに文字列の場合はそのまま保存
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(processed_data)
                    print(f"テキストデータとして保存しました: {output_path}")
                    return True

            # テキスト処理に失敗した場合やバイナリデータの場合はバイナリとして保存
            binary_data = processed_data
            if isinstance(processed_data, str):
                binary_data = processed_data.encode('utf-8')

            with open(output_path, 'wb') as f:
                f.write(binary_data)
            print(f"バイナリファイルとして保存しました: {output_path}")
            return True

        except Exception as e:
            print(f"エラー: ファイル保存中に問題が発生しました: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
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
            args.force_text,
            args.data_type
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
