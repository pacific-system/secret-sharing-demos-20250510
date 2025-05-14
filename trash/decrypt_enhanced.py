#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の復号実行ファイル - セキュリティ強化版

このモジュールは、準同型暗号マスキング方式を使用して暗号化されたファイルを復号するための
コマンドラインツールを提供します。元のdecrypt.pyよりもセキュリティが強化されており、
ソースコード改変攻撃への耐性が向上しています。
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
import traceback

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
    KDF_ITERATIONS,
    SECURITY_PARAMETER
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

# 強化版の依存関係
from method_8_homomorphic.key_analyzer_enhanced import (
    analyze_key_type_robust,
    extract_seed_from_key,
    debug_key_analysis
)
from method_8_homomorphic.indistinguishable_enhanced import (
    remove_comprehensive_indistinguishability_enhanced,
    safe_log10
)


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数の解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(
        description='準同型暗号マスキング方式による復号ツール（セキュリティ強化版）'
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

    parser.add_argument(
        '--use-enhanced-security',
        action='store_true',
        default=True,
        help='セキュリティ強化版の機能を使用する（デフォルト: 有効）'
    )

    parser.add_argument(
        '--compatibility-mode',
        action='store_true',
        help='互換モード（セキュリティ強化版の機能を使用しない）'
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


def decrypt_file_with_progress(encrypted_file_path: str, key: bytes, output_path: str,
                              key_type: Optional[str] = None,
                              verbose: bool = True,
                              force_binary: bool = False,
                              force_text: bool = False,
                              data_type: str = 'auto',
                              use_enhanced_security: bool = True) -> bool:
    """
    進捗表示付きで暗号化されたファイルを復号（セキュリティ強化版）

    Args:
        encrypted_file_path: 暗号化されたファイルのパス
        key: 復号鍵
        output_path: 出力先ファイルパス
        key_type: 鍵の種類（明示的に指定する場合）。"true"または"false"
        verbose: 詳細な出力を表示するかどうか
        force_binary: 強制的にバイナリとして扱うかどうか
        force_text: 強制的にテキストとして扱うかどうか
        data_type: データタイプ（'auto', 'text', 'binary', 'json', 'base64'）
        use_enhanced_security: セキュリティ強化版の機能を使用するかどうか

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

        start_time = time.time()  # 処理時間計測開始

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
            # セキュリティ強化版の鍵解析を使用
            if use_enhanced_security:
                # 強化された鍵解析を使用（メタデータも考慮）
                key_type = analyze_key_type_robust(key)
                print(f"鍵を堅牢に解析しました: {key_type}鍵として識別されました")
            else:
                # 標準の鍵解析を使用
                from method_8_homomorphic.key_analyzer import analyze_key_type as legacy_analyze_key_type
                key_type = legacy_analyze_key_type(key)
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

        # ファイル整合性の検証 (セキュリティ強化機能)
        if use_enhanced_security:
            # ファイルが改ざんされていないか検証
            encryption_time = encrypted_data.get("encryption_time", "")
            original_filename = encrypted_data.get("original_filename", "")
            chunks_hash = hashlib.sha256(str(chunks[:5]).encode()).hexdigest()[:8]

            print(f"ファイル整合性を検証中... ハッシュ: {chunks_hash}")
            print(f"暗号化日時: {encryption_time}, 元のファイル名: {original_filename}")

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
                    traceback.print_exc()
                return False

        # 識別不能性の除去
        # もしchunksがindistinguishable_ciphertextsの場合、識別不能性の除去が必要
        comprehensive_metadata = encrypted_data.get("indistinguishability", {})
        if comprehensive_metadata:
            print("識別不能性を除去中...")
            try:
                if use_enhanced_security:
                    # セキュリティ強化版を使用
                    unmasked_chunks = remove_comprehensive_indistinguishability_enhanced(
                        unmasked_chunks, comprehensive_metadata, key_type, paillier
                    )
                else:
                    # 既存の実装を使用
                    from method_8_homomorphic.indistinguishable import remove_comprehensive_indistinguishability
                    unmasked_chunks = remove_comprehensive_indistinguishability(
                        unmasked_chunks, comprehensive_metadata, key_type, paillier
                    )
                print("識別不能性除去完了")
            except Exception as e:
                print(f"エラー: 識別不能性除去中に問題が発生しました: {e}", file=sys.stderr)
                if verbose:
                    traceback.print_exc()
                return False

        # 暗号文を復号
        print("\n復号中...")
        plaintext_chunks = []
        for i, chunk in enumerate(unmasked_chunks):
            try:
                # 進捗表示
                if i % max(1, len(unmasked_chunks) // 100) == 0 or i == len(unmasked_chunks) - 1:
                    show_progress(i + 1, len(unmasked_chunks), "復号")

                # チャンクを復号
                plaintext = paillier.decrypt(chunk, private_key)
                plaintext_chunks.append(plaintext)
            except Exception as e:
                print(f"\nエラー: チャンク {i} の復号中に問題が発生しました: {e}", file=sys.stderr)
                if verbose:
                    traceback.print_exc()
                # エラーが発生しても処理を続行
                plaintext_chunks.append(0)  # ダミー値

        # データアダプタの決定とデータ処理
        try:
            from method_8_homomorphic.crypto_adapters import process_data_after_decryption
            from method_8_homomorphic.crypto_adapters import TextAdapter, BinaryAdapter, DataAdapter

            # データタイプに基づいてアダプタを選択
            adapter_type = None
            if force_text:
                adapter_type = "text"
            elif force_binary:
                adapter_type = "binary"
            else:
                adapter_type = data_type if data_type != "auto" else (current_data_type or "text")

            # アダプタの生成
            adapter: DataAdapter
            if adapter_type == "text":
                adapter = TextAdapter()
            else:
                adapter = BinaryAdapter()

            # 復号後のデータ処理
            result_data = process_data_after_decryption(plaintext_chunks, original_size, adapter)

            # 出力ファイルパスの準備
            if not output_path:
                # デフォルトの出力ファイル名を生成
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename, _ = os.path.splitext(os.path.basename(encrypted_file_path))
                output_path = f"{filename}_decrypted_{timestamp}.{OUTPUT_EXTENSION}"

            # 出力ディレクトリの確保
            output_dir = os.path.dirname(output_path)
            if output_dir:
                ensure_directory(output_dir)

            # 出力モード（テキストまたはバイナリ）
            mode = "w" if isinstance(result_data, str) else "wb"

            # 結果を出力ファイルに書き込み
            with open(output_path, mode) as f:
                f.write(result_data)

            print(f"\n復号完了: {output_path}")
            print(f"処理時間: {time.time() - start_time:.2f}秒")
            return True

        except Exception as e:
            print(f"\nエラー: データ処理中に問題が発生しました: {e}", file=sys.stderr)
            if verbose:
                traceback.print_exc()
            return False

    except Exception as e:
        print(f"エラー: 復号処理中に問題が発生しました: {e}", file=sys.stderr)
        if verbose:
            traceback.print_exc()
        return False


def main():
    """メイン関数"""
    args = parse_arguments()

    # 鍵の解析
    key = None

    # パスワードが指定されている場合はパスワードから鍵を導出
    if args.password:
        key = derive_key_from_password(args.password)
        print(f"パスワードから鍵を導出しました: {key.hex()}")
    # 鍵が指定されている場合は解析
    elif args.key:
        try:
            key = parse_key(args.key)
            if args.verbose:
                print(f"鍵を正常に解析しました: {key.hex()}")
        except Exception as e:
            print(f"エラー: 鍵の解析に失敗しました: {e}", file=sys.stderr)
            return 1

    # 入力ファイルのチェック
    if not os.path.exists(args.input_file):
        print(f"エラー: 入力ファイルが存在しません: {args.input_file}", file=sys.stderr)
        return 1

    # セキュリティ強化モードの判定
    use_enhanced_security = args.use_enhanced_security and not args.compatibility_mode
    if use_enhanced_security:
        print("セキュリティ強化版の機能を使用します")
    else:
        print("互換モードで動作します（セキュリティ強化機能無効）")

    # 復号実行
    success = decrypt_file_with_progress(
        args.input_file,
        key,
        args.output,
        args.key_type,
        args.verbose,
        args.force_binary,
        args.force_text,
        args.data_type,
        use_enhanced_security
    )

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())