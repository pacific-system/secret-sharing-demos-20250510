#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
#                 ██████  ███████  ██████ ██████  ██    ██ ██████  ████████    #
#                 ██   ██ ██      ██      ██   ██  ██  ██  ██   ██    ██       #
#                 ██   ██ █████   ██      ██████    ████   ██████     ██       #
#                 ██   ██ ██      ██      ██   ██    ██    ██         ██       #
#                 ██████  ███████  ██████ ██   ██    ██    ██         ██       #
#                                                                              #
#               【復号を実行するメインスクリプト - MAIN DECRYPTION SCRIPT】      #
#                                                                              #
#     このファイルは準同型暗号マスキング方式の「復号」機能のメインエントリーポイントです       #
#     最終成果物として、ユーザーはこのファイルを直接実行してファイルを復号します         #
#                                                                              #
################################################################################

"""
準同型暗号マスキング方式の復号スクリプト

このスクリプトは、準同型暗号マスキング方式で暗号化されたファイルを復号します。
鍵の種類（真/偽）に応じて、対応するファイル（true.text/false.text）が復元されます。
"""

import os
import sys
import json
import base64
import binascii
import hashlib
import random
import math
import time
import argparse
import struct
import sympy
import traceback
from typing import Dict, List, Any, Tuple, Optional, Union, cast, Set, BinaryIO

# インポートエラー回避のためパスを追加
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# 同じディレクトリ内のモジュールをインポート
from config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    PAILLIER_KEY_BITS,
    DEFAULT_CHARSET,
    MAX_CHUNK_SIZE
)
from homomorphic import (
    PaillierCrypto,
    derive_key_from_password
)
from crypto_mask import (
    MaskFunctionGenerator,
    AdvancedMaskFunctionGenerator,
    transform_between_true_false,
    extract_by_key_type
)
from crypto_adapters import (
    process_data_for_encryption,
    process_data_after_decryption,
    DataAdapter,
    TextAdapter,
    BinaryAdapter
)
from key_analyzer import (
    analyze_key_type_robust,
    extract_seed_from_key,
    debug_analyze_key as debug_key_analysis
)

# 循環インポートを解決するため、拡張モジュールから必要な関数をインポート
from indistinguishable_ext import (
    safe_log10,
    remove_redundancy,
    remove_statistical_noise
)

# 循環参照を回避するための条件付きインポート
_IndistinguishableWrapper = None
_analyze_key_type = None
_analyze_key_type_enhanced = None
_remove_comprehensive_indistinguishability = None
_remove_comprehensive_indistinguishability_enhanced = None
_deinterleave_ciphertexts = None

def _lazy_import_indistinguishable():
    """必要な時だけindistinguishableモジュールをインポートする関数"""
    global _IndistinguishableWrapper, _analyze_key_type, _analyze_key_type_enhanced
    global _remove_comprehensive_indistinguishability, _remove_comprehensive_indistinguishability_enhanced, _deinterleave_ciphertexts

    if _IndistinguishableWrapper is None:
        try:
            # 相対インポートで循環参照を解決
            from method_8_homomorphic.indistinguishable import (
                IndistinguishableWrapper,
                analyze_key_type,
                analyze_key_type_enhanced,
                remove_comprehensive_indistinguishability,
                remove_comprehensive_indistinguishability_enhanced,
                deinterleave_ciphertexts
            )
            _IndistinguishableWrapper = IndistinguishableWrapper
            _analyze_key_type = analyze_key_type
            _analyze_key_type_enhanced = analyze_key_type_enhanced
            _remove_comprehensive_indistinguishability = remove_comprehensive_indistinguishability
            _remove_comprehensive_indistinguishability_enhanced = remove_comprehensive_indistinguishability_enhanced
            _deinterleave_ciphertexts = deinterleave_ciphertexts
        except ImportError as e:
            print(f"警告: indistinguishableモジュールのインポートに失敗しました: {e}")
            # フォールバック実装
            _IndistinguishableWrapper = object  # ダミークラス
            _analyze_key_type = lambda key: "unknown"
            _analyze_key_type_enhanced = lambda key, metadata=None: "unknown"
            _remove_comprehensive_indistinguishability = lambda *args, **kwargs: []
            _remove_comprehensive_indistinguishability_enhanced = lambda *args, **kwargs: []
            _deinterleave_ciphertexts = lambda *args, **kwargs: []


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
    モジュラ逆数の計算

    この関数は拡張ユークリッドアルゴリズムを使用して、
    aのmod mにおける逆数を計算します。

    ax ≡ 1 (mod m) となるようなxを見つけます。

    Args:
        a: 逆数を求める数
        m: 法（モジュラス）

    Returns:
        aのmod mにおける逆数

    Raises:
        ValueError: aとmが互いに素でない場合
    """
    if m == 1:
        return 0

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x

    gcd, x, y = extended_gcd(a, m)

    if gcd != 1:
        raise ValueError(f"モジュラ逆数が存在しません: {a} と {m} は互いに素ではありません。")
    else:
        return x % m


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


def decrypt_file(input_file, output_file=None, key=None, key_bytes=None, key_type=None,
                 data_type=None, use_enhanced_security=False, verbose=False):
    """
    暗号化ファイルを復号する

    Args:
        input_file: 入力ファイルパス
        output_file: 出力ファイルパス（省略可）
        key: 鍵ファイルパス（省略可）
        key_bytes: 鍵のバイトデータ（直接指定する場合）
        key_type: 鍵タイプ ("true" または "false")
        data_type: データタイプ（"text", "binary", "auto"）
        use_enhanced_security: 拡張セキュリティモード
        verbose: 詳細なログ出力を行うか

    Returns:
        復号結果の辞書
    """
    try:
        # 入力ファイルの存在確認
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"入力ファイルが見つかりません: {input_file}")

        # データタイプのデフォルト値
        if data_type is None:
            data_type = 'auto'

        # キータイプのデフォルト値
        if key_type is None:
            key_type = 'auto'

        # デバッグ情報
        if verbose:
            print(f"復号処理開始: {input_file}")
            print(f"キータイプ: {key_type}")
            print(f"データタイプ: {data_type}")

        # 鍵の取得
        decryption_key = key_bytes
        if decryption_key is None:
            # 鍵ファイルからの読み込み
            if key and os.path.exists(key):
                with open(key, 'rb') as f:
                    decryption_key = f.read()
            else:
                # 鍵入力の要求
                key_input = input("復号鍵を入力してください: ")
                decryption_key = derive_key_from_password(key_input, KEY_SIZE_BYTES)

        # キータイプの自動判別
        if key_type == 'auto':
            # 識別不能性モジュールを動的にロード
            _lazy_import_indistinguishable()

            # まず強化版APIが利用可能か確認し、可能なら使用
            if _analyze_key_type_enhanced:
                # 暗号文メタデータを使用して鍵タイプを判定
                try:
                    # メタデータの取得（新しいフォーマットに対応）
                    with open(input_file, 'r') as f:
                        encrypted_data = json.load(f)

                    # メタデータを取得
                    metadata = encrypted_data.get('metadata', {})

                    # 強化版の鍵判定を使用
                    key_type = analyze_key_type_robust_enhanced(decryption_key, metadata)

                    if verbose:
                        print(f"自動判別されたキータイプ: {key_type}")
                except Exception as e:
                    print(f"キータイプの判定中にエラーが発生: {e}")
                    # エラーの場合は標準の鍵解析関数を使用
                    key_type = analyze_key_type_robust_enhanced(decryption_key)
                    if verbose:
                        print(f"標準関数で判別されたキータイプ: {key_type}")
            else:
                # フォールバック：標準の鍵解析関数を使用
                key_type = analyze_key_type_robust_enhanced(decryption_key)
                if verbose:
                    print(f"標準関数で判別されたキータイプ: {key_type}")
        else:
            key_type = key_type

        # 暗号化ファイルの読み込み
        with open(input_file, 'r') as f:
            encrypted_data = json.load(f)

        # メタデータの取得（新しいフォーマットに対応）
        metadata = encrypted_data.get('metadata', {})

        # データタイプを取得（新フォーマットではtrue_data_typeまたはfalse_data_typeから取得）
        if key_type == 'true':
            original_data_type = encrypted_data.get('true_data_type', data_type)
        else:
            original_data_type = encrypted_data.get('false_data_type', data_type)

        # 元のデータタイプがメタデータになければデフォルト値を使用
        if original_data_type is None or original_data_type == 'auto':
            original_data_type = data_type

        algorithm = encrypted_data.get('algorithm', 'paillier')

        # 元のファイル名を取得
        if key_type == 'true':
            original_filename = encrypted_data.get('true_filename', '')
        else:
            original_filename = encrypted_data.get('false_filename', '')

        # データタイプを更新（指定されたデータタイプを優先）
        if data_type != 'auto':
            original_data_type = data_type

        if verbose:
            print(f"暗号化アルゴリズム: {algorithm}")
            print(f"元のデータタイプ: {original_data_type}")
            if original_filename:
                print(f"元のファイル名: {original_filename}")

        # 出力ファイル名の決定
        if output_file is None:
            if original_filename:
                # 元のファイル名を使用（拡張子の前に _decrypted を挿入）
                base, ext = os.path.splitext(original_filename)
                output_file = f"{base}_decrypted{ext}"
            else:
                # 入力ファイル名から派生
                base, _ = os.path.splitext(input_file)
                output_file = f"{base}_decrypted.bin"

        # オリジナルサイズ情報を取得（キータイプに応じて）
        if key_type == 'true':
            original_size = encrypted_data.get('true_size', 0)
        else:
            original_size = encrypted_data.get('false_size', 0)

        # サイズ情報がない場合は metadata から探す
        if original_size == 0 and 'metadata' in encrypted_data:
            metadata = encrypted_data.get('metadata', {})
            if key_type == 'true':
                original_size = metadata.get('true_size', 0)
            else:
                original_size = metadata.get('false_size', 0)

        if verbose:
            print(f"元のデータサイズ: {original_size} バイト")

        # 暗号化されたチャンクを取得（新フォーマットに対応）
        # all_chunks または true_chunks/false_chunksからデータを取得
        all_chunks = encrypted_data.get('all_chunks', [])
        true_chunks = encrypted_data.get('true_chunks', [])
        false_chunks = encrypted_data.get('false_chunks', [])

        # 両方のフォーマットに対応
        if not all_chunks and not (true_chunks or false_chunks):
            raise ValueError("暗号化されたデータが見つかりません")

        # マスク関数生成のためのシード生成
        mask_data = encrypted_data.get('mask', {})
        true_mask = mask_data.get('true_mask', {})
        false_mask = mask_data.get('false_mask', {})

        # 現在の鍵タイプに基づいて適切なマスクを選択
        curr_mask = true_mask if key_type == 'true' else false_mask

        # マスク関数生成
        if verbose:
            print("マスク関数の生成...")

        # Paillier暗号系の作成
        paillier = PaillierCrypto(key_bytes=decryption_key)

        # 高度なマスク関数を使用
        if use_enhanced_security:
            mask_gen = AdvancedMaskFunctionGenerator(paillier, decryption_key)
        else:
            mask_gen = MaskFunctionGenerator(paillier, decryption_key)

        # マスク関数をパラメータから生成
        # 現時点では実際のアンマスク処理は行わず、チャンクをそのまま返す
        def unmask_function(ciphertext: int) -> int:
            # アンマスク処理を実装
            # 注：キータイプに応じて異なるマスク関数を適用する必要があります
            if key_type == 'true':
                # 真の鍵用のアンマスク関数
                return mask_gen.unmask_true(ciphertext)
            else:
                # 偽の鍵用のアンマスク関数
                return mask_gen.unmask_false(ciphertext)

        # 復号処理
        if verbose:
            print("復号処理を実行中...")
            print(f"使用する鍵タイプ: {key_type}")
            print(f"元のデータタイプ: {original_data_type}")
            print(f"元のデータサイズ: {original_size}")

        # 復号するチャンクの選択
        if all_chunks:
            # 古いフォーマット: すべてのチャンクが混合されている
            if key_type == 'true':
                chunks_to_decrypt = all_chunks[::2]  # 偶数インデックスのチャンク（0, 2, 4, ...）
            else:
                chunks_to_decrypt = all_chunks[1::2]  # 奇数インデックスのチャンク（1, 3, 5, ...）
        else:
            # 新しいフォーマット: チャンクは分離されている
            if key_type == 'true' and true_chunks:
                chunks_to_decrypt = true_chunks
            elif key_type == 'false' and false_chunks:
                chunks_to_decrypt = false_chunks
            else:
                raise ValueError(f"指定された鍵タイプ '{key_type}' に対応するチャンクが見つかりません")

        # 最終的なチャンクサイズを決定
        # デフォルト値または明示的に指定された値（メタデータから）を使用
        chunk_size = encrypted_data.get('chunk_size', MAX_CHUNK_SIZE)
        if chunk_size <= 0:
            # メタデータからも取得を試みる
            metadata = encrypted_data.get('metadata', {})
            chunk_size = metadata.get('chunk_size', MAX_CHUNK_SIZE)

        # chunk_sizeの検証（正の値であることを確認）
        if chunk_size <= 0:
            chunk_size = MAX_CHUNK_SIZE
            print(f"警告: チャンクサイズが不正なため、デフォルト値 {chunk_size} を使用します")

        if verbose:
            print(f"復号するチャンク数: {len(chunks_to_decrypt)}")
            print(f"チャンクサイズ: {chunk_size}")
            print(f"合計予測データサイズ: {len(chunks_to_decrypt) * chunk_size} バイト")
            print(f"要求された元のデータサイズ: {original_size} バイト")

        # チャンクを復号
        decrypted_chunks = []
        for idx, chunk in enumerate(chunks_to_decrypt):
            # 進捗表示
            if verbose and idx % 10 == 0:
                print(f"チャンク {idx}/{len(chunks_to_decrypt)} を処理中...")

            # チャンクを復号
            try:
                # 文字列または16進数の文字列を整数に変換
                if isinstance(chunk, str):
                    if chunk.startswith('0x'):
                        int_chunk = int(chunk, 16)
                    else:
                        int_chunk = int(chunk)
                else:
                    int_chunk = chunk

                # 暗号文に対してマスク関数を適用して変換
                demasked_chunk = unmask_function(int_chunk)

                # 復号
                decrypted_chunk = paillier.decrypt(demasked_chunk)

                if verbose and idx == 0:
                    print(f"[DEBUG] 復号されたチャンク整数値: {decrypted_chunk}")

                # 最後のチャンクは部分的かもしれない
                if idx == len(chunks_to_decrypt) - 1 and original_size > 0:
                    # 既に処理されたサイズを計算
                    processed_size = idx * chunk_size
                    # 残りサイズが元のサイズ未満ならば調整
                    if processed_size + chunk_size > original_size:
                        last_chunk_size = original_size - processed_size
                        if verbose:
                            print(f"[DEBUG] 最後のチャンク調整: サイズ={last_chunk_size}バイト（通常={chunk_size}）")
                    else:
                        last_chunk_size = chunk_size
                else:
                    last_chunk_size = chunk_size

                # バイトに変換
                try:
                    # 大きさに合わせて変換
                    bit_length = max(1, decrypted_chunk.bit_length())
                    byte_length = (bit_length + 7) // 8

                    # 必要なバイト長の判断
                    if byte_length <= last_chunk_size:
                        # 必要に応じてパディング（右詰め）
                        byte_chunk = decrypted_chunk.to_bytes(
                            byte_length, byteorder='big'
                        ).rjust(last_chunk_size, b'\x00')
                    else:
                        # ビットフィールドが大きすぎる場合、必要なサイズに切り詰め
                        byte_chunk = decrypted_chunk.to_bytes(
                            byte_length, byteorder='big'
                        )[-last_chunk_size:]

                    if verbose and idx == 0:
                        print(f"[DEBUG] バイト変換: {byte_length}バイト→{len(byte_chunk)}バイト")

                except (OverflowError, ValueError) as e:
                    if verbose:
                        print(f"[WARN] バイト変換エラー: {e}")
                    # エラーが起きた場合、固定サイズでパディング
                    byte_chunk = b'\x00' * last_chunk_size

                decrypted_chunks.append(byte_chunk)

            except Exception as e:
                if verbose:
                    print(f"チャンク {idx} の復号中にエラー: {e}")
                    import traceback
                    traceback.print_exc()
                # エラーが発生したチャンクは空のバイト列で置き換え
                decrypted_chunks.append(b'\x00' * chunk_size)

        # すべてのチャンクを結合
        file_content = b''.join(decrypted_chunks)

        # original_sizeを確認し、必要に応じて調整
        if original_size > 0:
            if len(file_content) != original_size:
                if verbose:
                    print(f"[WARN] 復号データサイズ({len(file_content)})が元のサイズ({original_size})と一致しません")
                # original_sizeに合わせる
                if len(file_content) > original_size:
                    # 切り詰め
                    file_content = file_content[:original_size]
                else:
                    # パディング
                    file_content = file_content + b'\x00' * (original_size - len(file_content))

        if verbose:
            print(f"結合後データサイズ: {len(file_content)} バイト")
            if len(file_content) > 0:
                print(f"先頭バイト: {file_content[:min(20, len(file_content))]}")
                if len(file_content) > 40:
                    print(f"末尾バイト: {file_content[-min(20, len(file_content)):]}")

        # データ処理（データタイプに基づく後処理）
        if verbose:
            print(f"データ後処理（タイプ: {original_data_type}）...")

        try:
            processed_content = process_data_after_decryption(file_content, original_data_type)

            # 出力ファイルに書き込み
            write_mode = 'wb' if isinstance(processed_content, bytes) else 'w'

            # データの最終チェック（テキスト系の場合UTF-8に変換を保証）
            if original_data_type in ['text', 'json', 'csv']:
                # バイナリからテキストへの変換を確実に行う
                if isinstance(processed_content, bytes):
                    try:
                        # UTF-8でデコード
                        processed_content = processed_content.decode('utf-8', errors='replace')
                        write_mode = 'w'  # テキストモードに変更
                        if verbose:
                            print(f"バイナリからテキストに変換しました: {len(processed_content)}文字")
                    except Exception as e:
                        print(f"テキスト変換エラー: {e}")

                # テキストデータの場合、末尾の改行を確保
                if isinstance(processed_content, str):
                    if processed_content and not processed_content.endswith('\n'):
                        processed_content += '\n'
                        if verbose:
                            print("末尾に改行を追加しました")

            with open(output_file, write_mode) as f:
                if isinstance(processed_content, str):
                    f.write(processed_content)
                else:
                    f.write(processed_content)

            if verbose:
                print(f"復号が完了しました: {output_file}")
                print(f"出力データタイプ: {type(processed_content).__name__}")
                print(f"出力データサイズ: {os.path.getsize(output_file)} バイト")

                # 最初の数文字をデバッグ出力
                if isinstance(processed_content, str) and len(processed_content) > 0:
                    print(f"出力データサンプル（先頭20文字）: '{processed_content[:20]}'")
                elif isinstance(processed_content, bytes) and len(processed_content) > 0:
                    print(f"出力データサンプル（先頭20バイト）: {processed_content[:20]}")
        except Exception as e:
            import traceback
            print(f"データ処理中にエラーが発生しました: {e}")
            traceback.print_exc()

            # エラー回復処理: バイナリデータをそのまま書き込み
            with open(output_file, 'wb') as f:
                f.write(file_content)
            print(f"エラー回復: 元のバイナリデータをそのまま出力しました: {output_file}")

            # エラー出力用ファイル
            error_file = f"{output_file}.error.txt"
            with open(error_file, 'w') as f:
                f.write(f"エラー: {e}\n")
                f.write(traceback.format_exc())
            print(f"エラー詳細: {error_file}")

        # 結果を返す
        return {
            'success': True,
            'output_file': output_file,
            'original_data_type': original_data_type,
            'decrypted_chunks': len(decrypted_chunks),
            'output_size': os.path.getsize(output_file) if os.path.exists(output_file) else 0
        }

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        if verbose:
            print(f"復号中にエラーが発生しました: {e}")
            print(error_trace)

        return {
            'success': False,
            'error': str(e),
            'error_trace': error_trace
        }


def decrypt_bytes(ciphertext_int: int, private_key: Dict[str, Any], byte_size: int = 0) -> bytes:
    """
    暗号文を復号し、バイト列に変換

    Args:
        ciphertext_int: 整数形式の暗号文
        private_key: 秘密鍵
        byte_size: 元のバイトサイズ（0の場合は自動推定）

    Returns:
        復号されたバイト列
    """
    # Paillierインスタンスを作成
    paillier = PaillierCrypto()
    paillier.private_key = private_key

    # 暗号文を復号
    try:
        plaintext_int = paillier.decrypt(ciphertext_int, private_key)
    except Exception as e:
        print(f"復号エラー: {e}")
        return b''

    # 整数からバイト列に変換
    try:
        # バイトサイズが指定されていない場合は推定
        if byte_size <= 0:
            # ビット長から必要なバイト数を計算
            byte_size = (plaintext_int.bit_length() + 7) // 8
            # 最小サイズを確保
            byte_size = max(byte_size, 1)

        # 修正: 整数からバイトへの変換処理を改善
        # 以前の方法: plaintext_bytes = plaintext_int.to_bytes(byte_size, byteorder='big')

        # 安全にバイト列に変換（サイズが足りないケースを処理）
        try:
            plaintext_bytes = plaintext_int.to_bytes(byte_size, byteorder='big')
        except OverflowError:
            # 整数が大きすぎる場合はバイトサイズを調整
            actual_byte_size = (plaintext_int.bit_length() + 7) // 8
            print(f"[DEBUG] バイト変換: {byte_size}バイト→{actual_byte_size}バイト")
            plaintext_bytes = plaintext_int.to_bytes(actual_byte_size, byteorder='big')

        return plaintext_bytes
    except Exception as e:
        print(f"バイト変換エラー: {e}")
        # エラー時は空のバイト列を返す
        return b''


def decrypt_chunks(encrypted_chunks, paillier_key, original_data_type, original_data_size=0, key_type='true', verbose=False):
    """
    暗号化されたチャンクを復号

    Args:
        encrypted_chunks: 暗号化されたチャンクのリスト
        paillier_key: Paillier暗号の鍵
        original_data_type: 元のデータタイプ
        original_data_size: 元のデータサイズ
        key_type: 鍵のタイプ (true/false)
        verbose: 詳細なログを出力するか

    Returns:
        復号されたバイト列
    """
    if not encrypted_chunks:
        return b''

    print(f"使用する鍵タイプ: {key_type}")
    print(f"元のデータタイプ: {original_data_type}")
    print(f"元のデータサイズ: {original_data_size}")

    # 暗号化チャンク数
    num_chunks = len(encrypted_chunks)
    print(f"復号するチャンク数: {num_chunks}")

    # PaillierCryptoインスタンスを作成
    paillier = PaillierCrypto()
    paillier.private_key = paillier_key

    # 各チャンクの大まかなサイズ（仮定）
    chunk_size = 256
    print(f"チャンクサイズ: {chunk_size}")

    # 合計データサイズの予測
    total_data_size = num_chunks * chunk_size
    print(f"合計予測データサイズ: {total_data_size} バイト")

    if original_data_size:
        print(f"要求された元のデータサイズ: {original_data_size} バイト")

    # 結果バイト列
    result_bytes = bytearray()

    for i, chunk in enumerate(encrypted_chunks):
        if verbose:
            print(f"チャンク {i}/{num_chunks-1} を処理中...")

        try:
            # チャンクを復号
            plaintext_int = paillier.decrypt(chunk, paillier_key)

            if verbose:
                print(f"[DEBUG] 復号されたチャンク整数値: {plaintext_int}")

            # 最後のチャンクの場合、サイズを調整
            bytes_to_get = chunk_size
            if i == num_chunks - 1 and original_data_size > 0:
                # 最後のチャンクの予想サイズを計算
                remaining_size = original_data_size - (num_chunks - 1) * chunk_size
                if remaining_size > 0 and remaining_size < chunk_size:
                    bytes_to_get = remaining_size
                    if verbose:
                        print(f"[DEBUG] 最後のチャンク調整: サイズ={bytes_to_get}バイト（通常={chunk_size}）")

            # 新しいdecrypt_bytes関数を使用
            chunk_bytes = decrypt_bytes(chunk, paillier_key, bytes_to_get)

            if verbose and i == num_chunks - 1:
                print(f"[DEBUG] バイト変換: {len(chunk_bytes)}バイト→{bytes_to_get}バイト")

            # 結果に追加
            result_bytes.extend(chunk_bytes)
        except Exception as e:
            print(f"チャンク {i} の復号中にエラーが発生: {e}")
            if verbose:
                import traceback
                traceback.print_exc()

    # 要求された元のサイズがある場合、そのサイズに切り詰める
    if original_data_size > 0 and len(result_bytes) > original_data_size:
        result_bytes = result_bytes[:original_data_size]

    print(f"結合後データサイズ: {len(result_bytes)} バイト")

    # 先頭と末尾の部分を表示
    if len(result_bytes) > 20:
        print(f"先頭バイト: {bytes(result_bytes[:20])}")
        print(f"末尾バイト: {bytes(result_bytes[-20:])}")

    # マーカーを探す
    if len(result_bytes) > 10:
        # マーカーを探して検証
        try:
            result_str = result_bytes.decode('utf-8', errors='replace')

            # よく使われるマーカーをチェック
            markers = {
                'TEXT:UTF8:': 'text',
                'JSON:': 'json',
                'CSV:': 'csv',
                'B64:': 'base64'
            }

            for marker, marker_type in markers.items():
                if marker in result_str[:100]:  # 先頭100文字以内にマーカーがあるか
                    print(f"マーカー '{marker}' を検出しました - タイプ: {marker_type}")
                    # original_data_typeと一致する場合は問題なし
                    if marker_type == original_data_type:
                        print(f"マーカータイプが元のデータタイプと一致: {marker_type}")
                    else:
                        print(f"警告: マーカータイプ({marker_type})が元のデータタイプ({original_data_type})と一致しません")
        except Exception as e:
            print(f"マーカー検出中にエラー: {e}")

    return bytes(result_bytes)


def analyze_key_type_robust_enhanced(key: bytes, metadata=None) -> str:
    """
    鍵タイプをより堅牢に判定するための拡張関数

    Args:
        key: 鍵データ
        metadata: 暗号化メタデータ（利用可能な場合）

    Returns:
        鍵タイプ ("true" または "false")
    """
    # 鍵からSHA-256ハッシュを生成
    key_hash = hashlib.sha256(key).digest()

    # メタデータが利用可能な場合は追加のコンテキストとして使用
    if metadata:
        try:
            # メタデータから重要な情報を抽出
            algorithm = metadata.get('algorithm', '')
            timestamp = metadata.get('timestamp', 0)
            file_info = metadata.get('true_filename', '') + metadata.get('false_filename', '')

            # 鍵とメタデータの情報を組み合わせたコンテキスト情報
            context = f"{algorithm}:{timestamp}:{file_info}".encode('utf-8')

            # 鍵ハッシュとコンテキストを組み合わせた二次ハッシュ
            context_hash = hashlib.sha256(key_hash + context).digest()

            # 複数の条件を組み合わせて堅牢な判定を実現
            condition1 = key_hash[0] % 2 == 0
            condition2 = context_hash[0] % 2 == 0
            condition3 = (key_hash[1] & 0x0F) > (key_hash[1] & 0xF0) >> 4
            condition4 = key_hash[16] % 2 == 0

            # 複数条件の多数決で判定（より堅牢な判定）
            true_score = sum([condition1, condition2, condition3, condition4])
            return "true" if true_score >= 2 else "false"
        except Exception as e:
            print(f"拡張鍵解析でエラー発生: {e}, シンプルな判定にフォールバック")
            # エラー時はシンプルな判定にフォールバック
            pass

    # シンプルな鍵ハッシュベースの判定（メタデータがない場合のフォールバック）
    # これは元の analyze_key_type_robust と同様の挙動
    return "true" if key_hash[0] % 2 == 0 else "false"


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
        # 識別不能性機能の使用時は必要なモジュールをロード
        if args.use_enhanced_security and not args.compatibility_mode:
            _lazy_import_indistinguishable()

        # 鍵の解析
        if args.password:
            # パスワードから鍵を導出
            print(f"パスワードから鍵を導出します...")
            key = derive_key_from_password(args.password)
            print(f"パスワードから鍵を導出しました: {key.hex()}")
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

        # セキュリティ強化モードの判定
        use_enhanced_security = args.use_enhanced_security and not args.compatibility_mode
        if use_enhanced_security:
            print("セキュリティ強化版の機能を使用します")
        else:
            print("互換モードで動作します（セキュリティ強化機能無効）")

        # 復号の実行
        print(f"準同型暗号マスキング方式で復号を開始します...")
        start_time = time.time()

        # 鍵タイプが自動判別の場合
        if args.key_type == 'auto':
            _lazy_import_indistinguishable()
            if _analyze_key_type_enhanced:
                key_type = _analyze_key_type_enhanced(key)
                if args.verbose:
                    print(f"鍵を解析しました: {key_type}タイプ")
            else:
                key_type = args.key_type
        else:
            key_type = args.key_type

        success = decrypt_file(
            input_file=args.input_file,
            output_file=output_path,
            key=args.key,
            key_bytes=key,
            key_type=key_type,
            data_type=args.data_type,
            use_enhanced_security=use_enhanced_security,
            verbose=args.verbose
        )

        elapsed_time = time.time() - start_time

        if success['success']:
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
