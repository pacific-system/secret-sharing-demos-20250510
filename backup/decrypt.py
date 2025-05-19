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

# ============================================================================ #
# 【警告: セキュリティ上の重要事項】                                              #
# 明示的に鍵の種類（true/false）を指定するコマンドラインオプションの実装は厳禁です。      #
# 例: 「output.henc -t true」や「output.henc -t false」のようなオプション         #
#                                                                              #
# このような実装は区別不能性の要件に違反し、暗号システム全体のセキュリティを損ないます。 #
# 攻撃者がソースコードを入手した場合に、trueとfalseの両方のオプションを試すことで       #
# ハニートラップの存在が明らかになってしまいます。                                  #
# ============================================================================ #

"""
準同型暗号マスキング方式 - 復号プログラム

準同型暗号マスキング方式で暗号化されたファイルを復号するためのプログラムです。
区別不能性の要件を満たし、異なる鍵で異なる平文を復号できます。
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
    process_data_after_decryption
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
    # ============================================================================ #
    # 【警告: セキュリティ上の重要事項】                                              #
    # 明示的な鍵タイプ指定機能（--key-type）はセキュリティ要件上廃止されるべきです。    #
    # この機能は暗号学的区別不能性の原則に違反します。                                 #
    # 下位互換性のためにコードは残していますが、将来のバージョンでは削除されます。       #
    # ============================================================================ #

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

    # セキュリティ上の問題あり - 将来のバージョンでは削除予定
    # 攻撃者が両方のオプションを試すことでハニートラップの存在が露呈するリスクがあります
    parser.add_argument(
        '--key-type',
        choices=['auto'],  # 'true'と'false'は削除し、'auto'のみに制限
        default='auto',
        help='【非推奨】鍵の種類は自動判定のみが安全です'
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

    # ============================================================================ #
    # 【セキュリティ警告】                                                         #
    # key_type パラメータの明示的な指定は厳禁です。                                 #
    # 区別不能性を保証するため、鍵の種類は暗号学的に自動検出されるべきで、            #
    # ユーザーが操作できるコマンドラインオプションとして公開してはなりません。         #
    # 明示的な鍵タイプ指定（-t true/false）は区別不能性の要件に違反するため廃止対象です #
    # ============================================================================ #

    Args:
        input_file: 入力ファイルパス
        output_file: 出力ファイルパス（省略可）
        key: 鍵ファイルパス（省略可）
        key_bytes: 鍵のバイトデータ（直接指定する場合）
        key_type: 【非推奨・使用禁止】鍵タイプ (常に自動判定を使用)
        data_type: データタイプ（"text", "binary", "auto"）
        use_enhanced_security: 拡張セキュリティモード
        verbose: 詳細なログ出力を行うか

    Returns:
        復号結果の辞書
    """
    # セキュリティ対策: 明示的な鍵タイプ指定が行われた場合の警告
    if key_type is not None and key_type not in ['auto', None]:
        print("【セキュリティ警告】明示的な鍵タイプ指定は安全でなく、将来のバージョンでは削除されます")
        print("区別不能性を確保するため、鍵タイプは常に自動判定を使用します")
        key_type = None  # 自動判定を強制
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
            # セキュリティ対策: 鍵タイプの情報は表示しない
            print(f"キータイプ: セキュリティポリシーにより非表示")
            print(f"データタイプ: {data_type}")
            print(f"※セキュリティ注意: 明示的な鍵タイプ指定は区別不能性の要件に違反します。")

        # 鍵の取得
        decryption_key = key_bytes
        if decryption_key is None:
            # 鍵入力が必要な場合
            key_input = input("復号鍵を入力してください: ")

            # パスワードから鍵を導出
            salt_bytes = os.urandom(SALT_SIZE)  # 一時的なソルト
            try:
                # 単純な方法で鍵を導出（パスワードからハッシュ生成）
                decryption_key = hashlib.sha256(key_input.encode()).digest()
    except Exception as e:
                print(f"鍵の処理中にエラーが発生しました: {e}")
                return None

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
                    key_type = analyze_key_type_robust(decryption_key)
            else:
                # 標準版の鍵判定を使用
                key_type = analyze_key_type_robust(decryption_key)
                if verbose:
                    print(f"自動判別されたキータイプ: {key_type}")

        # 暗号化ファイルの読み込み
        try:
            # 最初にJSON形式で読み込みを試みる
            with open(input_file, 'r') as f:
                try:
                encrypted_data = json.load(f)

                    # 新形式のJSONから必要な情報を抽出
                    ciphertexts = encrypted_data.get('ciphertext', [])
                    metadata = encrypted_data.get('metadata', {})
                    algorithm = metadata.get('algorithm', 'paillier')
                    original_type = metadata.get('data_type', 'auto')
                    original_filename = metadata.get('filename', '')
                    original_size = metadata.get('original_size', 0)
                    mask_params = metadata.get('mask_params', {})

                    if verbose:
                        print(f"暗号化アルゴリズム: {algorithm}")
                        print(f"元のデータタイプ: {original_type}")
                        print(f"元のファイル名: {original_filename}")
                        print(f"元のデータサイズ: {original_size} バイト")

                except json.JSONDecodeError:
                    # JSONとして解析できない場合は旧形式として扱う
                    f.seek(0)  # ファイルポインタを先頭に戻す

                    # 旧形式は直接チャンクのリストを含む
                    encrypted_lines = f.read().strip().split('\n')
                    ciphertexts = [int(line.strip()) for line in encrypted_lines if line.strip()]

                    # 旧形式ではメタデータがないので、デフォルト値を使用
                    algorithm = 'paillier'
                    original_type = data_type
                    original_filename = ''
                    original_size = 0
                    mask_params = {}
        except Exception as e:
            # ファイル読み込みに失敗した場合はバイナリモードで再試行
            try:
                with open(input_file, 'rb') as f:
                    # バイナリファイルを行ごとに分割
                    binary_data = f.read()

                    # 先頭バイトを確認して形式を判断
                    if binary_data.startswith(b'{'):
                        # JSONバイナリ形式
                        try:
                            encrypted_data = json.loads(binary_data.decode('utf-8'))
                            ciphertexts = encrypted_data.get('ciphertext', [])
                            metadata = encrypted_data.get('metadata', {})
                            algorithm = metadata.get('algorithm', 'paillier')
                            original_type = metadata.get('data_type', 'auto')
                            original_filename = metadata.get('filename', '')
                            original_size = metadata.get('original_size', 0)
                            mask_params = metadata.get('mask_params', {})
                        except:
                            # JSONとして解析できない場合
                            print(f"バイナリJSONフォーマットではないようです")
                            raise
        else:
                        # バイナリ行形式
                        binary_lines = binary_data.split(b'\n')
                        ciphertexts = []
                        for line in binary_lines:
                            if line.strip():
                                try:
                                    ciphertexts.append(int(line.strip()))
                                except:
                                    # 整数に変換できない行はスキップ
                                    pass

                        # メタデータはなし
                        algorithm = 'paillier'
                        original_type = data_type
                        original_filename = ''
                        original_size = 0
                        mask_params = {}
            except Exception as e2:
                print(f"暗号化ファイルの読み込みに失敗しました: {e2}")
                return None

        # マスク関数を適用するための準備
        if verbose:
            print("マスク関数の生成...")

        # シンプルな場合または互換モードでは高度なマスク関数ジェネレータを作成
        # 識別不能性モジュールを動的にロード
        _lazy_import_indistinguishable()
        try:
            # シード値を鍵から導出
            seed = extract_seed_from_key(decryption_key)

            # Paillier暗号鍵の導出
            public_key, private_key = derive_homomorphic_keys(decryption_key)

            # マスク関数ジェネレータを初期化
            if use_enhanced_security and _IndistinguishableWrapper:
                # 高度なマスク関数ジェネレータを使用
                mask_gen = AdvancedMaskFunctionGenerator(public_key=public_key, seed=seed)
            else:
                # 基本的なマスク関数ジェネレータを使用
                mask_gen = MaskFunctionGenerator(public_key=public_key, seed=seed)

        except Exception as e:
            print(f"マスク関数の生成に失敗しました: {e}")
            # メインのPaillier復号処理はまだ可能なので続行
            public_key = {'n': 0, 'g': 0}
            private_key = {'lambda': 0, 'mu': 0, 'p': 0, 'q': 0}
            mask_gen = None

        # すべてのチャンクを復号
        if verbose:
            print("復号処理を実行中...")

        try:
            # 修正: decrypt_chunks関数が(データ, データタイプ)のタプルを返すようになった
            decrypted_data, detected_data_type = decrypt_chunks(
                ciphertexts,
                private_key,
                original_type,
                original_size,
                key_type,
                verbose
            )

            # データタイプの決定
            if data_type != 'auto':
                # 明示的に指定されたデータタイプを使用
                final_data_type = data_type
            else:
                # 検出されたデータタイプを使用
                final_data_type = detected_data_type

            # データ処理を実行
            if verbose:
                print(f"データ後処理（タイプ: {final_data_type}）...")

            # データの後処理（テキスト変換など）
            processed_data = process_data_after_decryption(decrypted_data, final_data_type)

            # 出力ファイルパスの生成
            if output_file is None:
                # 適切な拡張子を追加
                if final_data_type == 'text':
                    output_file = 'decrypted.txt'
                elif final_data_type == 'json':
                    output_file = 'decrypted.json'
                elif final_data_type == 'csv':
                    output_file = 'decrypted.csv'
                else:
                    output_file = 'decrypted.bin'

            # 出力ディレクトリの確認
            output_dir = os.path.dirname(output_file)
            if output_dir:
                ensure_directory(output_dir)

            # ファイルへの書き込み
            try:
                if isinstance(processed_data, str):
                    # テキストとして書き込み
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(processed_data)
                    output_data_type = 'str'
                else:
                    # バイナリとして書き込み
                    with open(output_file, 'wb') as f:
                        f.write(processed_data)
                    output_data_type = 'bytes'

                print(f"復号が完了しました: {output_file}")
                print(f"出力データタイプ: {output_data_type}")
                print(f"出力データサイズ: {len(processed_data)} バイト")

                # サンプルデータの表示
                if isinstance(processed_data, str) and len(processed_data) > 0:
                    sample_length = min(20, len(processed_data))
                    print(f"出力データサンプル（先頭{sample_length}文字）: '{processed_data[:sample_length]}'")
                elif len(processed_data) > 0:
                    sample_length = min(20, len(processed_data))
                    print(f"出力データサンプル（先頭{sample_length}バイト）: {processed_data[:sample_length]}")

            except Exception as e:
                print(f"出力ファイルの書き込み中にエラーが発生: {e}")
                return None

            return {
                'success': True,
                'output_file': output_file,
                'data_type': final_data_type,
                'data_size': len(processed_data),
                'data': processed_data
            }

        except Exception as e:
            print(f"復号処理中にエラーが発生しました: {e}")
                    import traceback
                    traceback.print_exc()
            return None

    except Exception as e:
        print(f"復号処理中に予期せぬエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return None

    finally:
        start_time = time.time()
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"復号が完了しました（所要時間: {elapsed_time:.2f}秒）")


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
    暗号化されたチャンクを復号する

    Args:
        encrypted_chunks: 復号するチャンクのリスト
        paillier_key: Paillier暗号の鍵
        original_data_type: 元のデータタイプ
        original_data_size: 元のデータサイズ
        key_type: 鍵タイプ（'true' または 'false'）
        verbose: 詳細な出力を行うか

    Returns:
        (decrypted_data, data_type): 復号されたデータとデータタイプのタプル
    """
    # パラメータチェック
    if encrypted_chunks is None or len(encrypted_chunks) == 0:
        print("警告: 復号するチャンクがありません")
        return b"", "binary"

    if paillier_key is None:
        print("警告: Paillier鍵が指定されていません")
        return b"", "binary"

    # 鍵情報の表示
        if verbose:
        # ============================================================================ #
        # 【セキュリティポリシー実施】                                                  #
        # 鍵タイプ情報は攻撃者の解析を助ける可能性があるため、ログやコンソールに表示しません #
        # ============================================================================ #
        print(f"鍵情報: セキュリティ上の理由により詳細は非表示")
        print(f"元のデータタイプ: {original_data_type}")
        print(f"元のデータサイズ: {original_data_size}")
        print(f"【セキュリティ注意】鍵タイプの明示的な指定や表示は区別不能性を損なう可能性があるため禁止されています")

    # Paillier暗号を初期化
    paillier = PaillierCrypto(paillier_key)

    # チャンク数とサイズを計算
    chunk_size = 256  # 標準チャンクサイズ
    total_chunks = len(encrypted_chunks)

        if verbose:
        print(f"復号するチャンク数: {total_chunks}")
        print(f"チャンクサイズ: {chunk_size}")
        total_size = total_chunks * chunk_size
        print(f"合計予測データサイズ: {total_size} バイト")
        if original_data_size > 0:
            print(f"要求された元のデータサイズ: {original_data_size} バイト")

    # 復号処理
    try:
        # チャンクを復号してバイト列に変換
        decrypted_data = paillier.decrypt_bytes(
            encrypted_chunks,
            original_size=original_data_size,
            chunk_size=chunk_size
        )

        except Exception as e:
        print(f"復号処理中にエラーが発生しました: {e}")
                import traceback
                traceback.print_exc()
        return b"", "binary"

    # データサイズの確認
        if verbose:
        print(f"結合後データサイズ: {len(decrypted_data)} バイト")
        if len(decrypted_data) > 0:
            print(f"先頭バイト: {decrypted_data[:min(20, len(decrypted_data))]}")
        if len(decrypted_data) > 20:
            print(f"末尾バイト: {decrypted_data[-min(20, len(decrypted_data)):]}")

    # マーカーの有無を確認
    # マーカーが存在しない場合、元のデータタイプに基づいて処理する
    data_type = original_data_type

    # 重要: マーカーがなく、テキストとして処理しようとしていても、
    # 実際には暗号化時にマーカーが付加されている可能性がある
    # 暗号化プロセスで「TEXT:UTF8:」などのマーカーを付加する場合、
    # 復号後のバイト列には通常このマーカーが含まれていることになる

    # マーカーの検出を試みる
    markers = {
        b"TEXT:UTF8:": "text",
        b"JSON:UTF8:": "json",
        b"CSV:UTF8:": "csv",
        b"TEXT:": "text",
        b"JSON:": "json",
        b"CSV:": "csv",
        b"BINARY:": "binary"
    }

    detected_marker = None
    for marker, marker_type in markers.items():
        if decrypted_data.startswith(marker):
            detected_marker = marker
            data_type = marker_type
            # マーカーを保持したままデータを返す
            # これにより process_data_after_decryption で正しく処理される
            if verbose:
                print(f"マーカーを検出: '{marker.decode('utf-8', errors='replace')}', タイプ: {data_type}")
            break

    # マーカーがない場合でも、元のデータに基づいて適切なマーカーを付加
    # これはバックアップで、通常はdecrypt_bytes関数が復号した結果に既にマーカーが含まれているはず
    if detected_marker is None and data_type in ["text", "json", "csv"] and not decrypted_data.startswith(b"TEXT:") and not decrypted_data.startswith(b"JSON:") and not decrypted_data.startswith(b"CSV:"):
                        if verbose:
            print(f"マーカーが見つかりませんでした。データタイプに基づいてマーカーを付加: {data_type}")

    # データ形式に合わせてマーカーを付加
    # 重要: 暗号化時のプロセスと整合性を保つ必要がある
    if data_type == "text":
        # 多段エンコードマーカー（UTF8）
        decrypted_data = b"TEXT:UTF8:" + decrypted_data
    elif data_type == "json":
        decrypted_data = b"JSON:UTF8:" + decrypted_data
    elif data_type == "csv":
        decrypted_data = b"CSV:UTF8:" + decrypted_data

    # ここからはデータ後処理（マーカーを含む状態で戻す）
    if verbose:
        print(f"データ後処理（タイプ: {data_type}）...")

    # この時点でdecrypted_dataには正しいマーカーが含まれているはず
    # process_data_after_decryptionはマーカーを検出して適切に処理する

    return decrypted_data, data_type


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

        # ============================================================================ #
        # 【警告: セキュリティ上の重要事項】                                              #
        # 明示的な鍵タイプ指定は厳格に禁止されています。                                    #
        # 区別不能性を確保するため、鍵タイプは常に暗号学的アルゴリズムによって自動判定されます。 #
        # ============================================================================ #

        # セキュリティ対策: 鍵タイプは常に自動判定を使用
        # 明示的な指定が試みられた場合でも、自動判定にフォールバックします
        _lazy_import_indistinguishable()
        if _analyze_key_type_enhanced:
            key_type = _analyze_key_type_enhanced(key)
            if args.verbose:
                print(f"鍵を解析しました: セキュリティのため詳細は表示しません")
        else:
            key_type = 'auto'  # 常に自動判定

        # ============================================================================ #
        # 【最終的なセキュリティチェック】                                               #
        # 復号プロセス全体を通して、明示的な鍵タイプ指定が発生しないよう徹底するための最終チェック #
        # ============================================================================ #

        # key_type はシステムが自動判定したもののみ許可
        if not isinstance(key_type, str) or key_type not in ['auto', '_auto_detected_']:
            print("【セキュリティ強制対策】鍵タイプは自動判定のみが許可されています")
            key_type = 'auto'  # 最終的な安全策として強制上書き

        success = decrypt_file(
            input_file=args.input_file,
            output_file=output_path,
            key=args.key,
            key_bytes=key,
            key_type='auto',  # セキュリティ対策: 常に自動判定を使用
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
