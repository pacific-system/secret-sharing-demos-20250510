#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の設定モジュール

このモジュールは、準同型暗号マスキング方式に関連する設定定数を提供します。
"""

import os
import sys
from typing import Dict, List, Any, Tuple

# プロジェクトのルートパスを取得
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# true/falseテキストパス
TRUE_TEXT_PATH = os.path.join(PROJECT_ROOT, 'common', 'true-false-text', 't.text')
FALSE_TEXT_PATH = os.path.join(PROJECT_ROOT, 'common', 'true-false-text', 'f.text')

# 鍵関連の定数
KEY_SIZE_BYTES = 32  # 256ビット鍵
SALT_SIZE = 32  # ソルトサイズ（バイト）

# 準同型暗号関連の定数
PAILLIER_KEY_BITS = 1024  # Paillier鍵長
MAX_CHUNK_SIZE = 256  # 最大チャンクサイズ（バイト）
CHUNK_OVERHEAD = 2  # チャンク処理オーバーヘッド
DEFAULT_PRECISION = 3  # デフォルトの小数点以下桁数
PAILLIER_PRECISION = 3  # Paillier暗号の小数点以下桁数

# 出力フォーマット
OUTPUT_FORMAT = 'json'  # 出力形式（json, binary, base64）

# テスト設定
TEST_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'test_output')

# 詳細ログ出力モード
VERBOSE_MODE = False  # デバッグ情報の詳細表示フラグ

# ファイルパス設定
# プロジェクトルートからの相対パス
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TRUE_TEXT_PATH = os.path.join(PROJECT_ROOT, 'common', 'true-false-text', 't.text')
FALSE_TEXT_PATH = os.path.join(PROJECT_ROOT, 'common', 'true-false-text', 'f.text')

# 出力設定
OUTPUT_FORMAT = 'json'  # 出力形式（'json'または'binary'）
OUTPUT_EXTENSION = '.enc.json'  # 暗号化ファイルの拡張子

# 暗号化設定
CRYPTO_ALGORITHM = 'paillier'  # 準同型暗号アルゴリズム（'paillier'または'elgamal'）
ELGAMAL_KEY_BITS = 2048  # ElGamal暗号の鍵長（ビット数）
KDF_ITERATIONS = 10000  # 鍵導出関数の反復回数
SECURITY_PARAMETER = 128  # セキュリティパラメータ（ビット数）

# マスク関数設定
MASK_SEED_SIZE = 32  # マスク関数のシードサイズ（バイト数）

# データ処理設定
DEFAULT_CHARSET = 'utf-8'  # デフォルト文字セット

# ロギング設定
LOG_LEVEL = 'INFO'  # ログレベル（'DEBUG'、'INFO'、'WARNING'、'ERROR'、'CRITICAL'）

# テスト設定
TEST_MODE = False  # テストモード（True/False）
DEBUG_MODE = False  # デバッグモード（True/False）

# 多層暗号化設定
MULTI_LAYER_ENCRYPTION = False  # 多層暗号化モード（True/False）
LAYER_COUNT = 3  # 多層暗号化のレイヤー数

# 識別不能性設定
APPLY_INDISTINGUISHABILITY = True  # 識別不能性を適用（True/False）
NOISE_INTENSITY = 0.05  # 統計的ノイズの強度（0.0～1.0）
REDUNDANCY_FACTOR = 1  # 冗長性の係数（1以上、1=冗長性なし）

# プログラム動作設定
VERIFY_ENCRYPTION = True  # 暗号化の検証を行う（True/False）
VERIFY_DECRYPTION = True  # 復号の検証を行う（True/False）
PROGRESS_BAR = True  # 進捗バーを表示する（True/False）

# バックエンド選択
CRYPTO_BACKEND = 'builtin'  # 暗号バックエンド（'builtin'、'pycrypto'、'cryptography'）

# パフォーマンス設定
PARALLEL_PROCESSING = False  # 並列処理を有効にする（True/False）
MAX_THREADS = 4  # 最大スレッド数

def get_config() -> Dict[str, Any]:
    """
    現在の設定を辞書形式で取得

    Returns:
        設定値を含む辞書
    """
    return {
        'TRUE_TEXT_PATH': TRUE_TEXT_PATH,
        'FALSE_TEXT_PATH': FALSE_TEXT_PATH,
        'OUTPUT_FORMAT': OUTPUT_FORMAT,
        'OUTPUT_EXTENSION': OUTPUT_EXTENSION,
        'CRYPTO_ALGORITHM': CRYPTO_ALGORITHM,
        'PAILLIER_KEY_BITS': PAILLIER_KEY_BITS,
        'PAILLIER_PRECISION': PAILLIER_PRECISION,
        'ELGAMAL_KEY_BITS': ELGAMAL_KEY_BITS,
        'KEY_SIZE_BYTES': KEY_SIZE_BYTES,
        'SALT_SIZE': SALT_SIZE,
        'KDF_ITERATIONS': KDF_ITERATIONS,
        'SECURITY_PARAMETER': SECURITY_PARAMETER,
        'MASK_SEED_SIZE': MASK_SEED_SIZE,
        'MAX_CHUNK_SIZE': MAX_CHUNK_SIZE,
        'DEFAULT_CHARSET': DEFAULT_CHARSET,
        'LOG_LEVEL': LOG_LEVEL,
        'TEST_MODE': TEST_MODE,
        'DEBUG_MODE': DEBUG_MODE,
        'MULTI_LAYER_ENCRYPTION': MULTI_LAYER_ENCRYPTION,
        'LAYER_COUNT': LAYER_COUNT,
        'APPLY_INDISTINGUISHABILITY': APPLY_INDISTINGUISHABILITY,
        'NOISE_INTENSITY': NOISE_INTENSITY,
        'REDUNDANCY_FACTOR': REDUNDANCY_FACTOR,
        'VERIFY_ENCRYPTION': VERIFY_ENCRYPTION,
        'VERIFY_DECRYPTION': VERIFY_DECRYPTION,
        'PROGRESS_BAR': PROGRESS_BAR,
        'CRYPTO_BACKEND': CRYPTO_BACKEND,
        'PARALLEL_PROCESSING': PARALLEL_PROCESSING,
        'MAX_THREADS': MAX_THREADS
    }

def get_absolute_path(relative_path):
    """
    相対パスから絶対パスを取得

    Args:
        relative_path: プロジェクトルートからの相対パス

    Returns:
        絶対パス
    """
    return os.path.join(PROJECT_ROOT, relative_path)
