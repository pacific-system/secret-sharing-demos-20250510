#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の設定ファイル

このモジュールは、準同型暗号マスキング方式で使用する各種の設定値を定義します。
"""

# ファイルパス設定
TRUE_TEXT_PATH = "common/true-false-text/true.text"
FALSE_TEXT_PATH = "common/true-false-text/false.text"

# 暗号化パラメータ
KEY_SIZE_BYTES = 32  # 256ビット鍵
PRIME_BITS = 2048    # 準同型暗号の法（素数）のビット長
SALT_SIZE = 16       # ソルトサイズ
MASK_SIZE = 256      # マスクサイズ（ビット）
SECURITY_PARAMETER = 128  # セキュリティパラメータ（ビット）

# 鍵導出パラメータ
KDF_ITERATIONS = 10000  # 鍵導出関数の反復回数

# Paillier準同型暗号パラメータ
PAILLIER_KEY_BITS = 2048  # Paillier鍵サイズ
PAILLIER_PRECISION = 1024 # 準同型演算の精度
FLOAT_PRECISION = 1000000  # 浮動小数点数の精度

# ElGamal準同型暗号パラメータ
ELGAMAL_KEY_BITS = 2048  # ElGamal鍵サイズ

# 出力ファイル形式
OUTPUT_FORMAT = "homomorphic"
OUTPUT_EXTENSION = "txt"

# デバッグフラグ（本番では必ずFalseにする）
DEBUG = False

# 暗号化アルゴリズム選択
# 'paillier' (加法準同型) または 'elgamal' (乗法準同型) または 'hybrid'（両方）
CRYPTO_ALGORITHM = "paillier"

# マスク関数生成用パラメータ
MASK_SEED_SIZE = 32  # マスク生成用シードのサイズ（バイト）
NUM_MASK_FUNCTIONS = 4  # 使用するマスク関数の数
MAX_CHUNK_SIZE = 64  # バイトデータのチャンクサイズ上限
MASK_OUTPUT_FORMAT = "homomorphic_masked"
MASK_VERSION = "1.0"

# チャンク処理設定
MAX_CHUNK_SIZE = 64  # 最大チャンクサイズ（バイト）

# テスト設定
TEST_ITERATIONS = 10  # テスト反復回数
TEST_DATA_SIZE = 1024  # テストデータサイズ（バイト）

# 互換性設定
COMPATIBILITY_MODE = False  # 互換モード（古いバージョンと互換性を持たせる）
LEGACY_SUPPORT = True  # レガシーサポート（古いファイル形式をサポート）

# デバッグ設定
DEBUG_MODE = False  # デバッグモード
