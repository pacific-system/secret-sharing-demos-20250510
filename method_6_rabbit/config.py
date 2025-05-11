#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ラビット暗号化方式の設定ファイル
"""

# ラビットストリーム暗号の設定パラメータ
RABBIT_IV_SIZE = 8  # 初期化ベクトルサイズ（バイト）
RABBIT_KEY_SIZE = 16  # 鍵サイズ（バイト）
RABBIT_STATE_WORDS = 8  # 内部状態のワード数
RABBIT_COUNTER_WORDS = 4  # カウンタのワード数
RABBIT_ROUNDS = 4  # 各更新での反復回数

# 多重鍵パス設定
TRUE_KEY_MARKER = 0xA5  # 正規鍵マーカー（内部識別用）
FALSE_KEY_MARKER = 0x5A  # 非正規鍵マーカー（内部識別用）
STREAM_SELECTOR_SEED = 0x42  # ストリーム選択シード値

# ファイルパス設定
TRUE_FILE_PATH = "../../common/true-false-text/true.text"
FALSE_FILE_PATH = "../../common/true-false-text/false.text"
ENCRYPTED_FILE_PATH = "encrypted.bin"  # 暗号化ファイルの出力パス
DECRYPTED_FILE_PATH = "decrypted.text"  # 復号ファイルの出力パス

# 暗号化設定
ENCRYPT_CHUNK_SIZE = 1024  # 一度に暗号化するチャンクサイズ（バイト）
DECRYPT_CHUNK_SIZE = 1024  # 一度に復号するチャンクサイズ（バイト）

# デバッグ設定
DEBUG_MODE = False  # デバッグモード（True/False）

# セキュリティ設定
SECURE_MEMORY_WIPE = True  # メモリから機密データを消去するかどうか
KEY_DERIVATION_ITERATIONS = 10000  # 鍵導出関数の反復回数

# 特殊なマジック値（識別不能性のためにランダムに見える値を使用）
# これらの値は解析を困難にするために選定されています
MAGIC_VALUE_1 = 0x7A6B5C4D3E2F1011  # マジック値1（ビット分布が均一）
MAGIC_VALUE_2 = 0x1F2E3D4C5B6A7988  # マジック値2（マジック値1と補数関係）
MAGIC_XOR_VALUE = 0x123456789ABCDEF0  # XOR操作のためのマジック値

# バージョン情報
VERSION = "1.0.0"
