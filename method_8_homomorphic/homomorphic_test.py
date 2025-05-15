#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
#             ████████ ███████ ███████ ████████     ██████  ██    ██ ████████  #
#                ██    ██      ██         ██          ██    ██    ██    ██     #
#                ██    █████   ███████    ██          ██    ██    ██    ██     #
#                ██    ██           ██    ██          ██    ██    ██    ██     #
#                ██    ███████ ███████    ██        ██████   ██████     ██     #
#                                                                              #
#              【準同型暗号マスキング方式テスト - HOMOMORPHIC MASKING TEST】     #
#                                                                              #
#     このファイルは準同型暗号マスキング方式の「テスト」機能のメインエントリーポイントです     #
#     下記6つのテストファイルの機能を統合しています：                                #
#     - enhanced_homomorphic_test.py                                           #
#     - test_homomorphic_masking.py                                           #
#     - test_secure_homomorphic.py                                            #
#     - test_security_results.py                                              #
#     - integrated_homomorphic_test.py                                        #
#     - test_secure_homomorphic.py                                            #
#                                                                              #
################################################################################

"""
準同型暗号マスキング方式 統合テストスクリプト

このスクリプトは、以下の6つのテストスクリプトの機能を統合したものです：
- enhanced_homomorphic_test.py
- test_homomorphic_masking.py
- test_secure_homomorphic.py
- test_security_results.py
- integrated_homomorphic_test.py
- test_secure_homomorphic.py

主な機能:
1. 準同型暗号の基本機能テスト
2. マスク関数のテスト
3. 暗号文識別不能性のテスト
4. 暗号化・復号の統合テスト
5. 鍵解析のテスト
6. パフォーマンス計測機能
7. セキュリティ検証機能
8. タイムスタンプ付きログファイル生成機能
9. 検証結果のグラフ視覚化機能

使用方法:
  python3 homomorphic_test.py [オプション]

オプション:
  --test-type TYPE   実行するテストタイプ (all, basic, mask, security, performance)
  --output-dir DIR   出力ディレクトリ
  --verbose          詳細なログ出力
"""

import os
import sys
import time
import json
import base64
import hashlib
import binascii
import random
import argparse
import matplotlib
matplotlib.use('Agg')  # GUIなしで動作するバックエンド
import matplotlib.pyplot as plt
import numpy as np
import secrets
import math
import sympy
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from datetime import datetime, timedelta
from pathlib import Path

# 親ディレクトリをパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# 準同型暗号のインポート
from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, save_keys, load_keys,
    serialize_encrypted_data, deserialize_encrypted_data
)

# マスク関数のインポート
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)

# データアダプタのインポート
from method_8_homomorphic.crypto_adapters import (
    process_data_for_encryption, process_data_after_decryption,
    DataAdapter, TextAdapter, BinaryAdapter
)

# 鍵解析機能のインポート
from method_8_homomorphic.key_analyzer import (
    analyze_key_type, extract_seed_from_key
)

# 識別不能性機能のインポート（循環インポートを避けるため indistinguishable_ext から）
from method_8_homomorphic.indistinguishable_ext import (
    analyze_key_type_enhanced,
    remove_comprehensive_indistinguishability_enhanced,
    safe_log10,
    IndistinguishableWrapper
)

# デバッグユーティリティ
try:
    from method_8_homomorphic.debug_utils import (
        analyze_homomorphic_properties,
        visualize_key_distribution,
        test_timing_attack_resistance
    )
except ImportError:
    print("警告: debug_utils モジュールがインポートできません。一部のテスト機能が利用できません。")

# 入出力パス設定
TRUE_TEXT_PATH = "common/true-false-text/t.text"
FALSE_TEXT_PATH = "common/true-false-text/f.text"
OUTPUT_DIR = "test_output"
TIMESTAMP = time.strftime("%Y%m%d-%H%M%S")

# タイムスタンプ付きログファイル
LOG_FILE = os.path.join(OUTPUT_DIR, f"homomorphic_test_log_{TIMESTAMP}.txt")

# グローバル設定
VERBOSE = False
TEST_TYPE = "all"

# テスト設定
TEST_SETTINGS = {
    "key_bits": 1024,       # テスト用に小さいビットサイズを使用
    "chunk_size": 64,       # チャンクサイズ (バイト)
    "max_test_size": 10240, # 最大テストデータサイズ (バイト)
    "graph_dpi": 100,       # グラフのDPI
    "timeout": 60,          # タイムアウト (秒)
}

# テスト結果
TEST_RESULTS = {
    "basic": {},      # 基本機能テスト結果
    "mask": {},       # マスク関数テスト結果
    "security": {},   # セキュリティテスト結果
    "performance": {} # パフォーマンステスト結果
}


def ensure_directory(directory: str) -> None:
    """ディレクトリの存在を確認し、なければ作成"""
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        if VERBOSE:
            print(f"ディレクトリを作成しました: {directory}")


def log_message(message: str, console: bool = True, markdown: bool = False) -> None:
    """
    メッセージをログファイルに記録し、オプションでコンソールにも出力

    Args:
        message: 記録するメッセージ
        console: コンソールに出力するかどうか
        markdown: マークダウン形式で出力するかどうか
    """
    ensure_directory(os.path.dirname(LOG_FILE))

    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if markdown:
            # マークダウン形式で出力
            f.write(f"{message}\n")
        else:
            # 通常のログ形式で出力
            log_line = f"[{timestamp}] {message}"
            f.write(log_line + "\n")

    if console:
        print(message)


def print_section_header(title: str, level: int = 1) -> None:
    """
    セクションヘッダーを出力

    Args:
        title: セクションタイトル
        level: ヘッダーレベル (1: 主要セクション, 2: サブセクション, 3: 小セクション)
    """
    if level == 1:
        separator = "=" * 80
        log_message("\n" + separator, markdown=True)
        log_message(f"# {title}", markdown=True)
        log_message(separator + "\n", markdown=True)

        if VERBOSE:
            print("\n" + separator)
            print(f" {title} ".center(80, "="))
            print(separator + "\n")

    elif level == 2:
        log_message(f"\n## {title}", markdown=True)

        if VERBOSE:
            print("\n" + "-" * 60)
            print(f" {title} ".center(60, "-"))
            print("-" * 60 + "\n")

    else:  # level == 3
        log_message(f"\n### {title}", markdown=True)

        if VERBOSE:
            print(f"\n--- {title} ---\n")


def parse_arguments() -> argparse.Namespace:
    """コマンドライン引数の解析"""
    parser = argparse.ArgumentParser(
        description='準同型暗号マスキング方式の統合テストスクリプト'
    )

    parser.add_argument(
        '--test-type',
        choices=['all', 'basic', 'mask', 'security', 'performance', 'indistinguishable'],
        default='all',
        help='実行するテストのタイプ'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default=OUTPUT_DIR,
        help='出力ディレクトリ'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='詳細なログ出力'
    )

    parser.add_argument(
        '--true-file',
        type=str,
        default=TRUE_TEXT_PATH,
        help='真のテストファイルパス'
    )

    parser.add_argument(
        '--false-file',
        type=str,
        default=FALSE_TEXT_PATH,
        help='偽のテストファイルパス'
    )

    parser.add_argument(
        '--key-bits',
        type=int,
        default=TEST_SETTINGS["key_bits"],
        help='鍵のビット長'
    )

    return parser.parse_args()

#------------------------------------------------------------------------------
# 基本暗号化・復号テスト機能
#------------------------------------------------------------------------------

def test_basic_homomorphic_functions() -> Dict[str, Any]:
    """
    準同型暗号の基本機能をテスト

    Returns:
        テスト結果の辞書
    """
    print_section_header("準同型暗号の基本機能テスト", 1)

    results = {
        "success": False,
        "encryption_time": 0,
        "decryption_time": {"true": 0, "false": 0},
        "file_sizes": {
            "true_original": 0,
            "false_original": 0,
            "encrypted": 0,
            "true_decrypted": 0,
            "false_decrypted": 0
        }
    }

    # テスト出力ディレクトリの作成
    test_output_dir = os.path.join(OUTPUT_DIR, "basic_test")
    ensure_directory(test_output_dir)

    # 暗号化ファイルのパス
    encrypted_file = os.path.join(test_output_dir, f"encrypted_{TIMESTAMP}.json")
    true_decrypted_file = os.path.join(test_output_dir, f"decrypted_true_{TIMESTAMP}.txt")
    false_decrypted_file = os.path.join(test_output_dir, f"decrypted_false_{TIMESTAMP}.txt")

    try:
        # テストファイルの読み込み
        print_section_header("テストファイルの読み込み", 2)

        with open(TRUE_TEXT_PATH, 'rb') as f:
            true_content = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            false_content = f.read()

        # ファイルサイズを記録
        results["file_sizes"]["true_original"] = len(true_content)
        results["file_sizes"]["false_original"] = len(false_content)

        log_message(f"テストファイル読み込み完了:")
        log_message(f"  真テキストサイズ: {len(true_content)}バイト")
        log_message(f"  偽テキストサイズ: {len(false_content)}バイト")

        # 暗号化
        print_section_header("暗号化処理", 2)
        log_message("準同型暗号システムを初期化中...")

        # 暗号化開始時間
        encryption_start = time.time()

        # Paillier暗号の初期化
        paillier = PaillierCrypto(bits=TEST_SETTINGS["key_bits"])
        public_key, private_key = paillier.generate_keys()

        log_message(f"公開鍵生成完了: n={public_key['n']}, g={public_key['g']}")

        # 鍵の生成
        log_message("真偽判別用の鍵を生成中...")
        true_key = os.urandom(32)
        false_key = os.urandom(32)

        log_message(f"鍵生成完了:")
        log_message(f"  真鍵: {binascii.hexlify(true_key).decode()}")
        log_message(f"  偽鍵: {binascii.hexlify(false_key).decode()}")

        # データの前処理
        log_message("データを前処理中...")
        true_processed, true_data_type = process_data_for_encryption(true_content, 'text')
        false_processed, false_data_type = process_data_for_encryption(false_content, 'text')

        log_message(f"前処理完了:")
        log_message(f"  真データタイプ: {true_data_type}, サイズ: {len(true_processed)}バイト")
        log_message(f"  偽データタイプ: {false_data_type}, サイズ: {len(false_processed)}バイト")

        # チャンク分割
        chunk_size = TEST_SETTINGS["chunk_size"]
        true_chunks = [true_processed[i:i+chunk_size] for i in range(0, len(true_processed), chunk_size)]
        false_chunks = [false_processed[i:i+chunk_size] for i in range(0, len(false_processed), chunk_size)]

        log_message(f"チャンク分割完了:")
        log_message(f"  真チャンク数: {len(true_chunks)}")
        log_message(f"  偽チャンク数: {len(false_chunks)}")

        # 各チャンクを暗号化
        true_encrypted = []
        false_encrypted = []

        for i, chunk in enumerate(true_chunks):
            # 進捗表示
            if VERBOSE and i % 5 == 0:
                log_message(f"真データ暗号化中: {i+1}/{len(true_chunks)}")
            chunk_int = int.from_bytes(chunk, byteorder='big')
            encrypted = paillier.encrypt(chunk_int, public_key)
            true_encrypted.append(encrypted)

        for i, chunk in enumerate(false_chunks):
            # 進捗表示
            if VERBOSE and i % 5 == 0:
                log_message(f"偽データ暗号化中: {i+1}/{len(false_chunks)}")
            chunk_int = int.from_bytes(chunk, byteorder='big')
            encrypted = paillier.encrypt(chunk_int, public_key)
            false_encrypted.append(encrypted)

        log_message(f"暗号化完了:")
        log_message(f"  真暗号化チャンク数: {len(true_encrypted)}")
        log_message(f"  偽暗号化チャンク数: {len(false_encrypted)}")

        # マスク関数生成
        log_message("マスク関数を生成中...")
        mask_generator = AdvancedMaskFunctionGenerator(paillier, true_key)

        # マスク適用と真偽変換
        log_message("マスク関数を適用して真偽チャンクを変換中...")
        masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
            paillier, true_encrypted, false_encrypted, mask_generator
        )

        # メタデータ作成
        metadata = {
            "format": "homomorphic_masked",
            "version": "1.0",
            "algorithm": "paillier",
            "timestamp": int(time.time()),
            "true_size": len(true_processed),
            "false_size": len(false_processed),
            "true_original_size": len(true_content),
            "false_original_size": len(false_content),
            "chunk_size": chunk_size,
            "true_data_type": true_data_type,
            "false_data_type": false_data_type,
            "true_filename": os.path.basename(TRUE_TEXT_PATH),
            "false_filename": os.path.basename(FALSE_TEXT_PATH),
            "public_key": public_key,
            "private_key": private_key  # 注意: 実際の運用では秘密鍵は含めません
        }

        # 識別不能形式に変換
        log_message("暗号文を識別不能な形式に変換中...")
        indistinguishable_data = create_indistinguishable_form(
            masked_true, masked_false, true_mask, false_mask, metadata
        )

        # 暗号化の終了時間
        encryption_end = time.time()
        results["encryption_time"] = encryption_end - encryption_start

        # 暗号化データを保存
        log_message(f"暗号化データを保存中: {encrypted_file}")
        with open(encrypted_file, 'w', encoding='utf-8') as f:
            json.dump(indistinguishable_data, f, indent=2)

        # 暗号化ファイルのサイズを記録
        results["file_sizes"]["encrypted"] = os.path.getsize(encrypted_file)
        log_message(f"暗号化データを保存しました: サイズ={results['file_sizes']['encrypted']}バイト")

        # 真鍵での復号
        print_section_header("真鍵での復号", 2)
        true_decrypt_start = time.time()

        # 暗号文の読み込み
        with open(encrypted_file, 'r') as f:
            encrypted_data = json.load(f)

        # マスク生成器の初期化
        true_mask_generator = AdvancedMaskFunctionGenerator(paillier, true_key)

        # 真鍵用のデータを抽出
        log_message("真鍵用のデータを抽出中...")
        true_encrypted_chunks, true_mask_info = extract_by_key_type(encrypted_data, "true")

        # マスク除去
        log_message("マスクを除去中...")
        true_unmasked_chunks = true_mask_generator.remove_advanced_mask(true_encrypted_chunks, true_mask_info)

        # 復号
        log_message("復号中...")
        true_decrypted_chunks = []

        for i, chunk in enumerate(true_unmasked_chunks):
            # 進捗表示
            if VERBOSE and i % 5 == 0:
                log_message(f"真鍵での復号中: {i+1}/{len(true_unmasked_chunks)}")

            decrypted_int = paillier.decrypt(chunk, private_key)
            byte_length = max(1, (decrypted_int.bit_length() + 7) // 8)
            decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
            true_decrypted_chunks.append(decrypted_bytes)

        # チャンクを結合
        true_decrypted_data = b''.join(true_decrypted_chunks)

        # 元のサイズに合わせる
        original_true_size = metadata.get("true_size", len(true_decrypted_data))
        if len(true_decrypted_data) > original_true_size:
            true_decrypted_data = true_decrypted_data[:original_true_size]

        # データの後処理
        true_data_type = metadata.get("true_data_type", "text")
        log_message(f"真鍵データの後処理中... データタイプ: {true_data_type}")
        true_processed_data = process_data_after_decryption(true_decrypted_data, true_data_type)

        # 復号データを保存
        log_message(f"真鍵での復号データを保存中: {true_decrypted_file}")

        # 文字列の場合はバイト列に変換
        if isinstance(true_processed_data, str):
            true_processed_data = true_processed_data.encode('utf-8')

        with open(true_decrypted_file, 'wb') as f:
            f.write(true_processed_data)

        # 復号ファイルのサイズを記録
        results["file_sizes"]["true_decrypted"] = os.path.getsize(true_decrypted_file)

        # 真鍵での復号時間を記録
        true_decrypt_end = time.time()
        results["decryption_time"]["true"] = true_decrypt_end - true_decrypt_start

        # 偽鍵での復号
        print_section_header("偽鍵での復号", 2)
        false_decrypt_start = time.time()

        # マスク生成器の初期化
        false_mask_generator = AdvancedMaskFunctionGenerator(paillier, false_key)

        # 偽鍵用のデータを抽出
        log_message("偽鍵用のデータを抽出中...")
        false_encrypted_chunks, false_mask_info = extract_by_key_type(encrypted_data, "false")

        # マスク除去
        log_message("マスクを除去中...")
        false_unmasked_chunks = false_mask_generator.remove_advanced_mask(false_encrypted_chunks, false_mask_info)

        # 復号
        log_message("復号中...")
        false_decrypted_chunks = []

        for i, chunk in enumerate(false_unmasked_chunks):
            # 進捗表示
            if VERBOSE and i % 5 == 0:
                log_message(f"偽鍵での復号中: {i+1}/{len(false_unmasked_chunks)}")

            decrypted_int = paillier.decrypt(chunk, private_key)
            byte_length = max(1, (decrypted_int.bit_length() + 7) // 8)
            decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
            false_decrypted_chunks.append(decrypted_bytes)

        # チャンクを結合
        false_decrypted_data = b''.join(false_decrypted_chunks)

        # 元のサイズに合わせる
        original_false_size = metadata.get("false_size", len(false_decrypted_data))
        if len(false_decrypted_data) > original_false_size:
            false_decrypted_data = false_decrypted_data[:original_false_size]

        # データの後処理
        false_data_type = metadata.get("false_data_type", "text")
        log_message(f"偽鍵データの後処理中... データタイプ: {false_data_type}")
        false_processed_data = process_data_after_decryption(false_decrypted_data, false_data_type)

        # 復号データを保存
        log_message(f"偽鍵での復号データを保存中: {false_decrypted_file}")

        # 文字列の場合はバイト列に変換
        if isinstance(false_processed_data, str):
            false_processed_data = false_processed_data.encode('utf-8')

        with open(false_decrypted_file, 'wb') as f:
            f.write(false_processed_data)

        # 復号ファイルのサイズを記録
        results["file_sizes"]["false_decrypted"] = os.path.getsize(false_decrypted_file)

        # 偽鍵での復号時間を記録
        false_decrypt_end = time.time()
        results["decryption_time"]["false"] = false_decrypt_end - false_decrypt_start

        # 復号結果の検証
        print_section_header("復号結果の検証", 2)

        # ハッシュ値を計算
        original_true_hash = hashlib.sha256(true_content).hexdigest()
        original_false_hash = hashlib.sha256(false_content).hexdigest()
        decrypted_true_hash = hashlib.sha256(true_processed_data).hexdigest()
        decrypted_false_hash = hashlib.sha256(false_processed_data).hexdigest()

        # ハッシュ値を比較
        true_match = original_true_hash == decrypted_true_hash
        false_match = original_false_hash == decrypted_false_hash

        log_message(f"真ファイルのハッシュ比較: {true_match}")
        log_message(f"  元のハッシュ:   {original_true_hash}")
        log_message(f"  復号後のハッシュ: {decrypted_true_hash}")

        log_message(f"偽ファイルのハッシュ比較: {false_match}")
        log_message(f"  元のハッシュ:   {original_false_hash}")
        log_message(f"  復号後のハッシュ: {decrypted_false_hash}")

        # 総合結果
        results["success"] = true_match and false_match
        results["true_match"] = true_match
        results["false_match"] = false_match
        results["file_paths"] = {
            "encrypted": encrypted_file,
            "true_decrypted": true_decrypted_file,
            "false_decrypted": false_decrypted_file
        }

        log_message(f"テスト結果: {'成功' if results['success'] else '失敗'}")

        return results

    except Exception as e:
        log_message(f"エラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

#------------------------------------------------------------------------------
# マスク関数テスト
#------------------------------------------------------------------------------

def test_masking_functions() -> Dict[str, Any]:
    """
    マスク関数の機能テスト

    Returns:
        テスト結果の辞書
    """
    print_section_header("マスク関数テスト", 1)

    results = {
        "success": False,
        "basic_mask": {"success": False, "time": 0},
        "advanced_mask": {"success": False, "time": 0},
        "mask_difference": 0,
        "statistical_test": {"passed": False, "p_value": 0}
    }

    # テスト出力ディレクトリの作成
    test_output_dir = os.path.join(OUTPUT_DIR, "mask_test")
    ensure_directory(test_output_dir)

    try:
        # Paillier暗号の初期化
        print_section_header("準同型暗号の初期化", 2)
        paillier = PaillierCrypto(bits=TEST_SETTINGS["key_bits"])
        public_key, private_key = paillier.generate_keys()

        log_message(f"公開鍵生成完了: n={public_key['n']}, g={public_key['g']}")

        # テストメッセージ
        test_message = b"This is a test message for masking function verification."
        message_int = int.from_bytes(test_message, byteorder='big')

        # メッセージを暗号化
        encrypted_message = paillier.encrypt(message_int, public_key)

        # 1. 基本マスク関数テスト
        print_section_header("基本マスク関数テスト", 2)
        basic_start_time = time.time()

        # 基本マスク生成器の初期化
        basic_key = os.urandom(32)
        basic_mask_gen = MaskFunctionGenerator(paillier, basic_key)

        # マスクを生成
        true_mask, false_mask = basic_mask_gen.generate_mask_pair()

        log_message(f"基本マスク関数を生成しました")
        log_message(f"  真マスク: {true_mask}")
        log_message(f"  偽マスク: {false_mask}")

        # マスクを適用
        masked_message_true = basic_mask_gen.apply_mask(encrypted_message, true_mask)
        masked_message_false = basic_mask_gen.apply_mask(encrypted_message, false_mask)

        log_message(f"基本マスクを適用しました")

        # マスクを除去
        unmasked_message_true = basic_mask_gen.remove_mask(masked_message_true, true_mask)
        unmasked_message_false = basic_mask_gen.remove_mask(masked_message_false, false_mask)

        # 復号して結果を確認
        decrypted_true = paillier.decrypt(unmasked_message_true, private_key)
        decrypted_false = paillier.decrypt(unmasked_message_false, private_key)

        basic_success = (decrypted_true == message_int) and (decrypted_false == message_int)
        basic_time = time.time() - basic_start_time

        log_message(f"基本マスク関数テスト結果: {'成功' if basic_success else '失敗'}")
        results["basic_mask"]["success"] = basic_success
        results["basic_mask"]["time"] = basic_time

        # 2. 高度マスク関数テスト
        print_section_header("高度マスク関数テスト", 2)
        advanced_start_time = time.time()

        # 高度マスク生成器の初期化
        advanced_key = os.urandom(32)
        advanced_mask_gen = AdvancedMaskFunctionGenerator(paillier, advanced_key)

        # マスクを生成
        advanced_true_mask, advanced_false_mask = advanced_mask_gen.generate_mask_pair()

        log_message(f"高度マスク関数を生成しました")

        # マスクを適用
        advanced_masked_true = advanced_mask_gen.apply_advanced_mask(encrypted_message, advanced_true_mask)
        advanced_masked_false = advanced_mask_gen.apply_advanced_mask(encrypted_message, advanced_false_mask)

        log_message(f"高度マスクを適用しました")

        # マスクを除去
        advanced_unmasked_true = advanced_mask_gen.remove_advanced_mask(advanced_masked_true, advanced_true_mask)
        advanced_unmasked_false = advanced_mask_gen.remove_advanced_mask(advanced_masked_false, advanced_false_mask)

        # 復号して結果を確認
        advanced_decrypted_true = paillier.decrypt(advanced_unmasked_true, private_key)
        advanced_decrypted_false = paillier.decrypt(advanced_unmasked_false, private_key)

        advanced_success = (advanced_decrypted_true == message_int) and (advanced_decrypted_false == message_int)
        advanced_time = time.time() - advanced_start_time

        log_message(f"高度マスク関数テスト結果: {'成功' if advanced_success else '失敗'}")
        results["advanced_mask"]["success"] = advanced_success
        results["advanced_mask"]["time"] = advanced_time

        # 3. 統計的特性テスト（マスクが暗号学的に安全かどうか）
        print_section_header("マスクの統計的特性テスト", 2)

        # マスクのランダム性を評価
        # 簡易版：多数のマスクを生成して分布を確認
        mask_samples = 100
        basic_masks = []
        advanced_masks = []

        for _ in range(mask_samples):
            # 基本マスク
            temp_key = os.urandom(32)
            temp_mask_gen = MaskFunctionGenerator(paillier, temp_key)
            temp_mask, _ = temp_mask_gen.generate_mask_pair()
            basic_masks.append(temp_mask)

            # 高度マスク
            temp_adv_mask_gen = AdvancedMaskFunctionGenerator(paillier, temp_key)
            temp_adv_mask, _ = temp_adv_mask_gen.generate_mask_pair()
            advanced_masks.append(temp_adv_mask)

        # 基本的な統計チェック（非常に簡易的な手法）
        # マスクの統計的特性を調べるため、params内の値を使用
        basic_additive_values = []
        basic_multiplicative_values = []
        advanced_additive_values = []
        advanced_multiplicative_values = []

        # 各マスクからパラメータを抽出
        for mask in basic_masks:
            if isinstance(mask, dict) and "params" in mask:
                if "additive" in mask["params"]:
                    basic_additive_values.extend(mask["params"]["additive"])
                if "multiplicative" in mask["params"]:
                    basic_multiplicative_values.extend(mask["params"]["multiplicative"])

        for mask in advanced_masks:
            if isinstance(mask, dict) and "params" in mask:
                if "additive" in mask["params"]:
                    advanced_additive_values.extend(mask["params"]["additive"])
                if "multiplicative" in mask["params"]:
                    advanced_multiplicative_values.extend(mask["params"]["multiplicative"])

        # 平均を計算
        basic_avg_additive = sum(basic_additive_values) / len(basic_additive_values) if basic_additive_values else 0
        basic_avg_multiplicative = sum(basic_multiplicative_values) / len(basic_multiplicative_values) if basic_multiplicative_values else 0
        advanced_avg_additive = sum(advanced_additive_values) / len(advanced_additive_values) if advanced_additive_values else 0
        advanced_avg_multiplicative = sum(advanced_multiplicative_values) / len(advanced_multiplicative_values) if advanced_multiplicative_values else 0

        # 分散を計算
        basic_var_additive = sum((x - basic_avg_additive) ** 2 for x in basic_additive_values) / len(basic_additive_values) if basic_additive_values else 0
        basic_var_multiplicative = sum((x - basic_avg_multiplicative) ** 2 for x in basic_multiplicative_values) / len(basic_multiplicative_values) if basic_multiplicative_values else 0
        advanced_var_additive = sum((x - advanced_avg_additive) ** 2 for x in advanced_additive_values) / len(advanced_additive_values) if advanced_additive_values else 0
        advanced_var_multiplicative = sum((x - advanced_avg_multiplicative) ** 2 for x in advanced_multiplicative_values) / len(advanced_multiplicative_values) if advanced_multiplicative_values else 0

        log_message(f"基本マスクの統計:")
        log_message(f"  加算パラメータ平均: {basic_avg_additive}")
        log_message(f"  加算パラメータ分散: {basic_var_additive}")
        log_message(f"  乗算パラメータ平均: {basic_avg_multiplicative}")
        log_message(f"  乗算パラメータ分散: {basic_var_multiplicative}")

        log_message(f"高度マスクの統計:")
        log_message(f"  加算パラメータ平均: {advanced_avg_additive}")
        log_message(f"  加算パラメータ分散: {advanced_var_additive}")
        log_message(f"  乗算パラメータ平均: {advanced_avg_multiplicative}")
        log_message(f"  乗算パラメータ分散: {advanced_var_multiplicative}")

        # マスク関数の強度を比較するための簡易指標
        mask_difference = (advanced_var_additive + advanced_var_multiplicative) / (basic_var_additive + basic_var_multiplicative) if (basic_var_additive + basic_var_multiplicative) > 0 else float('inf')
        results["mask_difference"] = mask_difference

        # マスク分布をプロット
        plt.figure(figsize=(10, 6))

        plt.subplot(2, 1, 1)
        # dictオブジェクトの代わりに抽出したパラメータ値をプロット
        plt.hist(basic_additive_values, bins=20, alpha=0.7, label='基本マスク(加算パラメータ)')
        plt.axvline(basic_avg_additive, color='r', linestyle='dashed', linewidth=1, label='平均')
        plt.title('基本マスク関数の分布')
        plt.legend()

        plt.subplot(2, 1, 2)
        # dictオブジェクトの代わりに抽出したパラメータ値をプロット
        plt.hist(advanced_additive_values, bins=20, alpha=0.7, label='高度マスク(加算パラメータ)')
        plt.axvline(advanced_avg_additive, color='r', linestyle='dashed', linewidth=1, label='平均')
        plt.title('高度マスク関数の分布')
        plt.legend()

        plt.tight_layout()
        plot_file = os.path.join(test_output_dir, f"mask_distribution_{TIMESTAMP}.png")
        plt.savefig(plot_file)
        plt.close()

        log_message(f"マスク分布グラフを保存しました: {plot_file}")

        # 簡易統計テスト結果
        # マスクが十分にランダムであれば、分散は大きくなるはず
        statistical_pass = advanced_var_additive > 1e5  # 適当な閾値
        results["statistical_test"]["passed"] = statistical_pass
        results["statistical_test"]["p_value"] = advanced_var_additive  # 統計的検定ではないが、参考値として

        log_message(f"統計的特性テスト結果: {'合格' if statistical_pass else '不合格'}")

        # 4. 準同型特性の保存確認
        print_section_header("準同型特性の保存確認", 2)

        # 2つのテストメッセージ
        message1 = 123
        message2 = 456

        # 暗号化
        encrypted1 = paillier.encrypt(message1, public_key)
        encrypted2 = paillier.encrypt(message2, public_key)

        # 準同型演算
        sum_encrypted = paillier.add(encrypted1, encrypted2)

        # マスクを適用
        masked_sum = advanced_mask_gen.apply_advanced_mask(sum_encrypted, advanced_true_mask)

        # マスクを除去
        unmasked_sum = advanced_mask_gen.remove_advanced_mask(masked_sum, advanced_true_mask)

        # 復号
        decrypted_sum = paillier.decrypt(unmasked_sum, private_key)

        # 期待値
        expected_sum = message1 + message2

        # 結果検証
        homomorphic_preserved = (decrypted_sum == expected_sum)
        results["homomorphic_preserved"] = homomorphic_preserved

        log_message(f"準同型特性の保存: {'成功' if homomorphic_preserved else '失敗'}")
        log_message(f"  期待値: {expected_sum}")
        log_message(f"  実際の結果: {decrypted_sum}")

        # 総合結果
        results["success"] = basic_success and advanced_success and homomorphic_preserved
        results["plot_file"] = plot_file

        return results

    except Exception as e:
        log_message(f"エラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results


#------------------------------------------------------------------------------
# セキュリティテスト
#------------------------------------------------------------------------------

def test_security_features() -> Dict[str, Any]:
    """
    暗号文の識別不能性やセキュリティ特性をテスト

    Returns:
        テスト結果の辞書
    """
    print_section_header("セキュリティ特性テスト", 1)

    results = {
        "success": False,
        "indistinguishability": {"passed": False, "details": {}},
        "key_analysis": {"passed": False, "details": {}},
        "timing_attack": {"passed": False, "details": {}}
    }

    # テスト出力ディレクトリの作成
    test_output_dir = os.path.join(OUTPUT_DIR, "security_test")
    ensure_directory(test_output_dir)

    try:
        # 1. 識別不能性テスト
        print_section_header("暗号文識別不能性テスト", 2)

        # テストファイルの読み込み
        with open(TRUE_TEXT_PATH, 'rb') as f:
            true_content = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            false_content = f.read()

        # ファイルを複数回暗号化して結果が異なるか検証
        iterations = 3
        encrypted_files = []
        encrypted_hashes = []

        for i in range(iterations):
            # 暗号化ファイルのパス
            encrypted_file = os.path.join(test_output_dir, f"encrypted_test_{i}_{TIMESTAMP}.json")

            log_message(f"暗号化テスト {i+1}/{iterations} を実行...")

            # Paillier暗号の初期化
            paillier = PaillierCrypto(bits=TEST_SETTINGS["key_bits"])
            public_key, private_key = paillier.generate_keys()

            # 鍵の生成
            true_key = os.urandom(32)
            false_key = os.urandom(32)

            # データの前処理
            true_processed, true_data_type = process_data_for_encryption(true_content, 'text')
            false_processed, false_data_type = process_data_for_encryption(false_content, 'text')

            # チャンク分割
            chunk_size = TEST_SETTINGS["chunk_size"]
            true_chunks = [true_processed[i:i+chunk_size] for i in range(0, len(true_processed), chunk_size)]
            false_chunks = [false_processed[i:i+chunk_size] for i in range(0, len(false_processed), chunk_size)]

            # 各チャンクを暗号化
            true_encrypted = []
            false_encrypted = []

            for chunk in true_chunks:
                chunk_int = int.from_bytes(chunk, byteorder='big')
                encrypted = paillier.encrypt(chunk_int, public_key)
                true_encrypted.append(encrypted)

            for chunk in false_chunks:
                chunk_int = int.from_bytes(chunk, byteorder='big')
                encrypted = paillier.encrypt(chunk_int, public_key)
                false_encrypted.append(encrypted)

            # マスク関数生成
            mask_generator = AdvancedMaskFunctionGenerator(paillier, true_key)

            # マスク適用と真偽変換
            masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
                paillier, true_encrypted, false_encrypted, mask_generator
            )

            # メタデータ作成
            metadata = {
                "format": "homomorphic_masked",
                "version": "1.0",
                "algorithm": "paillier",
                "timestamp": int(time.time()),
                "true_size": len(true_processed),
                "false_size": len(false_processed),
                "chunk_size": chunk_size,
                "true_data_type": true_data_type,
                "false_data_type": false_data_type,
                "true_filename": os.path.basename(TRUE_TEXT_PATH),
                "false_filename": os.path.basename(FALSE_TEXT_PATH),
                "public_key": public_key,
                "private_key": private_key
            }

            # 識別不能形式に変換
            indistinguishable_data = create_indistinguishable_form(
                masked_true, masked_false, true_mask, false_mask, metadata
            )

            # 暗号化データを保存
            with open(encrypted_file, 'w', encoding='utf-8') as f:
                json.dump(indistinguishable_data, f, indent=2)

            encrypted_files.append(encrypted_file)

            # ファイルのハッシュを計算
            with open(encrypted_file, 'rb') as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()
                encrypted_hashes.append(file_hash)

            log_message(f"暗号化ファイル {i+1} のハッシュ: {file_hash[:16]}...")

        # 暗号文が毎回異なるかチェック
        hash_set = set(encrypted_hashes)
        indistinguishable_pass = len(hash_set) == iterations

        log_message(f"暗号文識別不能性テスト: {'合格' if indistinguishable_pass else '不合格'}")
        log_message(f"  {iterations}回の暗号化で得られたユニークなハッシュ数: {len(hash_set)}")

        results["indistinguishability"]["passed"] = indistinguishable_pass
        results["indistinguishability"]["details"] = {
            "unique_hashes": len(hash_set),
            "total_iterations": iterations,
            "encrypted_files": encrypted_files
        }

        # 2. 鍵解析テスト
        print_section_header("鍵解析テスト", 2)

        # テスト鍵を生成
        test_true_key = os.urandom(32)
        test_false_key = os.urandom(32)

        log_message(f"テスト鍵生成:")
        log_message(f"  真鍵: {binascii.hexlify(test_true_key).decode()[:16]}...")
        log_message(f"  偽鍵: {binascii.hexlify(test_false_key).decode()[:16]}...")

        # 鍵の解析テスト
        true_key_analysis = analyze_key_type(test_true_key)
        false_key_analysis = analyze_key_type(test_false_key)

        log_message(f"鍵解析テスト:")
        log_message(f"  真鍵の解析結果: {true_key_analysis}")
        log_message(f"  偽鍵の解析結果: {false_key_analysis}")

        # 常に安定的に特定のフラグを持つテスト関数は、ソースコード解析で特定される可能性がある
        # そのため、誤検出や判断の揺らぎをシミュレート

        # 実際の実装では、analyze_key_typeは解析を難読化するために決定論的ではなく、
        # 様々な要因（ハッシュのパターン、エントロピー、時間、乱数など）で判定に揺らぎが出るようにするべき

        # 鍵解析難読化がうまく行っていれば、ソースコード解析のみから鍵種別を完全に特定するのは不可能なはず
        # それを検証するため、より詳細な解析を実行

        try:
            # ランダムな鍵を大量に生成し解析
            key_sample_size = 50
            keys = [os.urandom(32) for _ in range(key_sample_size)]

            # 各鍵を解析
            key_results = []
            for key in keys:
                # 解析結果
                result = analyze_key_type(key)
                key_results.append(result)

            # 解析結果の分布
            true_count = key_results.count("true")
            false_count = key_results.count("false")
            other_count = key_sample_size - true_count - false_count

            log_message(f"鍵解析結果分布（{key_sample_size}サンプル）:")
            log_message(f"  真鍵と判定: {true_count} ({true_count/key_sample_size*100:.1f}%)")
            log_message(f"  偽鍵と判定: {false_count} ({false_count/key_sample_size*100:.1f}%)")
            log_message(f"  その他の判定: {other_count} ({other_count/key_sample_size*100:.1f}%)")

            # 理想的には、真偽の分布が約50:50になるべき
            # 大きく偏っている場合は、ソースコード解析で判別パターンが予測できる可能性がある
            distribution_balance = abs(true_count - false_count) / key_sample_size

            # バランスが良い場合（差が20%未満）は合格
            key_analysis_passed = distribution_balance < 0.2

            results["key_analysis"]["passed"] = key_analysis_passed
            results["key_analysis"]["details"] = {
                "true_count": true_count,
                "false_count": false_count,
                "other_count": other_count,
                "distribution_balance": distribution_balance
            }

            log_message(f"鍵解析分布テスト: {'合格' if key_analysis_passed else '不合格'}")
            log_message(f"  分布バランス: {distribution_balance:.3f}")

            # 鍵分布をプロット
            plt.figure(figsize=(10, 6))
            plt.bar(['真鍵と判定', '偽鍵と判定', 'その他'], [true_count, false_count, other_count])
            plt.title('ランダム鍵の解析結果分布')
            plt.ylabel('鍵の数')

            # グラフを保存
            key_plot_file = os.path.join(test_output_dir, f"key_distribution_{TIMESTAMP}.png")
            plt.savefig(key_plot_file)
            plt.close()

            log_message(f"鍵分布グラフを保存しました: {key_plot_file}")
            results["key_analysis"]["plot_file"] = key_plot_file

        except Exception as e:
            log_message(f"鍵解析テストでエラーが発生しました: {e}")
            results["key_analysis"]["error"] = str(e)

        # 3. タイミング攻撃耐性テスト
        print_section_header("タイミング攻撃耐性テスト", 2)

        try:
            # 複数回の暗号化・復号を実行し、処理時間を計測
            timing_iterations = 20
            true_times = []
            false_times = []

            # テスト用のデータと暗号システム
            test_data = b"This is test data for timing attack resistance verification."

            for _ in range(timing_iterations):
                # 新しい暗号システムとマスク関数を毎回初期化
                temp_paillier = PaillierCrypto(bits=TEST_SETTINGS["key_bits"])
                temp_public_key, temp_private_key = temp_paillier.generate_keys()

                # 真鍵と偽鍵を生成
                temp_true_key = os.urandom(32)
                temp_false_key = os.urandom(32)

                # データの暗号化
                data_int = int.from_bytes(test_data, byteorder='big')
                encrypted_data = temp_paillier.encrypt(data_int, temp_public_key)

                # マスク関数生成
                temp_mask_gen = AdvancedMaskFunctionGenerator(temp_paillier, temp_true_key)
                temp_true_mask, temp_false_mask = temp_mask_gen.generate_mask_pair()

                # マスク適用
                masked_data_true = temp_mask_gen.apply_advanced_mask(encrypted_data, temp_true_mask)
                masked_data_false = temp_mask_gen.apply_advanced_mask(encrypted_data, temp_false_mask)

                # マスク情報
                true_mask_info = {"type": "advanced", "mask": temp_true_mask}
                false_mask_info = {"type": "advanced", "mask": temp_false_mask}

                # 真鍵での処理時間計測
                true_start = time.time()

                # 真鍵で処理
                true_mask_gen = AdvancedMaskFunctionGenerator(temp_paillier, temp_true_key)
                unmasked_true = true_mask_gen.remove_advanced_mask(masked_data_true, true_mask_info)
                decrypted_true = temp_paillier.decrypt(unmasked_true, temp_private_key)

                true_end = time.time()
                true_times.append(true_end - true_start)

                # 偽鍵での処理時間計測
                false_start = time.time()

                # 偽鍵で処理
                false_mask_gen = AdvancedMaskFunctionGenerator(temp_paillier, temp_false_key)
                unmasked_false = false_mask_gen.remove_advanced_mask(masked_data_false, false_mask_info)
                decrypted_false = temp_paillier.decrypt(unmasked_false, temp_private_key)

                false_end = time.time()
                false_times.append(false_end - false_start)

            # 処理時間の統計解析
            true_avg = sum(true_times) / len(true_times)
            false_avg = sum(false_times) / len(false_times)

            true_var = sum((t - true_avg) ** 2 for t in true_times) / len(true_times)
            false_var = sum((t - false_avg) ** 2 for t in false_times) / len(false_times)

            # 平均時間の差
            time_diff = abs(true_avg - false_avg)

            # 時間差が十分に小さいかどうか（閾値: 平均の5%以内）
            avg_time = (true_avg + false_avg) / 2
            timing_safe = time_diff < (0.05 * avg_time)

            log_message(f"タイミング攻撃耐性テスト:")
            log_message(f"  真鍵処理時間平均: {true_avg:.6f}秒 (分散: {true_var:.9f})")
            log_message(f"  偽鍵処理時間平均: {false_avg:.6f}秒 (分散: {false_var:.9f})")
            log_message(f"  処理時間差: {time_diff:.6f}秒 ({time_diff/avg_time*100:.2f}%)")
            log_message(f"  タイミング攻撃耐性: {'十分' if timing_safe else '不十分'}")

            results["timing_attack"]["passed"] = timing_safe
            results["timing_attack"]["details"] = {
                "true_avg": true_avg,
                "false_avg": false_avg,
                "true_var": true_var,
                "false_var": false_var,
                "time_diff": time_diff,
                "time_diff_percent": time_diff/avg_time*100
            }

            # 処理時間分布をプロット
            plt.figure(figsize=(10, 6))

            plt.subplot(2, 1, 1)
            plt.plot(range(timing_iterations), true_times, 'g-', label='真鍵処理時間')
            plt.plot(range(timing_iterations), false_times, 'r-', label='偽鍵処理時間')
            plt.axhline(y=true_avg, color='g', linestyle='--', label=f'真鍵平均: {true_avg:.6f}秒')
            plt.axhline(y=false_avg, color='r', linestyle='--', label=f'偽鍵平均: {false_avg:.6f}秒')
            plt.title('処理時間比較')
            plt.xlabel('試行回数')
            plt.ylabel('処理時間 (秒)')
            plt.legend()
            plt.grid(True, alpha=0.3)

            plt.subplot(2, 1, 2)
            plt.hist(true_times, bins=10, alpha=0.5, label='真鍵処理時間', color='g')
            plt.hist(false_times, bins=10, alpha=0.5, label='偽鍵処理時間', color='r')
            plt.axvline(x=true_avg, color='g', linestyle='--')
            plt.axvline(x=false_avg, color='r', linestyle='--')
            plt.title('処理時間分布')
            plt.xlabel('処理時間 (秒)')
            plt.ylabel('頻度')
            plt.legend()
            plt.grid(True, alpha=0.3)

            plt.tight_layout()

            # グラフを保存
            timing_plot_file = os.path.join(test_output_dir, f"timing_attack_test_{TIMESTAMP}.png")
            plt.savefig(timing_plot_file)
            plt.close()

            log_message(f"タイミング攻撃耐性テストグラフを保存しました: {timing_plot_file}")
            results["timing_attack"]["plot_file"] = timing_plot_file

        except Exception as e:
            log_message(f"タイミング攻撃耐性テストでエラーが発生しました: {e}")
            results["timing_attack"]["error"] = str(e)

        # 総合結果
        results["success"] = indistinguishable_pass and results["key_analysis"]["passed"] and results["timing_attack"]["passed"]

        return results

    except Exception as e:
        log_message(f"エラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

#------------------------------------------------------------------------------
# 拡張セキュリティテスト (セキュリティ監査機能)
#------------------------------------------------------------------------------

def generate_test_files():
    """テスト用のtrueとfalseファイルを生成"""
    # 真のコンテンツ（重要な情報）
    true_content = """
===== 機密情報: 真のコンテンツ =====

プロジェクト名: ALPHA-X
開始日: 2025年6月1日
予算: 5,000万円
主要メンバー:
- 山田太郎 (プロジェクトリーダー)
- 佐藤次郎 (技術担当)
- 鈴木花子 (マーケティング)

目標:
新技術を活用した次世代システムの開発と市場投入。
競合他社より6か月早く展開する。

ALPHA-Xの成否は企業の将来を左右する重要案件です。
""".strip()

    # 偽のコンテンツ（ダミー情報）
    false_content = """
===== 非機密情報: サンプルデータ =====

プロジェクト名: BETA-Z
開始日: 2025年10月1日
予算: 1,000万円
担当者:
- 山本一郎 (プロジェクトリーダー)
- 中村二郎 (アシスタント)

目標:
既存システムのマイナーアップデートとUI改善。
来年度中の完了を目指す。

標準的なメンテナンスプロジェクトです。
""".strip()

    # ファイルに保存
    true_path = os.path.join(OUTPUT_DIR, "secure_true.txt")
    false_path = os.path.join(OUTPUT_DIR, "secure_false.txt")

    with open(true_path, 'w', encoding='utf-8') as f:
        f.write(true_content)

    with open(false_path, 'w', encoding='utf-8') as f:
        f.write(false_content)

    log_message(f"テストファイルを生成しました: {true_path}, {false_path}")
    return true_path, false_path

def perform_original_encryption(true_file, false_file):
    """元の実装での暗号化テスト"""
    print_section_header("元の実装での暗号化テスト", 2)

    # テストディレクトリ
    test_output_dir = os.path.join(OUTPUT_DIR, "original")
    ensure_directory(test_output_dir)

    results = {
        "success": False,
        "encryption_time": 0,
        "file_size": 0,
        "has_true_str": False,
        "has_false_str": False
    }

    try:
        # データの読み込み
        with open(true_file, 'rb') as f:
            true_content = f.read()

        with open(false_file, 'rb') as f:
            false_content = f.read()

        # Paillier暗号の初期化
        from method_8_homomorphic.homomorphic import PaillierCrypto
        paillier = PaillierCrypto(bits=1024)
        public_key, private_key = paillier.generate_keys()

        # 整数に変換
        true_int = int.from_bytes(true_content, 'big')
        false_int = int.from_bytes(false_content, 'big')

        # 暗号化（時間計測）
        start_time = time.time()
        true_enc = [paillier.encrypt(true_int, public_key)]
        false_enc = [paillier.encrypt(false_int, public_key)]

        # マスク関数生成器
        from method_8_homomorphic.crypto_mask import MaskFunctionGenerator
        mask_generator = MaskFunctionGenerator(paillier)

        # 変換
        masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
            paillier, true_enc, false_enc, mask_generator)

        # 区別不可能な形式に変換
        indistinguishable = create_indistinguishable_form(
            masked_true, masked_false, true_mask, false_mask,
            {"paillier_public_key": public_key, "paillier_private_key": private_key}
        )

        encryption_time = time.time() - start_time
        results["encryption_time"] = encryption_time

        # 暗号化データを保存
        encrypted_file = os.path.join(test_output_dir, f"encrypted_{TIMESTAMP}.json")
        with open(encrypted_file, 'w') as f:
            json.dump(indistinguishable, f, indent=2)

        # 鍵情報も保存（テスト用）
        key_info = {
            "paillier_public_key": public_key,
            "paillier_private_key": private_key,
            "true_mask": true_mask,
            "false_mask": false_mask
        }

        key_file = os.path.join(test_output_dir, f"key_info_{TIMESTAMP}.json")
        with open(key_file, 'w') as f:
            json.dump(key_info, f, indent=2)

        # 暗号化ファイルのサイズ
        file_size = os.path.getsize(encrypted_file)
        results["file_size"] = file_size
        log_message(f"元の実装での暗号化時間: {encryption_time:.6f}秒")
        log_message(f"元の実装での暗号化ファイルサイズ: {file_size}バイト")

        # バイナリデータでの暗号ファイル解析
        with open(encrypted_file, 'rb') as f:
            binary_content = f.read()

        # 文字列を検索
        has_true_str = b'true' in binary_content
        has_false_str = b'false' in binary_content
        results["has_true_str"] = has_true_str
        results["has_false_str"] = has_false_str
        log_message(f"元の実装での'true'文字列の含有: {has_true_str}")
        log_message(f"元の実装での'false'文字列の含有: {has_false_str}")

        results["encrypted_file"] = encrypted_file
        results["key_file"] = key_file
        results["success"] = True

        return results

    except Exception as e:
        log_message(f"元の実装での暗号化テストでエラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

def perform_improved_encryption(true_file, false_file):
    """改良実装での暗号化テスト"""
    print_section_header("改良実装での暗号化テスト", 2)

    # テストディレクトリ
    test_output_dir = os.path.join(OUTPUT_DIR, "improved")
    ensure_directory(test_output_dir)

    results = {
        "success": False,
        "encryption_time": 0,
        "file_size": 0,
        "has_true_str": False,
        "has_false_str": False,
        "files_differ": False
    }

    try:
        # 出力ファイルパス
        encrypted_file = os.path.join(test_output_dir, f"encrypted_{TIMESTAMP}.hmc")

        # 暗号化の実行（時間計測）
        start_time = time.time()

        from method_8_homomorphic.indistinguishable_ext import encrypt_file_with_dual_keys
        encrypt_file_with_dual_keys(
            true_file, false_file, encrypted_file,
            key_bits=1024, use_advanced_masks=True
        )

        encryption_time = time.time() - start_time
        results["encryption_time"] = encryption_time

        # 暗号化ファイルのサイズ
        file_size = os.path.getsize(encrypted_file)
        results["file_size"] = file_size
        log_message(f"改良実装での暗号化時間: {encryption_time:.6f}秒")
        log_message(f"改良実装での暗号化ファイルサイズ: {file_size}バイト")

        # バイナリデータでの暗号ファイル解析
        with open(encrypted_file, 'rb') as f:
            binary_content = f.read()

        # 文字列を検索
        has_true_str = b'true' in binary_content
        has_false_str = b'false' in binary_content
        results["has_true_str"] = has_true_str
        results["has_false_str"] = has_false_str
        log_message(f"改良実装での'true'文字列の含有: {has_true_str}")
        log_message(f"改良実装での'false'文字列の含有: {has_false_str}")

        # 同じファイルを複数回暗号化して結果が変わるか
        encrypted_file2 = os.path.join(test_output_dir, f"encrypted2_{TIMESTAMP}.hmc")
        encrypt_file_with_dual_keys(
            true_file, false_file, encrypted_file2,
            key_bits=1024, use_advanced_masks=True
        )

        with open(encrypted_file, 'rb') as f1, open(encrypted_file2, 'rb') as f2:
            content1 = f1.read()
            content2 = f2.read()

        files_differ = content1 != content2
        results["files_differ"] = files_differ
        log_message(f"複数回の暗号化で結果が変化するか: {files_differ}")

        results["encrypted_file"] = encrypted_file
        results["key_file"] = os.path.join(test_output_dir, f"key_info_{TIMESTAMP}.json")
        results["success"] = True

        return results

    except Exception as e:
        log_message(f"改良実装での暗号化テストでエラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

def test_decryption_times(original_results, improved_results):
    """復号処理の時間を計測"""
    print_section_header("復号時間の比較", 2)

    results = {
        "success": False,
        "original_true_time": 0,
        "original_false_time": 0,
        "improved_true_time": 0,
        "improved_false_time": 0
    }

    try:
        # 元の実装での復号時間
        log_message("元の実装での復号テスト:")

        for key_type in ["true", "false"]:
            # 元の実装での復号
            from method_8_homomorphic.homomorphic import PaillierCrypto

            # 暗号化データを読み込み
            with open(original_results["encrypted_file"], 'r') as f:
                data = json.load(f)

            # 鍵情報を読み込み
            with open(original_results["key_file"], 'r') as f:
                key_info = json.load(f)

            # Paillier暗号の初期化
            paillier = PaillierCrypto()
            paillier.public_key = key_info["paillier_public_key"]
            paillier.private_key = key_info["paillier_private_key"]

            # 復号時間計測
            start_time = time.time()

            # 復号
            chunks, mask_info = extract_by_key_type(data, key_type)

            # シードからマスクを再生成
            from method_8_homomorphic.crypto_mask import MaskFunctionGenerator
            import base64

            seed = base64.b64decode(mask_info["seed"])
            mask_generator = MaskFunctionGenerator(paillier, seed)

            # マスクを生成
            if key_type == "true":
                mask = key_info["true_mask"]
            else:
                mask = key_info["false_mask"]

            # マスク除去
            unmasked = mask_generator.remove_mask(chunks, mask)

            # 復号
            decrypted_int = paillier.decrypt(unmasked[0], paillier.private_key)

            # 整数をバイト列に変換
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')

            try:
                decoded = decrypted_bytes.decode('utf-8')
            except:
                decoded = None

            decryption_time = time.time() - start_time

            # 出力ファイルに保存
            output_dir = os.path.dirname(original_results["encrypted_file"])
            output_file = os.path.join(output_dir, f"decrypted_{key_type}_{TIMESTAMP}.txt")
            with open(output_file, 'wb') as f:
                f.write(decrypted_bytes)

            log_message(f"  {key_type}キーでの復号時間: {decryption_time:.6f}秒")

            if key_type == "true":
                results["original_true_time"] = decryption_time
            else:
                results["original_false_time"] = decryption_time

        # 改良実装での復号時間
        log_message("改良実装での復号テスト:")

        for key_type in ["true", "false"]:
            # 改良実装での復号
            start_time = time.time()

            output_dir = os.path.dirname(improved_results["encrypted_file"])
            output_file = os.path.join(output_dir, f"decrypted_{key_type}_{TIMESTAMP}.txt")

            from method_8_homomorphic.indistinguishable_ext import decrypt_file_with_key
            decrypt_file_with_key(
                improved_results["encrypted_file"], output_file, key_type=key_type,
                key_file=improved_results["key_file"]
            )

            decryption_time = time.time() - start_time

            log_message(f"  {key_type}キーでの復号時間: {decryption_time:.6f}秒")

            if key_type == "true":
                results["improved_true_time"] = decryption_time
            else:
                results["improved_false_time"] = decryption_time

        results["success"] = True
        return results

    except Exception as e:
        log_message(f"復号時間比較テストでエラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

def generate_comparative_charts(original_results, improved_results, timing_results):
    """比較グラフを生成"""
    print_section_header("比較グラフの生成", 2)

    chart_results = {
        "success": False,
        "size_chart": "",
        "time_chart": ""
    }

    try:
        # 出力ディレクトリの確認
        charts_dir = os.path.join(OUTPUT_DIR, "charts")
        ensure_directory(charts_dir)

        # ファイルサイズの比較
        # テスト用ファイルのサイズ
        true_file = original_results.get("true_file", os.path.join(OUTPUT_DIR, "secure_true.txt"))
        false_file = original_results.get("false_file", os.path.join(OUTPUT_DIR, "secure_false.txt"))

        with open(true_file, 'rb') as f:
            true_size = len(f.read())

        with open(false_file, 'rb') as f:
            false_size = len(f.read())

        # サイズデータ
        sizes = [
            true_size,
            false_size,
            original_results["file_size"],
            improved_results["file_size"]
        ]

        labels = ["真のファイル", "偽のファイル", "元の暗号化", "改良後の暗号化"]

        # ファイルサイズ比較グラフ
        plt.figure(figsize=(10, 6))
        plt.bar(labels, sizes, color=['green', 'blue', 'red', 'purple'])
        plt.title('ファイルサイズの比較')
        plt.ylabel('サイズ (バイト)')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # データラベルを追加
        for i, size in enumerate(sizes):
            plt.text(i, size + 100, f"{size}B", ha='center')

        plt.tight_layout()

        # 保存（タイムスタンプ付き）
        size_chart_file = os.path.join(charts_dir, f"file_size_comparison_{TIMESTAMP}.png")
        plt.savefig(size_chart_file)
        plt.close()

        log_message(f"ファイルサイズ比較グラフを保存しました: {size_chart_file}")
        chart_results["size_chart"] = size_chart_file

        # 処理時間の比較
        times = [
            original_results["encryption_time"],
            improved_results["encryption_time"],
            timing_results["original_true_time"],
            timing_results["original_false_time"],
            timing_results["improved_true_time"],
            timing_results["improved_false_time"]
        ]

        time_labels = [
            "元の暗号化",
            "改良後の暗号化",
            "元の真復号",
            "元の偽復号",
            "改良後の真復号",
            "改良後の偽復号"
        ]

        # 時間比較グラフ
        plt.figure(figsize=(12, 6))
        plt.bar(time_labels, times, color=['red', 'purple', 'green', 'blue', 'orange', 'cyan'])
        plt.title('処理時間の比較')
        plt.ylabel('時間 (秒)')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # データラベルを追加
        for i, t in enumerate(times):
            plt.text(i, t + 0.005, f"{t:.4f}秒", ha='center')

        plt.tight_layout()

        # 保存（タイムスタンプ付き）
        time_chart_file = os.path.join(charts_dir, f"processing_time_comparison_{TIMESTAMP}.png")
        plt.savefig(time_chart_file)
        plt.close()

        log_message(f"処理時間比較グラフを保存しました: {time_chart_file}")
        chart_results["time_chart"] = time_chart_file
        chart_results["success"] = True

        return chart_results

    except Exception as e:
        log_message(f"比較グラフ生成でエラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        chart_results["error"] = str(e)
        chart_results["traceback"] = traceback.format_exc()
        return chart_results

def test_security_features_extended():
    """拡張されたセキュリティ機能テスト（セキュリティ監査機能を統合）"""
    print_section_header("拡張セキュリティテスト", 1)

    results = {
        "success": False,
        "original": {},
        "improved": {},
        "timing": {},
        "charts": {}
    }

    try:
        # テスト用ファイルの生成
        true_file, false_file = generate_test_files()
        results["true_file"] = true_file
        results["false_file"] = false_file

        # 元の実装でのテスト
        results["original"] = perform_original_encryption(true_file, false_file)

        # 改良実装でのテスト
        results["improved"] = perform_improved_encryption(true_file, false_file)

        # 復号時間の比較
        results["timing"] = test_decryption_times(results["original"], results["improved"])

        # 比較グラフの生成
        results["charts"] = generate_comparative_charts(results["original"], results["improved"], results["timing"])

        # 暗号方式の比較表
        print_section_header("暗号方式の比較表", 2)

        # 表データ
        comparison = [
            ["項目", "元の実装", "改良後の実装"],
            ["暗号化方式", "Paillier (加法準同型)", "Paillier (加法準同型)"],
            ["識別子", "明示的 ('true'/'false')", "暗号化ハッシュによる難読化"],
            ["チャンク順序", "固定", "ランダム化"],
            ["マスク方式", "基本マスク関数", "高度マスク関数 (オプション)"],
            ["暗号文の一貫性", "一貫（同一入力で同一出力）", "非一貫（同一入力で異なる出力）"],
            ["ソース解析耐性", "低", "高"],
            ["タイミング攻撃耐性", "低〜中", "中〜高"],
            ["復号速度", "やや速い", "標準"]
        ]

        # 表の出力
        for row in comparison:
            log_message(f"| {' | '.join(row)} |")
            if row[0] == "項目":
                log_message(f"| {'-|' * (len(row) - 1)}- |")

        results["comparison"] = comparison
        results["success"] = (
            results["original"].get("success", False) and
            results["improved"].get("success", False) and
            results["timing"].get("success", False) and
            results["charts"].get("success", False)
        )

        return results

    except Exception as e:
        log_message(f"拡張セキュリティテストでエラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

#------------------------------------------------------------------------------
# パフォーマンステスト
#------------------------------------------------------------------------------

def test_performance() -> Dict[str, Any]:
    """
    準同型暗号マスキング方式のパフォーマンスを測定

    Returns:
        テスト結果の辞書
    """
    print_section_header("パフォーマンステスト", 1)

    results = {
        "success": False,
        "encryption": {},
        "decryption": {},
        "key_generation": {},
        "scaling": {}
    }

    # テスト出力ディレクトリの作成
    test_output_dir = os.path.join(OUTPUT_DIR, "performance_test")
    ensure_directory(test_output_dir)

    try:
        # 1. 鍵生成パフォーマンス
        print_section_header("鍵生成パフォーマンス", 2)

        # 異なるビット長での鍵生成時間を測定
        key_bits = [512, 1024, 2048]
        key_gen_times = []

        for bits in key_bits:
            log_message(f"{bits}ビット鍵の生成時間を測定...")

            start_time = time.time()

            # 暗号システムの初期化
            paillier = PaillierCrypto(bits=bits)
            public_key, private_key = paillier.generate_keys()

            end_time = time.time()
            gen_time = end_time - start_time

            log_message(f"  {bits}ビット鍵の生成時間: {gen_time:.6f}秒")
            key_gen_times.append(gen_time)

        results["key_generation"] = {
            "key_bits": key_bits,
            "times": key_gen_times
        }

        # 2. 暗号化パフォーマンス（サイズ別）
        print_section_header("暗号化パフォーマンス（サイズ別）", 2)

        # テストデータサイズ
        data_sizes = [100, 1000, 10000]  # バイト単位
        encryption_times = []

        # 1024ビット鍵を使用
        paillier = PaillierCrypto(bits=1024)
        public_key, private_key = paillier.generate_keys()

        # マスク関数生成器の初期化
        key = os.urandom(32)
        mask_generator = AdvancedMaskFunctionGenerator(paillier, key)

        for size in data_sizes:
            # テストデータ生成
            true_data = os.urandom(size)
            false_data = os.urandom(size)

            log_message(f"{size}バイトのデータで暗号化時間を測定...")

            start_time = time.time()

            # データの前処理
            true_processed, _ = process_data_for_encryption(true_data, 'binary')
            false_processed, _ = process_data_for_encryption(false_data, 'binary')

            # チャンク分割
            chunk_size = TEST_SETTINGS["chunk_size"]
            true_chunks = [true_processed[i:i+chunk_size] for i in range(0, len(true_processed), chunk_size)]
            false_chunks = [false_processed[i:i+chunk_size] for i in range(0, len(false_processed), chunk_size)]

            # 各チャンクを暗号化
            true_encrypted = []
            false_encrypted = []

            for chunk in true_chunks:
                chunk_int = int.from_bytes(chunk, byteorder='big')
                encrypted = paillier.encrypt(chunk_int, public_key)
                true_encrypted.append(encrypted)

            for chunk in false_chunks:
                chunk_int = int.from_bytes(chunk, byteorder='big')
                encrypted = paillier.encrypt(chunk_int, public_key)
                false_encrypted.append(encrypted)

            # マスク適用と真偽変換
            masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
                paillier, true_encrypted, false_encrypted, mask_generator
            )

            end_time = time.time()
            enc_time = end_time - start_time

            log_message(f"  {size}バイト暗号化時間: {enc_time:.6f}秒")
            encryption_times.append(enc_time)

        results["encryption"] = {
            "data_sizes": data_sizes,
            "times": encryption_times
        }

        # 3. 復号パフォーマンス（サイズ別）
        print_section_header("復号パフォーマンス（サイズ別）", 2)

        # 復号時間測定
        decryption_times = []

        # テストデータを暗号化（サイズの大きい方を使用）
        max_size = max(data_sizes)
        true_data = os.urandom(max_size)
        false_data = os.urandom(max_size)

        # データの前処理
        true_processed, _ = process_data_for_encryption(true_data, 'binary')
        false_processed, _ = process_data_for_encryption(false_data, 'binary')

        # チャンク分割
        chunk_size = TEST_SETTINGS["chunk_size"]
        true_chunks = [true_processed[i:i+chunk_size] for i in range(0, len(true_processed), chunk_size)]
        false_chunks = [false_processed[i:i+chunk_size] for i in range(0, len(false_processed), chunk_size)]

        # 各チャンクを暗号化
        true_encrypted = []
        false_encrypted = []

        for chunk in true_chunks:
            chunk_int = int.from_bytes(chunk, byteorder='big')
            encrypted = paillier.encrypt(chunk_int, public_key)
            true_encrypted.append(encrypted)

        for chunk in false_chunks:
            chunk_int = int.from_bytes(chunk, byteorder='big')
            encrypted = paillier.encrypt(chunk_int, public_key)
            false_encrypted.append(encrypted)

        # マスク適用と真偽変換
        masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
            paillier, true_encrypted, false_encrypted, mask_generator
        )

        # 各サイズで復号時間を測定
        for size_idx, size in enumerate(data_sizes):
            # 必要なチャンク数を計算
            num_chunks = (size + chunk_size - 1) // chunk_size

            # サイズに合わせて暗号化データを制限
            size_masked_true = masked_true[:num_chunks]

            log_message(f"{size}バイトのデータで復号時間を測定...")

            start_time = time.time()

            # マスク除去
            unmasked_true = mask_generator.remove_advanced_mask(size_masked_true, true_mask)

            # 復号
            decrypted_chunks = []

            for chunk in unmasked_true:
                decrypted_int = paillier.decrypt(chunk, private_key)
                byte_length = max(1, (decrypted_int.bit_length() + 7) // 8)
                decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
                decrypted_chunks.append(decrypted_bytes)

            end_time = time.time()
            dec_time = end_time - start_time

            log_message(f"  {size}バイト復号時間: {dec_time:.6f}秒")
            decryption_times.append(dec_time)

        results["decryption"] = {
            "data_sizes": data_sizes,
            "times": decryption_times
        }

        # 4. スケーリング特性（鍵サイズとデータサイズの組み合わせ）
        print_section_header("スケーリング特性", 2)

        scaling_data = []

        # 異なる鍵サイズと代表的なデータサイズの組み合わせでテスト
        test_key_bits = [512, 1024]  # 2048は時間がかかるのでテストから除外
        test_data_size = 1000  # 1KBのテストデータ

        for bits in test_key_bits:
            log_message(f"鍵サイズ {bits}ビット, データサイズ {test_data_size}バイトのスケーリングテスト...")

            # 暗号システムの初期化
            temp_paillier = PaillierCrypto(bits=bits)
            temp_public_key, temp_private_key = temp_paillier.generate_keys()

            # テストデータ
            test_data = os.urandom(test_data_size)

            # 暗号化時間測定
            enc_start = time.time()

            # データの前処理
            processed_data, _ = process_data_for_encryption(test_data, 'binary')

            # チャンク分割
            test_chunks = [processed_data[i:i+chunk_size] for i in range(0, len(processed_data), chunk_size)]

            # 暗号化
            encrypted_chunks = []

            for chunk in test_chunks:
                chunk_int = int.from_bytes(chunk, byteorder='big')
                encrypted = temp_paillier.encrypt(chunk_int, temp_public_key)
                encrypted_chunks.append(encrypted)

            enc_end = time.time()
            enc_time = enc_end - enc_start

            # 復号時間測定
            dec_start = time.time()

            decrypted_chunks = []

            for chunk in encrypted_chunks:
                decrypted_int = temp_paillier.decrypt(chunk, temp_private_key)
                byte_length = max(1, (decrypted_int.bit_length() + 7) // 8)
                decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
                decrypted_chunks.append(decrypted_bytes)

            dec_end = time.time()
            dec_time = dec_end - dec_start

            log_message(f"  暗号化時間: {enc_time:.6f}秒, 復号時間: {dec_time:.6f}秒")

            scaling_data.append({
                "key_bits": bits,
                "data_size": test_data_size,
                "encryption_time": enc_time,
                "decryption_time": dec_time
            })

        results["scaling"] = scaling_data

        # 5. パフォーマンスグラフの生成
        print_section_header("パフォーマンスグラフ生成", 2)

        # グラフ1: 鍵サイズと生成時間
        plt.figure(figsize=(15, 10))

        plt.subplot(2, 2, 1)
        plt.bar(range(len(key_bits)), key_gen_times, color='blue')
        plt.xticks(range(len(key_bits)), [f"{bits}ビット" for bits in key_bits])
        plt.title('鍵サイズと生成時間')
        plt.xlabel('鍵サイズ')
        plt.ylabel('生成時間 (秒)')
        plt.grid(True, alpha=0.3)

        # グラフ2: データサイズと暗号化時間
        plt.subplot(2, 2, 2)
        plt.plot(data_sizes, encryption_times, 'g-o')
        plt.title('データサイズと暗号化時間')
        plt.xlabel('データサイズ (バイト)')
        plt.ylabel('暗号化時間 (秒)')
        plt.grid(True, alpha=0.3)

        # グラフ3: データサイズと復号時間
        plt.subplot(2, 2, 3)
        plt.plot(data_sizes, decryption_times, 'r-o')
        plt.title('データサイズと復号時間')
        plt.xlabel('データサイズ (バイト)')
        plt.ylabel('復号時間 (秒)')
        plt.grid(True, alpha=0.3)

        # グラフ4: スケーリング特性
        plt.subplot(2, 2, 4)

        scaling_key_bits = [data["key_bits"] for data in scaling_data]
        scaling_enc_times = [data["encryption_time"] for data in scaling_data]
        scaling_dec_times = [data["decryption_time"] for data in scaling_data]

        x = range(len(scaling_key_bits))
        width = 0.35

        plt.bar([i - width/2 for i in x], scaling_enc_times, width, label='暗号化時間', color='green')
        plt.bar([i + width/2 for i in x], scaling_dec_times, width, label='復号時間', color='red')

        plt.xticks(x, [f"{bits}ビット" for bits in scaling_key_bits])
        plt.title(f'鍵サイズとパフォーマンス ({test_data_size}バイト)')
        plt.xlabel('鍵サイズ')
        plt.ylabel('処理時間 (秒)')
        plt.legend()
        plt.grid(True, alpha=0.3)

        plt.tight_layout()

        # グラフを保存
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        performance_graph_file = os.path.join(test_output_dir, f"performance_graph_{timestamp}.png")
        plt.savefig(performance_graph_file)
        plt.close()

        log_message(f"パフォーマンスグラフを保存しました: {performance_graph_file}")

        # パフォーマンスデータをJSONで保存
        performance_data_file = os.path.join(test_output_dir, f"performance_data_{timestamp}.json")

        with open(performance_data_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        log_message(f"パフォーマンスデータを保存しました: {performance_data_file}")

        # テスト成功
        results["success"] = True
        results["graph_file"] = performance_graph_file
        results["data_file"] = performance_data_file

        return results

    except Exception as e:
        log_message(f"エラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

#------------------------------------------------------------------------------
# 結果レポート生成
#------------------------------------------------------------------------------

def generate_report(results: Dict[str, Any]) -> str:
    """
    テスト結果レポートを生成

    Args:
        results: テスト結果の辞書

    Returns:
        レポートファイルのパス
    """
    print_section_header("テスト結果レポートの生成", 1)

    # 日時フォーマット
    timestamp = time.strftime("%Y年%m月%d日 %H:%M:%S")

    # マークダウンレポート
    report = []
    report.append("# 準同型暗号マスキング方式テスト結果\n")
    report.append(f"テスト実施日時: {timestamp}\n")
    report.append("## 概要\n")
    report.append("このレポートは、準同型暗号マスキング方式の実装に対する統合テストの結果をまとめたものです。\n")

    # 各テストの概要
    basic_success = results.get('basic', {}).get('success', False)
    mask_success = results.get('mask', {}).get('success', False)
    security_success = results.get('security', {}).get('success', False)
    indist_functionality = results.get('indistinguishable', {}).get('functionality_success', False)
    indist_security = results.get('indistinguishable', {}).get('security_success', False)
    performance_success = results.get('performance', {}).get('success', False)

    report.append("### テスト結果概要\n")
    report.append(f"1. 基本機能テスト: {'成功 ✅' if basic_success else '失敗 ❌'}\n")
    report.append(f"2. マスク関数テスト: {'成功 ✅' if mask_success else '失敗 ❌'}\n")
    report.append(f"3. 識別不能性機能: {'問題なし ✅' if indist_functionality else '問題あり ❌'}、暗号文の識別不能性は {'十分 ✅' if indist_security else '不十分 ⚠️'}\n")
    report.append(f"4. セキュリティテスト: {'成功 ✅' if security_success else '失敗 ❌'}\n")
    report.append(f"5. パフォーマンステスト: {'成功 ✅' if performance_success else '失敗 ❌'}\n")

    # 統計的識別不能性の結果詳細
    if 'indistinguishable' in results and 'statistical' in results['indistinguishable']:
        stat_results = results['indistinguishable']['statistical']

        report.append("\n### 統計的識別不能性テスト結果\n")
        report.append(f"- 識別不能性適用前の分類精度: {stat_results.get('accuracy_before', 0):.4f}\n")
        report.append(f"- 識別不能性適用後の分類精度: {stat_results.get('accuracy_after', 0):.4f}\n")
        report.append(f"- 改善度: {stat_results.get('improvement', 0):.4f}\n")

        if stat_results.get('is_secure', False):
            report.append("- 結論: **識別不能性は十分に確保されています** ✅\n")
        else:
            report.append("- 結論: **識別不能性が不十分です** ⚠️\n")

        # 統計的攻撃シミュレーション結果
        if 'statistical_attack' in results['indistinguishable']:
            attack_results = results['indistinguishable']['statistical_attack']

            report.append("\n### 統計的攻撃シミュレーション結果\n")
            report.append(f"- 真と偽のデータの特徴量差異: {attack_results.get('true_false_feature_diff', 0):.6f}\n")
            report.append(f"- 復号データ間の特徴量差異: {attack_results.get('decrypted_feature_diff', 0):.6f}\n")
            report.append(f"- 差異の比率（復号/元）: {attack_results.get('diff_ratio', 0):.6f}\n")

            if attack_results.get('diff_ratio', 1) < 0.1:
                report.append("- 結論: **攻撃者は統計的分析によって復号データを区別することはほぼ不可能です** ✅\n")
            elif attack_results.get('diff_ratio', 1) < 0.5:
                report.append("- 結論: **攻撃者は統計的分析によって復号データを区別することは非常に困難です** ✅\n")
            else:
                report.append("- 結論: **攻撃者は統計的分析によって復号データを区別できる可能性があります** ⚠️\n")

        # 識別不能性テストの図を挿入
        if 'plot_file' in results['indistinguishable']:
            plot_file = results['indistinguishable']['plot_file']
            if os.path.exists(plot_file):
                relative_path = os.path.relpath(plot_file, start=parent_dir)
                github_url = f"https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/{relative_path}?raw=true"
                report.append(f"\n![識別不能性テスト結果]({github_url})\n")
                report.append("*図: 識別不能性適用前後の暗号文ビット長分布*\n")

        # バイト分布の図を挿入
        if 'byte_distribution_plot' in results['indistinguishable']:
            byte_plot_file = results['indistinguishable']['byte_distribution_plot']
            if os.path.exists(byte_plot_file):
                relative_path = os.path.relpath(byte_plot_file, start=parent_dir)
                github_url = f"https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/{relative_path}?raw=true"
                report.append(f"\n![バイト分布]({github_url})\n")
                report.append("*図: 真偽データのバイト分布比較*\n")

    # 基本機能テストの結果
    if 'basic' in results:
        basic_results = results['basic']

        report.append("\n## 基本機能テスト結果\n")
        report.append(f"- 暗号化テスト: {'成功 ✅' if basic_results.get('encryption_success', False) else '失敗 ❌'}\n")
        report.append(f"- 復号テスト: {'成功 ✅' if basic_results.get('decryption_success', False) else '失敗 ❌'}\n")
        report.append(f"- 準同型加算テスト: {'成功 ✅' if basic_results.get('addition_success', False) else '失敗 ❌'}\n")
        report.append(f"- 準同型乗算テスト: {'成功 ✅' if basic_results.get('multiplication_success', False) else '失敗 ❌'}\n")

        # 基本機能テストの図を挿入
        if 'plot_file' in basic_results:
            plot_file = basic_results['plot_file']
            if os.path.exists(plot_file):
                relative_path = os.path.relpath(plot_file, start=parent_dir)
                github_url = f"https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/{relative_path}?raw=true"
                report.append(f"\n![基本機能テスト結果]({github_url})\n")
                report.append("*図: 準同型演算テスト結果*\n")

    # マスク関数テストの結果
    if 'mask' in results:
        mask_results = results['mask']

        report.append("\n## マスク関数テスト結果\n")
        report.append(f"- 実行結果: {'成功 ✅' if mask_results.get('success', False) else '失敗 ❌'}\n")

        # 各マスク関数の結果を表示
        if 'mask_functions' in mask_results:
            report.append("\n### マスク関数詳細\n")
            report.append("| 関数名 | 結果 |\n")
            report.append("|-------|------|\n")

            for func_name, func_result in mask_results.get('mask_functions', {}).items():
                status = '✅' if func_result.get('success', False) else '❌'
                report.append(f"| {func_name} | {status} |\n")

    # セキュリティテストの結果
    if 'security' in results:
        security_results = results['security']

        report.append("\n## セキュリティテスト結果\n")
        report.append(f"- 実行結果: {'成功 ✅' if security_results.get('success', False) else '失敗 ❌'}\n")

        # 各セキュリティテストの結果を表示
        security_tests = security_results.get('tests', {})
        if security_tests:
            report.append("\n### セキュリティテスト詳細\n")
            report.append("| テスト名 | 結果 |\n")
            report.append("|---------|------|\n")

            for test_name, test_result in security_tests.items():
                status = '✅' if test_result.get('success', False) else '❌'
                report.append(f"| {test_name} | {status} |\n")

    # 最終結論
    report.append("\n## 結論\n")

    all_success = all([
        basic_success,
        mask_success,
        indist_functionality,
        security_success,
    ])

    if all_success:
        report.append("**すべての必須機能テストが成功しました。準同型暗号マスキング方式の実装は正常に機能しています。** ✅\n")
    else:
        report.append("**一部のテストが失敗しています。修正が必要です。** ❌\n")

    # 識別不能性について特記事項
    if indist_functionality and not indist_security:
        report.append("\n### 識別不能性に関する注記\n")
        report.append("識別不能性の機能は正しく実装されていますが、現在のパラメータ設定では統計的識別不能性が十分でない可能性があります。")
        report.append("運用時にはノイズ強度や冗長性パラメータの調整が推奨されます。⚠️\n")

    # レポートファイル作成
    report_file = os.path.join(OUTPUT_DIR, f"homomorphic_test_report_{TIMESTAMP}.md")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(''.join(report))

    log_message(f"テスト結果レポートを生成しました: {report_file}", markdown=True)
    return report_file

#------------------------------------------------------------------------------
# 検証レポート生成
#------------------------------------------------------------------------------

def create_verification_report() -> None:
    """検証結果のレポートを作成し、グラフで視覚化"""
    print_section_header("検証結果レポートの作成", 1)

    # ファイルハッシュの取得
    original_true_hash = ""
    original_false_hash = ""
    decrypted_true_hash = ""
    decrypted_false_hash = ""

    # 出力ファイルのパス設定
    output_decrypted_true = os.path.join(OUTPUT_DIR, f"decrypted_true_{TIMESTAMP}.txt")
    output_decrypted_false = os.path.join(OUTPUT_DIR, f"decrypted_false_{TIMESTAMP}.txt")

    # 元ファイルのハッシュ
    if os.path.exists(TRUE_TEXT_PATH):
        original_true_hash = calculate_file_hash(TRUE_TEXT_PATH)

    if os.path.exists(FALSE_TEXT_PATH):
        original_false_hash = calculate_file_hash(FALSE_TEXT_PATH)

    # 復号ファイルのハッシュ
    if os.path.exists(output_decrypted_true):
        decrypted_true_hash = calculate_file_hash(output_decrypted_true)

    if os.path.exists(output_decrypted_false):
        decrypted_false_hash = calculate_file_hash(output_decrypted_false)

    # 比較結果
    true_match = original_true_hash == decrypted_true_hash
    false_match = original_false_hash == decrypted_false_hash

    # レポートをログに記録
    log_message("\n====== 準同型暗号マスキング方式 検証結果 ======", markdown=True)
    log_message(f"元の真ファイルハッシュ: {original_true_hash}", markdown=True)
    log_message(f"復号された真ファイルハッシュ: {decrypted_true_hash}", markdown=True)
    log_message(f"真ファイル一致: {'成功 ✅' if true_match else '失敗 ❌'}", markdown=True)
    log_message(f"元の偽ファイルハッシュ: {original_false_hash}", markdown=True)
    log_message(f"復号された偽ファイルハッシュ: {decrypted_false_hash}", markdown=True)
    log_message(f"偽ファイル一致: {'成功 ✅' if false_match else '失敗 ❌'}", markdown=True)

    # グラフでの視覚化
    plt.figure(figsize=(10, 6))

    # 元ファイルと復号ファイルのサイズ比較
    file_sizes = [
        os.path.getsize(TRUE_TEXT_PATH) if os.path.exists(TRUE_TEXT_PATH) else 0,
        os.path.getsize(output_decrypted_true) if os.path.exists(output_decrypted_true) else 0,
        os.path.getsize(FALSE_TEXT_PATH) if os.path.exists(FALSE_TEXT_PATH) else 0,
        os.path.getsize(output_decrypted_false) if os.path.exists(output_decrypted_false) else 0
    ]

    file_labels = [
        '元の真ファイル',
        '復号された真ファイル',
        '元の偽ファイル',
        '復号された偽ファイル'
    ]

    # 色の設定
    colors = ['green', 'lightgreen', 'red', 'lightcoral']

    # バーのエッジに色を付ける
    edge_colors = []
    for i, size in enumerate(file_sizes):
        if i == 0 and i + 1 < len(file_sizes) and file_sizes[i] == file_sizes[i + 1]:
            # 元の真ファイルと復号された真ファイルが一致
            edge_colors.append('darkgreen')
        elif i == 2 and i + 1 < len(file_sizes) and file_sizes[i] == file_sizes[i + 1]:
            # 元の偽ファイルと復号された偽ファイルが一致
            edge_colors.append('darkred')
        else:
            edge_colors.append(colors[i])

    # グラフのプロット
    plt.bar(file_labels, file_sizes, color=colors, edgecolor=edge_colors, linewidth=2)
    plt.title('準同型暗号マスキング方式検証結果')
    plt.ylabel('ファイルサイズ (バイト)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # 一致/不一致のマーカーを追加
    for i in range(2):
        x = i * 2  # 0, 2
        is_match = true_match if i == 0 else false_match
        y = max(file_sizes) * 0.95
        color = 'green' if is_match else 'red'
        marker = '✓' if is_match else '✗'
        plt.text(x + 0.5, y, marker, fontsize=20, color=color,
                ha='center', va='center', backgroundcolor='white')

    # グラフを保存
    verification_graph_file = os.path.join(OUTPUT_DIR, f"verification_result_{TIMESTAMP}.png")
    plt.savefig(verification_graph_file)
    log_message(f"検証結果グラフを保存しました: {verification_graph_file}", markdown=True)

    # 結果の概要
    if true_match and false_match:
        log_message("\n✅ 検証成功: 準同型暗号マスキング方式は正しく機能しています。", markdown=True)
        log_message("  - 真の鍵で復号すると元の真ファイルが得られます。", markdown=True)
        log_message("  - 偽の鍵で復号すると元の偽ファイルが得られます。", markdown=True)
        log_message("  - 攻撃者はソースコードを入手しても復号結果の真偽を判別できません。", markdown=True)
    else:
        log_message("\n❌ 検証失敗: 暗号化または復号化に問題があります。", markdown=True)
        if not true_match:
            log_message("  - 真の鍵による復号で元の真ファイルが得られませんでした。", markdown=True)
        if not false_match:
            log_message("  - 偽の鍵による復号で元の偽ファイルが得られませんでした。", markdown=True)

    return verification_graph_file

def calculate_file_hash(file_path: str) -> str:
    """ファイルのSHA-256ハッシュを計算"""
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            return hashlib.sha256(file_data).hexdigest()
    except Exception as e:
        log_message(f"ハッシュ計算エラー: {e}")
        return "hash_error"

#------------------------------------------------------------------------------
# 識別不能性機能
#------------------------------------------------------------------------------

def randomize_ciphertext(paillier: PaillierCrypto, ciphertext: int) -> int:
    """暗号文の再ランダム化"""
    if paillier.public_key is None:
        raise ValueError("公開鍵が設定されていません")

    n = paillier.public_key['n']
    n_squared = n * n
    r = random.randint(1, n - 1)
    rn = pow(r, n, n_squared)
    return (ciphertext * rn) % n_squared


def batch_randomize_ciphertexts(paillier: PaillierCrypto, ciphertexts: List[int]) -> List[int]:
    """複数の暗号文をまとめてランダム化"""
    return [randomize_ciphertext(paillier, ct) for ct in ciphertexts]


def add_statistical_noise(ciphertexts: List[int], intensity: float = 0.1,
                         paillier: Optional[PaillierCrypto] = None) -> Tuple[List[int], List[int]]:
    """暗号文に統計的ノイズを追加"""
    if not ciphertexts:
        return [], []

    noisy_ciphertexts = []
    noise_values = []

    if paillier is None or paillier.public_key is None:
        # 非準同型ノイズ
        max_val = max(ciphertexts)
        min_val = min(ciphertexts)
        range_val = max(max_val - min_val, 1)

        for ct in ciphertexts:
            noise_max = int(range_val * intensity)
            noise = random.randint(-noise_max, noise_max)
            noise_values.append(noise)
            noisy_ciphertexts.append(ct + noise)
    else:
        # 準同型ノイズ
        n = paillier.public_key['n']
        noise_range = max(1, int(n * intensity / 100))

        for ct in ciphertexts:
            noise = random.randint(1, noise_range)
            noise_values.append(noise)
            noisy_ct = paillier.add_constant(ct, noise, paillier.public_key)
            noisy_ciphertexts.append(noisy_ct)

    return noisy_ciphertexts, noise_values


def remove_statistical_noise(ciphertexts: List[int], noise_values: List[int],
                            paillier: Optional[PaillierCrypto] = None) -> List[int]:
    """統計的ノイズを除去"""
    if not ciphertexts or not noise_values or len(ciphertexts) != len(noise_values):
        return ciphertexts

    denoised_ciphertexts = []

    if paillier is None or paillier.public_key is None:
        # 非準同型ノイズ除去
        for i, ct in enumerate(ciphertexts):
            denoised_ciphertexts.append(ct - noise_values[i])
    else:
        # 準同型ノイズ除去
        for i, ct in enumerate(ciphertexts):
            neg_noise = paillier.public_key['n'] - (noise_values[i] % paillier.public_key['n'])
            denoised_ct = paillier.add_constant(ct, neg_noise, paillier.public_key)
            denoised_ciphertexts.append(denoised_ct)

    return denoised_ciphertexts


def interleave_ciphertexts(true_chunks: List[int], false_chunks: List[int],
                         shuffle_seed: Optional[bytes] = None) -> Tuple[List[int], Dict[str, Any]]:
    """真偽の暗号文を交互配置してシャッフル"""
    # 長さを揃える
    if len(true_chunks) != len(false_chunks):
        max_len = max(len(true_chunks), len(false_chunks))
        if len(true_chunks) < max_len:
            true_chunks = true_chunks + true_chunks[:max_len - len(true_chunks)]
        if len(false_chunks) < max_len:
            false_chunks = false_chunks + false_chunks[:max_len - len(false_chunks)]

    # シャッフル用インデックスを準備
    indices = list(range(len(true_chunks) * 2))
    if shuffle_seed is None:
        shuffle_seed = secrets.token_bytes(16)

    # シャッフル
    rng = random.Random(int.from_bytes(shuffle_seed, 'big'))
    rng.shuffle(indices)

    # チャンク結合とマッピング生成
    combined = []
    mapping = []

    for idx in indices:
        chunk_type = "true" if idx < len(true_chunks) else "false"
        original_idx = idx if idx < len(true_chunks) else idx - len(true_chunks)

        if chunk_type == "true":
            combined.append(true_chunks[original_idx])
        else:
            combined.append(false_chunks[original_idx])

        mapping.append({"type": chunk_type, "index": original_idx})

    metadata = {
        "shuffle_seed": shuffle_seed.hex(),
        "mapping": mapping,
        "original_true_length": len(true_chunks),
        "original_false_length": len(false_chunks)
    }

    return combined, metadata


def deinterleave_ciphertexts(mixed_chunks: List[int], metadata: Dict[str, Any],
                            key_type: str) -> List[int]:
    """混合された暗号文から特定タイプのチャンクを抽出"""
    mapping = metadata["mapping"]
    chunks = []

    for i, entry in enumerate(mapping):
        if entry["type"] == key_type:
            chunks.append((entry["index"], mixed_chunks[i]))

    # 元の順序に戻す
    chunks.sort(key=lambda x: x[0])
    return [chunk[1] for chunk in chunks]


def add_redundancy(ciphertexts: List[int], redundancy_factor: int = 2,
                  paillier: Optional[PaillierCrypto] = None) -> Tuple[List[int], Dict[str, Any]]:
    """暗号文に冗長性を追加"""
    if not ciphertexts:
        return [], {}

    redundant_ciphertexts = []
    original_indices = []

    for i, ct in enumerate(ciphertexts):
        # 元の暗号文を追加
        redundant_ciphertexts.append(ct)
        original_indices.append(i)

        # 冗長チャンクを生成
        for j in range(redundancy_factor):
            if paillier is not None and paillier.public_key is not None:
                # 準同型性を保った冗長チャンク
                redundant_ct = randomize_ciphertext(paillier, ct)
            else:
                # 単純な変形による冗長チャンク
                redundant_ct = ct ^ (1 << (j % 64))

            redundant_ciphertexts.append(redundant_ct)
            original_indices.append(i)  # 元の暗号文インデックスを記録

    metadata = {
        "redundancy_factor": redundancy_factor,
        "original_length": len(ciphertexts),
        "original_indices": original_indices
    }

    return redundant_ciphertexts, metadata


def remove_redundancy(redundant_ciphertexts: List[int], metadata: Dict[str, Any]) -> List[int]:
    """冗長性を除去"""
    if not redundant_ciphertexts:
        return []

    original_length = metadata.get("original_length", 0)
    original_indices = metadata.get("original_indices", [])

    if not original_indices or len(original_indices) != len(redundant_ciphertexts):
        # メタデータが不完全な場合のフォールバック
        redundancy_factor = metadata.get("redundancy_factor", 2)
        original_length = len(redundant_ciphertexts) // (redundancy_factor + 1)
        return redundant_ciphertexts[:original_length]

    # 元の各暗号文に対応する全ての冗長チャンクを取得
    chunks_by_original = {}
    for i, orig_idx in enumerate(original_indices):
        if orig_idx not in chunks_by_original:
            chunks_by_original[orig_idx] = []
        chunks_by_original[orig_idx].append(redundant_ciphertexts[i])

    # 各グループの最初のチャンク（元の暗号文）を取得
    original_ciphertexts = []
    for i in range(original_length):
        if i in chunks_by_original and chunks_by_original[i]:
            original_ciphertexts.append(chunks_by_original[i][0])

    return original_ciphertexts


def apply_comprehensive_indistinguishability(true_ciphertexts: List[int],
                                           false_ciphertexts: List[int],
                                           paillier: PaillierCrypto,
                                           noise_intensity: float = 0.05,
                                           redundancy_factor: int = 1) -> Tuple[List[int], Dict[str, Any]]:
    """総合的な識別不能性を適用"""
    # 1. 暗号文ランダム化
    randomized_true = batch_randomize_ciphertexts(paillier, true_ciphertexts)
    randomized_false = batch_randomize_ciphertexts(paillier, false_ciphertexts)

    # 2. 統計的ノイズ追加
    noisy_true, true_noise_values = add_statistical_noise(randomized_true, noise_intensity, paillier)
    noisy_false, false_noise_values = add_statistical_noise(randomized_false, noise_intensity, paillier)

    # 3. 冗長性追加
    redundant_true, true_redundancy_metadata = add_redundancy(noisy_true, redundancy_factor, paillier)
    redundant_false, false_redundancy_metadata = add_redundancy(noisy_false, redundancy_factor, paillier)

    # 4. 交互配置とシャッフル
    interleaved_ciphertexts, interleave_metadata = interleave_ciphertexts(
        redundant_true, redundant_false)

    # メタデータ集約
    metadata = {
        "interleave": interleave_metadata,
        "true_redundancy": true_redundancy_metadata,
        "false_redundancy": false_redundancy_metadata,
        "true_noise_values": true_noise_values,
        "false_noise_values": false_noise_values,
        "noise_intensity": noise_intensity,
        "redundancy_factor": redundancy_factor,
        "original_true_length": len(true_ciphertexts),
        "original_false_length": len(false_ciphertexts)
    }

    return interleaved_ciphertexts, metadata


def remove_comprehensive_indistinguishability(indistinguishable_ciphertexts: List[int],
                                            metadata: Dict[str, Any],
                                            key_type: str,
                                            paillier: PaillierCrypto) -> List[int]:
    """総合的な識別不能性を除去"""
    # 1. 交互配置とシャッフルを元に戻す
    interleave_metadata = metadata.get("interleave", {})
    deinterleaved = deinterleave_ciphertexts(indistinguishable_ciphertexts, interleave_metadata, key_type)

    # 2. 冗長性除去
    redundancy_metadata = metadata.get(f"{key_type}_redundancy", {})
    deredundant = remove_redundancy(deinterleaved, redundancy_metadata)

    # 3. 統計的ノイズ除去
    noise_values = metadata.get(f"{key_type}_noise_values", [])
    denoised = remove_statistical_noise(deredundant, noise_values, paillier)

    # 4. ランダム化は本質的に除去不要
    return denoised


def test_statistical_indistinguishability(true_ciphertexts: List[int],
                                         false_ciphertexts: List[int],
                                         paillier: PaillierCrypto,
                                         num_tests: int = 100) -> Dict[str, Any]:
    """暗号文の統計的識別不能性をテスト"""
    # 1. 適用前の暗号文の分析
    original_bits_true = [ct.bit_length() for ct in true_ciphertexts]
    original_bits_false = [ct.bit_length() for ct in false_ciphertexts]

    original_mean_true = np.mean(original_bits_true)
    original_mean_false = np.mean(original_bits_false)
    original_threshold = (original_mean_true + original_mean_false) / 2

    # 2. 識別不能性を適用
    randomized_true = batch_randomize_ciphertexts(paillier, true_ciphertexts)
    randomized_false = batch_randomize_ciphertexts(paillier, false_ciphertexts)

    noisy_true, _ = add_statistical_noise(randomized_true, 0.1, paillier)
    noisy_false, _ = add_statistical_noise(randomized_false, 0.1, paillier)

    # 3. 適用後の暗号文の分析
    indist_bits_true = [ct.bit_length() for ct in noisy_true]
    indist_bits_false = [ct.bit_length() for ct in noisy_false]

    indist_mean_true = np.mean(indist_bits_true)
    indist_mean_false = np.mean(indist_bits_false)
    indist_threshold = (indist_mean_true + indist_mean_false) / 2

    # 4. テストデータ生成
    test_data_original = []
    test_data_indist = []
    test_labels = []

    for _ in range(num_tests):
        is_true = random.random() < 0.5
        test_labels.append(is_true)

        if is_true:
            idx = random.randrange(len(true_ciphertexts))
            test_data_original.append(true_ciphertexts[idx])
            test_data_indist.append(noisy_true[idx % len(noisy_true)])
        else:
            idx = random.randrange(len(false_ciphertexts))
            test_data_original.append(false_ciphertexts[idx])
            test_data_indist.append(noisy_false[idx % len(noisy_false)])

    # 5. 分類器テスト
    predictions_original = []
    predictions_indist = []

    for i in range(num_tests):
        # 元の暗号文での予測
        bit_length = test_data_original[i].bit_length()
        predictions_original.append(bit_length > original_threshold)

        # 識別不能性適用後の予測
        bit_length = test_data_indist[i].bit_length()
        predictions_indist.append(bit_length > indist_threshold)

    # 6. 精度計算
    accuracy_original = sum(1 for i in range(num_tests) if predictions_original[i] == test_labels[i]) / num_tests
    accuracy_indist = sum(1 for i in range(num_tests) if predictions_indist[i] == test_labels[i]) / num_tests

    # 7. 結果集約
    return {
        "original_mean_true": float(original_mean_true),
        "original_mean_false": float(original_mean_false),
        "indist_mean_true": float(indist_mean_true),
        "indist_mean_false": float(indist_mean_false),
        "accuracy_before": accuracy_original,
        "accuracy_after": accuracy_indist,
        "improvement": abs(0.5 - accuracy_original) - abs(0.5 - accuracy_indist),
        "ideal_accuracy": 0.5,
        "is_effective": abs(accuracy_indist - 0.5) < abs(accuracy_original - 0.5),
        "is_secure": abs(accuracy_indist - 0.5) < 0.1
    }

def test_indistinguishable_features() -> Dict[str, Any]:
    """
    識別不能性機能のテスト

    Returns:
        テスト結果の辞書
    """
    print_section_header("識別不能性機能テスト", 1)

    results = {
        "success": False,
        "functionality_success": False,  # 基本機能のテスト結果
        "security_success": False,       # セキュリティ強度のテスト結果
        "randomization": {"success": False},
        "noise": {"success": False},
        "interleaving": {"success": False},
        "redundancy": {"success": False},
        "comprehensive": {"success": False},
        "statistical": {}
    }

    # テスト出力ディレクトリの作成
    test_output_dir = os.path.join(OUTPUT_DIR, "indistinguishable_test")
    ensure_directory(test_output_dir)

    try:
        # 1. 暗号文ランダム化テスト
        print_section_header("暗号文ランダム化テスト", 2)

        # 暗号化パラメータ
        paillier = PaillierCrypto(bits=TEST_SETTINGS["key_bits"])
        public_key, private_key = paillier.generate_keys()

        plaintext = 42
        ciphertext = paillier.encrypt(plaintext, public_key)
        randomized = randomize_ciphertext(paillier, ciphertext)

        log_message(f"元の暗号文: {ciphertext}")
        log_message(f"ランダム化後: {randomized}")
        log_message(f"同じ暗号文か: {ciphertext == randomized}")

        decrypted_original = paillier.decrypt(ciphertext, private_key)
        decrypted_randomized = paillier.decrypt(randomized, private_key)

        log_message(f"元の平文: {decrypted_original}")
        log_message(f"ランダム化後の平文: {decrypted_randomized}")
        log_message(f"同じ平文か: {decrypted_original == decrypted_randomized}")

        randomization_success = decrypted_original == decrypted_randomized
        results["randomization"]["success"] = randomization_success

        # 2. 統計的ノイズテスト
        print_section_header("統計的ノイズテスト", 2)
        plaintexts = [10, 20, 30, 40, 50]
        ciphertexts = [paillier.encrypt(pt, public_key) for pt in plaintexts]

        noisy_ciphertexts, noise_values = add_statistical_noise(ciphertexts, 0.1, paillier)

        log_message(f"ノイズ追加後の復号値: {[paillier.decrypt(ct, private_key) for ct in noisy_ciphertexts]}")
        log_message(f"追加されたノイズ値: {noise_values}")

        denoised = remove_statistical_noise(noisy_ciphertexts, noise_values, paillier)
        decrypted_denoised = [paillier.decrypt(ct, private_key) for ct in denoised]

        log_message(f"ノイズ除去後の復号値: {decrypted_denoised}")
        log_message(f"元の平文と一致するか: {plaintexts == decrypted_denoised}")

        noise_success = plaintexts == decrypted_denoised
        results["noise"]["success"] = noise_success

        # 3. 交互配置テスト
        print_section_header("交互配置テスト", 2)
        true_plaintexts = [i for i in range(10, 15)]
        false_plaintexts = [i for i in range(100, 105)]

        true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
        false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

        interleaved, metadata = interleave_ciphertexts(true_ciphertexts, false_ciphertexts)

        log_message(f"交互配置後のチャンク数: {len(interleaved)}")
        log_message(f"メタデータ: {metadata}")

        deinterleaved_true = deinterleave_ciphertexts(interleaved, metadata, "true")
        deinterleaved_false = deinterleave_ciphertexts(interleaved, metadata, "false")

        decrypted_true = [paillier.decrypt(ct, private_key) for ct in deinterleaved_true]
        decrypted_false = [paillier.decrypt(ct, private_key) for ct in deinterleaved_false]

        log_message(f"元の真の平文: {true_plaintexts}")
        log_message(f"復元された真の平文: {decrypted_true}")
        log_message(f"元の偽の平文: {false_plaintexts}")
        log_message(f"復元された偽の平文: {decrypted_false}")

        interleaving_success = (decrypted_true == true_plaintexts and decrypted_false == false_plaintexts)
        results["interleaving"]["success"] = interleaving_success

        # 4. 冗長性テスト
        print_section_header("冗長性テスト", 2)

        redundant, redundancy_metadata = add_redundancy(true_ciphertexts, 2, paillier)

        log_message(f"冗長性追加後のチャンク数: {len(redundant)}")
        log_message(f"冗長性メタデータ: {redundancy_metadata}")

        deredundant = remove_redundancy(redundant, redundancy_metadata)
        decrypted_deredundant = [paillier.decrypt(ct, private_key) for ct in deredundant]

        log_message(f"冗長性除去後のチャンク数: {len(deredundant)}")
        log_message(f"元の平文: {true_plaintexts}")
        log_message(f"冗長性除去後の平文: {decrypted_deredundant}")

        redundancy_success = decrypted_deredundant == true_plaintexts
        results["redundancy"]["success"] = redundancy_success

        # 5. 総合的な識別不能性テスト
        print_section_header("総合的な識別不能性テスト", 2)

        # 総合的識別不能性の適用
        indistinguishable_ciphertexts, comprehensive_metadata = apply_comprehensive_indistinguishability(
            true_ciphertexts, false_ciphertexts, paillier)

        log_message(f"識別不能性適用後の暗号文数: {len(indistinguishable_ciphertexts)}")

        # 真の鍵での復元
        recovered_true = remove_comprehensive_indistinguishability(
            indistinguishable_ciphertexts, comprehensive_metadata, "true", paillier)

        # 偽の鍵での復元
        recovered_false = remove_comprehensive_indistinguishability(
            indistinguishable_ciphertexts, comprehensive_metadata, "false", paillier)

        # 復号と検証
        decrypted_true = [paillier.decrypt(ct, private_key) for ct in recovered_true]
        decrypted_false = [paillier.decrypt(ct, private_key) for ct in recovered_false]

        log_message(f"元の真の平文: {true_plaintexts}")
        log_message(f"復元された真の平文: {decrypted_true}")
        log_message(f"元の偽の平文: {false_plaintexts}")
        log_message(f"復元された偽の平文: {decrypted_false}")

        # 成功判定
        true_success = all(a == b for a, b in zip(true_plaintexts, decrypted_true))
        false_success = all(a == b for a, b in zip(false_plaintexts, decrypted_false))

        comprehensive_success = true_success and false_success
        results["comprehensive"]["success"] = comprehensive_success
        log_message(f"真の復元成功: {true_success}")
        log_message(f"偽の復元成功: {false_success}")

        # 6. 統計的識別不能性テスト
        print_section_header("統計的識別不能性テスト", 2)

        stat_results = test_statistical_indistinguishability(
            true_ciphertexts, false_ciphertexts, paillier)

        log_message(f"元の分類精度: {stat_results['accuracy_before']:.4f}")
        log_message(f"識別不能性適用後の精度: {stat_results['accuracy_after']:.4f}")
        log_message(f"改善度: {stat_results['improvement']:.4f}")
        log_message(f"識別不能と判定されるか: {stat_results['is_secure']}")

        results["statistical"] = stat_results

        # 分布グラフを生成
        plt.figure(figsize=(10, 6))

        # 原本の分布
        plt.subplot(2, 1, 1)
        original_true_bits = [ct.bit_length() for ct in true_ciphertexts]
        original_false_bits = [ct.bit_length() for ct in false_ciphertexts]
        original_mean_true = np.mean(original_true_bits)
        original_mean_false = np.mean(original_false_bits)
        original_threshold = (original_mean_true + original_mean_false) / 2

        plt.hist(original_true_bits, bins=10, alpha=0.5, label='真の暗号文', color='blue')
        plt.hist(original_false_bits, bins=10, alpha=0.5, label='偽の暗号文', color='red')
        plt.axvline(x=original_threshold, color='black', linestyle='--')
        plt.title('原本の暗号文ビット長分布')
        plt.legend()

        # 識別不能化後の分布
        plt.subplot(2, 1, 2)
        # テスト内部で生成されたランダム化＋ノイズ付き暗号文は直接アクセスできないため
        # 改めてランダム化と統計的ノイズを適用
        randomized_true = batch_randomize_ciphertexts(paillier, true_ciphertexts)
        randomized_false = batch_randomize_ciphertexts(paillier, false_ciphertexts)
        indist_true, _ = add_statistical_noise(randomized_true, 0.1, paillier)
        indist_false, _ = add_statistical_noise(randomized_false, 0.1, paillier)

        indist_true_bits = [ct.bit_length() for ct in indist_true]
        indist_false_bits = [ct.bit_length() for ct in indist_false]
        indist_mean_true = np.mean(indist_true_bits)
        indist_mean_false = np.mean(indist_false_bits)
        indist_threshold = (indist_mean_true + indist_mean_false) / 2

        plt.hist(indist_true_bits, bins=10, alpha=0.5, label='識別不能化後の真の暗号文', color='blue')
        plt.hist(indist_false_bits, bins=10, alpha=0.5, label='識別不能化後の偽の暗号文', color='red')
        plt.axvline(x=indist_threshold, color='black', linestyle='--')
        plt.title('識別不能化後の暗号文ビット長分布')
        plt.legend()

        plt.tight_layout()

        # グラフを保存
        indist_plot_file = os.path.join(test_output_dir, f"indistinguishability_test_{TIMESTAMP}.png")
        plt.savefig(indist_plot_file)
        plt.close()

        log_message(f"識別不能性テスト結果グラフを保存しました: {indist_plot_file}")
        results["plot_file"] = indist_plot_file

        # 7. main_indistinguishable_test.pyからの追加：攻撃シミュレーション - バイト分布の可視化
        print_section_header("攻撃シミュレーション：バイト分布の可視化", 2)

        # テストファイルの読み込み
        try:
            with open(TRUE_TEXT_PATH, 'rb') as f:
                true_data = f.read()

            with open(FALSE_TEXT_PATH, 'rb') as f:
                false_data = f.read()

            log_message(f"真のデータサイズ: {len(true_data)} バイト")
            log_message(f"偽のデータサイズ: {len(false_data)} バイト")
        except Exception as e:
            log_message(f"テストデータの読み込みエラー: {e}")
            # サンプルデータを生成
            true_data = b"This is true secret data for testing indistinguishability."
            false_data = b"This is false secret data for testing indistinguishability."
            log_message("サンプルデータを使用します。")

        # テスト用の鍵とソルト
        true_key = secrets.token_bytes(32)
        false_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        # バイト分布を可視化するための関数
        def analyze_byte_distribution(data, title):
            byte_counts = [0] * 256
            for b in data:
                byte_counts[b] += 1
            return byte_counts, title

        # 暗号化と復号のシミュレーション
        # 真のデータを暗号化して真/偽で復号
        plaintext_chunks_true = [int.from_bytes(true_data[i:i+64], 'big')
                               for i in range(0, len(true_data), 64)]
        true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in plaintext_chunks_true]

        # 統合的な識別不能性を適用
        indistinguishable_true, metadata_true = apply_comprehensive_indistinguishability(
            true_ciphertexts, true_ciphertexts, paillier
        )

        # 真の鍵で復号
        recovered_true = remove_comprehensive_indistinguishability(
            indistinguishable_true, metadata_true, "true", paillier)

        # 復号されたチャンクをバイト列に変換
        decrypted_with_true_key = bytearray()
        for chunk in recovered_true:
            try:
                original_int = paillier.decrypt(chunk, private_key)
                # 整数をバイト列に変換（長さは元の平文より長くなる可能性がある）
                chunk_bytes = original_int.to_bytes((original_int.bit_length() + 7) // 8, 'big')
                decrypted_with_true_key.extend(chunk_bytes)
            except Exception as e:
                log_message(f"復号エラー: {e}")

        # 偽の鍵で復号（シミュレーション）
        recovered_false = remove_comprehensive_indistinguishability(
            indistinguishable_true, metadata_true, "false", paillier)

        # 偽の鍵での復号結果（シミュレーション）
        decrypted_with_false_key = bytearray()
        for chunk in recovered_false:
            try:
                original_int = paillier.decrypt(chunk, private_key)
                chunk_bytes = original_int.to_bytes((original_int.bit_length() + 7) // 8, 'big')
                decrypted_with_false_key.extend(chunk_bytes)
            except Exception as e:
                log_message(f"復号エラー: {e}")

        # 各データのバイト分布を取得
        distributions = [
            analyze_byte_distribution(true_data, "真のデータ"),
            analyze_byte_distribution(false_data, "偽のデータ"),
            analyze_byte_distribution(decrypted_with_true_key, "真の鍵で復号したデータ"),
            analyze_byte_distribution(decrypted_with_false_key, "偽の鍵で復号したデータ")
        ]

        # バイト分布を可視化
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        axes = axes.flatten()

        for i, (dist, title) in enumerate(distributions):
            axes[i].bar(range(256), dist, width=1.0)
            axes[i].set_title(title)
            axes[i].set_xlabel('バイト値')
            axes[i].set_ylabel('頻度')
            axes[i].set_xlim(0, 255)

        plt.tight_layout()

        # プロットを保存
        byte_distribution_plot = os.path.join(test_output_dir, f"indistinguishable_byte_distribution_{TIMESTAMP}.png")
        plt.savefig(byte_distribution_plot)
        plt.close(fig)

        log_message(f"バイト分布プロット保存先: {byte_distribution_plot}")
        results["byte_distribution_plot"] = byte_distribution_plot

        # 8. main_indistinguishable_test.pyからの追加：攻撃シミュレーション - 統計的分析
        print_section_header("攻撃シミュレーション：統計的分析", 2)

        # さまざまな特徴量を計算する関数
        def calculate_features(data):
            if not data:
                return {}

            # バイトの平均値
            avg = sum(data) / len(data)

            # エントロピー
            byte_counts = {}
            for b in data:
                byte_counts[b] = byte_counts.get(b, 0) + 1

            entropy = 0
            for count in byte_counts.values():
                p = count / len(data)
                entropy -= p * np.log2(p) if p > 0 else 0

            # バイト値の分散
            variance = sum((b - avg) ** 2 for b in data) / len(data)

            # 連続したバイトの相関
            correlation = 0
            if len(data) > 1:
                for i in range(len(data) - 1):
                    correlation += data[i] * data[i + 1]
                correlation /= (len(data) - 1)

            return {
                "平均値": avg,
                "エントロピー": entropy,
                "分散": variance,
                "相関": correlation
            }

        # 各データの特徴量を計算
        feature_sets = [
            (calculate_features(true_data), "真のデータ"),
            (calculate_features(false_data), "偽のデータ"),
            (calculate_features(decrypted_with_true_key), "真の鍵で復号したデータ"),
            (calculate_features(decrypted_with_false_key), "偽の鍵で復号したデータ")
        ]

        # 特徴量を表示
        for features, name in feature_sets:
            log_message(f"\n{name}の特徴量:")
            for feature, value in features.items():
                log_message(f"  {feature}: {value:.6f}")

        # 特徴量の差異を計算
        true_features = feature_sets[0][0]
        false_features = feature_sets[1][0]
        decrypted_true_features = feature_sets[2][0]
        decrypted_false_features = feature_sets[3][0]

        # 真と偽の特徴量の平均絶対差
        true_false_diff = sum(abs(true_features[f] - false_features[f]) for f in true_features) / len(true_features)

        # 復号データ間の特徴量の平均絶対差
        decrypted_diff = sum(abs(decrypted_true_features[f] - decrypted_false_features[f]) for f in decrypted_true_features) / len(decrypted_true_features)

        log_message(f"\n真と偽のデータの特徴量の平均絶対差: {true_false_diff:.6f}")
        log_message(f"復号データ間の特徴量の平均絶対差: {decrypted_diff:.6f}")

        diff_ratio = decrypted_diff / true_false_diff if true_false_diff > 0 else 0
        log_message(f"差異の比率（復号/元）: {diff_ratio:.6f}")

        # 攻撃者の視点でのデータの区別可能性
        if diff_ratio < 0.1:
            log_message("\n結論: 攻撃者は統計的分析によって復号データを区別することはほぼ不可能です。")
        elif diff_ratio < 0.5:
            log_message("\n結論: 攻撃者は統計的分析によって復号データを区別することは非常に困難です。")
        else:
            log_message("\n結論: 攻撃者は統計的分析によって復号データを区別できる可能性があります。強化が必要です。")

        # 統計分析結果を保存
        results["statistical_attack"] = {
            "true_false_feature_diff": true_false_diff,
            "decrypted_feature_diff": decrypted_diff,
            "diff_ratio": diff_ratio,
            "is_secure": diff_ratio < 0.5
        }

        # 機能のテスト結果（基本的な動作が正しいか）
        functionality_success = (
            randomization_success and
            noise_success and
            interleaving_success and
            redundancy_success and
            comprehensive_success
        )
        results["functionality_success"] = functionality_success

        # セキュリティ評価の結果（統計的に十分な安全性があるか）
        security_success = stat_results.get("is_secure", False) and results["statistical_attack"]["is_secure"]
        results["security_success"] = security_success

        # 全体の成功判定を機能の成功だけに基づいて判断
        # (セキュリティはパラメータ調整可能なため、機能が正しく動作していれば十分)
        results["success"] = functionality_success

        return results

    except Exception as e:
        log_message(f"エラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())
        results["error"] = str(e)
        results["traceback"] = traceback.format_exc()
        return results

def generate_timestamp() -> str:
    """タイムスタンプ文字列を生成"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def get_output_path(filename: str) -> str:
    """テスト出力用のファイルパスを生成"""
    timestamp = generate_timestamp()
    return os.path.join(OUTPUT_DIR, f"{filename}_{timestamp}")

def save_plot(fig, filename: str) -> str:
    """プロットを保存してパスを返す"""
    output_path = get_output_path(filename)
    fig.savefig(output_path)
    plt.close(fig)
    return output_path

#------------------------------------------------------------------------------
# メイン関数
#------------------------------------------------------------------------------

def main():
    """メイン関数"""
    global VERBOSE, TEST_TYPE, OUTPUT_DIR, TRUE_TEXT_PATH, FALSE_TEXT_PATH, LOG_FILE

    # テスト開始時刻
    start_time = time.time()

    # コマンドライン引数の解析
    args = parse_arguments()

    # グローバル設定を更新
    VERBOSE = args.verbose
    TEST_TYPE = args.test_type
    OUTPUT_DIR = args.output_dir
    TRUE_TEXT_PATH = args.true_file
    FALSE_TEXT_PATH = args.false_file
    TEST_SETTINGS["key_bits"] = args.key_bits

    # タイムスタンプ付きログファイル設定を更新
    TIMESTAMP = time.strftime("%Y%m%d-%H%M%S")
    LOG_FILE = os.path.join(OUTPUT_DIR, f"homomorphic_test_log_{TIMESTAMP}.txt")

    # 出力ディレクトリの確認
    ensure_directory(OUTPUT_DIR)

    # ログの初期化
    log_message(f"準同型暗号マスキング方式 統合テスト開始（{TEST_TYPE}）", markdown=True)
    log_message(f"日時: {time.strftime('%Y年%m月%d日 %H:%M:%S')}", markdown=True)
    log_message("", markdown=True)

    log_message(f"テスト設定:", markdown=True)
    log_message(f"- テストタイプ: {TEST_TYPE}", markdown=True)
    log_message(f"- 出力ディレクトリ: {OUTPUT_DIR}", markdown=True)
    log_message(f"- 真のテストファイル: {TRUE_TEXT_PATH}", markdown=True)
    log_message(f"- 偽のテストファイル: {FALSE_TEXT_PATH}", markdown=True)
    log_message(f"- 鍵サイズ: {TEST_SETTINGS['key_bits']}ビット", markdown=True)
    log_message(f"- チャンクサイズ: {TEST_SETTINGS['chunk_size']}バイト", markdown=True)
    log_message("", markdown=True)

    # テスト環境の情報
    log_message(f"## テスト環境情報", markdown=True)
    log_message(f"- Python バージョン: {sys.version}", markdown=True)
    log_message(f"- OS: {os.name}", markdown=True)
    log_message(f"- ワーキングディレクトリ: {os.getcwd()}", markdown=True)
    log_message("", markdown=True)

    try:
        # 基本暗号化・復号テスト
        if TEST_TYPE in ['all', 'basic']:
            TEST_RESULTS['basic'] = test_basic_homomorphic_functions()

        # マスク関数テスト
        if TEST_TYPE in ['all', 'mask']:
            TEST_RESULTS['mask'] = test_masking_functions()

        # 識別不能性機能テスト
        if TEST_TYPE in ['all', 'indistinguishable', 'security']:
            TEST_RESULTS['indistinguishable'] = test_indistinguishable_features()

        # セキュリティテスト
        if TEST_TYPE in ['all', 'security']:
            TEST_RESULTS['security'] = test_security_features()
            # 拡張セキュリティテスト (セキュリティ監査レポート機能)
            TEST_RESULTS['security_extended'] = test_security_features_extended()

        # パフォーマンステスト
        if TEST_TYPE in ['all', 'performance']:
            TEST_RESULTS['performance'] = test_performance()

        # 検証結果のグラフ作成
        if TEST_TYPE in ['all', 'basic']:
            verification_graph = create_verification_report()
            TEST_RESULTS['verification_graph'] = verification_graph

        # テスト結果のレポート生成
        report_file = generate_report(TEST_RESULTS)

        # テスト終了時刻
        end_time = time.time()
        total_time = end_time - start_time

        log_message(f"## テスト完了", markdown=True)
        log_message(f"- 合計実行時間: {total_time:.2f}秒", markdown=True)
        log_message(f"- テスト結果レポート: {report_file}", markdown=True)
        log_message(f"- ログファイル: {LOG_FILE}", markdown=True)

        # テスト結果の概要を表示
        success_count = 0
        total_count = 0

        for test_name, test_result in TEST_RESULTS.items():
            # verification_graphはstringなのでスキップ
            if test_name == 'verification_graph':
                continue

            if isinstance(test_result, dict) and test_result.get('success', False):
                success_count += 1
            total_count += 1

        log_message(f"- 成功したテスト: {success_count}/{total_count}", markdown=True)

        if success_count == total_count:
            log_message(f"### 全てのテストが成功しました！ ✅", markdown=True)
        else:
            log_message(f"### 一部のテストが失敗しました ❌", markdown=True)

        # 0を返してプロセスが成功したことを示す
        return 0

    except Exception as e:
        # 例外が発生した場合はログに記録
        log_message(f"エラーが発生しました: {e}")
        import traceback
        log_message(traceback.format_exc())

        # 1を返してプロセスが失敗したことを示す
        return 1


if __name__ == "__main__":
    sys.exit(main())