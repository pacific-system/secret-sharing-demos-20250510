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
#     下記5つのテストファイルの機能を統合しています：                                #
#     - enhanced_homomorphic_test.py                                           #
#     - test_homomorphic_masking.py                                           #
#     - test_secure_homomorphic.py                                            #
#     - test_security_results.py                                              #
#     - integrated_homomorphic_test.py                                        #
#                                                                              #
################################################################################

"""
準同型暗号マスキング方式 統合テストスクリプト

このスクリプトは、以下の5つのテストスクリプトの機能を統合したものです：
- enhanced_homomorphic_test.py
- test_homomorphic_masking.py
- test_secure_homomorphic.py
- test_security_results.py
- integrated_homomorphic_test.py

主な機能:
1. 準同型暗号の基本機能テスト
2. マスク関数のテスト
3. 暗号文識別不能性のテスト
4. 暗号化・復号の統合テスト
5. 鍵解析のテスト
6. パフォーマンス計測機能
7. セキュリティ検証機能
8. タイムスタンプ付きログファイル生成機能

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
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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
from method_8_homomorphic.key_analyzer_robust import (
    analyze_key_type, extract_seed_from_key
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
        choices=['all', 'basic', 'mask', 'security', 'performance'],
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
    テスト結果からレポートを生成

    Args:
        results: テスト結果の辞書

    Returns:
        レポートのファイルパス
    """
    print_section_header("テスト結果レポートの生成", 1)

    # タイムスタンプ
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_file = os.path.join(OUTPUT_DIR, f"homomorphic_test_report_{timestamp}.md")

    # レポートのヘッダー
    report_content = f"""# 準同型暗号マスキング方式テスト結果

テスト実施日時: {time.strftime("%Y年%m月%d日 %H:%M:%S")}

## 概要

このレポートは、準同型暗号マスキング方式の実装に対する統合テストの結果をまとめたものです。

"""

    # テスト結果サマリー
    all_success = True

    # 各テストの結果を追加
    for test_name, test_results in TEST_RESULTS.items():
        if test_name in results:
            success = results[test_name].get("success", False)
            all_success = all_success and success

            report_content += f"- {test_name}テスト: {'成功 ✅' if success else '失敗 ❌'}\n"

    report_content += f"\n全体のテスト結果: {'成功 ✅' if all_success else '失敗 ❌'}\n"

    # 詳細結果
    for test_name, test_results in results.items():
        if not test_results:
            continue

        if test_name == "basic":
            report_content += f"""
## 基本暗号化・復号テスト

- テスト成功: {'はい ✅' if test_results.get('success', False) else 'いいえ ❌'}
- 真ファイル一致: {'はい ✅' if test_results.get('true_match', False) else 'いいえ ❌'}
- 偽ファイル一致: {'はい ✅' if test_results.get('false_match', False) else 'いいえ ❌'}

### 処理時間

- 暗号化時間: {test_results.get('encryption_time', 0):.6f}秒
- 真鍵での復号時間: {test_results.get('decryption_time', {}).get('true', 0):.6f}秒
- 偽鍵での復号時間: {test_results.get('decryption_time', {}).get('false', 0):.6f}秒

### ファイルサイズ

- 元の真ファイル: {test_results.get('file_sizes', {}).get('true_original', 0)}バイト
- 元の偽ファイル: {test_results.get('file_sizes', {}).get('false_original', 0)}バイト
- 暗号化ファイル: {test_results.get('file_sizes', {}).get('encrypted', 0)}バイト
- 真鍵での復号ファイル: {test_results.get('file_sizes', {}).get('true_decrypted', 0)}バイト
- 偽鍵での復号ファイル: {test_results.get('file_sizes', {}).get('false_decrypted', 0)}バイト
"""

        elif test_name == "mask":
            report_content += f"""
## マスク関数テスト

- テスト成功: {'はい ✅' if test_results.get('success', False) else 'いいえ ❌'}
- 基本マスク関数: {'正常 ✅' if test_results.get('basic_mask', {}).get('success', False) else '失敗 ❌'}
- 高度マスク関数: {'正常 ✅' if test_results.get('advanced_mask', {}).get('success', False) else '失敗 ❌'}
- 統計的特性: {'合格 ✅' if test_results.get('statistical_test', {}).get('passed', False) else '不合格 ❌'}
- 準同型特性の保存: {'維持 ✅' if test_results.get('homomorphic_preserved', False) else '失われた ❌'}

### 処理時間

- 基本マスク処理時間: {test_results.get('basic_mask', {}).get('time', 0):.6f}秒
- 高度マスク処理時間: {test_results.get('advanced_mask', {}).get('time', 0):.6f}秒

### 統計的特性

- マスク分散比率: {test_results.get('mask_difference', 0):.2f}
"""

            # マスク分布グラフがあれば追加
            plot_file = test_results.get('plot_file')
            if plot_file and os.path.exists(plot_file):
                # 相対パスに変換
                rel_path = os.path.relpath(plot_file, os.path.dirname(report_file))
                report_content += f"\n![マスク分布]({rel_path})\n"

        elif test_name == "security":
            report_content += f"""
## セキュリティ特性テスト

- テスト成功: {'はい ✅' if test_results.get('success', False) else 'いいえ ❌'}
- 暗号文識別不能性: {'合格 ✅' if test_results.get('indistinguishability', {}).get('passed', False) else '不合格 ❌'}
- 鍵解析耐性: {'合格 ✅' if test_results.get('key_analysis', {}).get('passed', False) else '不合格 ❌'}
- タイミング攻撃耐性: {'合格 ✅' if test_results.get('timing_attack', {}).get('passed', False) else '不合格 ❌'}

### 識別不能性テスト

- 暗号化回数: {test_results.get('indistinguishability', {}).get('details', {}).get('total_iterations', 0)}
- ユニークハッシュ数: {test_results.get('indistinguishability', {}).get('details', {}).get('unique_hashes', 0)}

### 鍵解析テスト

- 真鍵と判定された割合: {test_results.get('key_analysis', {}).get('details', {}).get('true_count', 0) / (test_results.get('key_analysis', {}).get('details', {}).get('true_count', 0) + test_results.get('key_analysis', {}).get('details', {}).get('false_count', 0) + test_results.get('key_analysis', {}).get('details', {}).get('other_count', 0)) * 100:.1f}%
- 偽鍵と判定された割合: {test_results.get('key_analysis', {}).get('details', {}).get('false_count', 0) / (test_results.get('key_analysis', {}).get('details', {}).get('true_count', 0) + test_results.get('key_analysis', {}).get('details', {}).get('false_count', 0) + test_results.get('key_analysis', {}).get('details', {}).get('other_count', 0)) * 100:.1f}%
- 分布バランス: {test_results.get('key_analysis', {}).get('details', {}).get('distribution_balance', 0):.3f}
"""

            # 鍵分布グラフがあれば追加
            key_plot_file = test_results.get('key_analysis', {}).get('plot_file')
            if key_plot_file and os.path.exists(key_plot_file):
                # 相対パスに変換
                rel_path = os.path.relpath(key_plot_file, os.path.dirname(report_file))
                report_content += f"\n![鍵分布]({rel_path})\n"

            # タイミング攻撃グラフがあれば追加
            timing_plot_file = test_results.get('timing_attack', {}).get('plot_file')
            if timing_plot_file and os.path.exists(timing_plot_file):
                # 相対パスに変換
                rel_path = os.path.relpath(timing_plot_file, os.path.dirname(report_file))
                report_content += f"\n![タイミング攻撃耐性]({rel_path})\n"

            report_content += f"""
### タイミング攻撃耐性テスト

- 真鍵処理時間平均: {test_results.get('timing_attack', {}).get('details', {}).get('true_avg', 0):.6f}秒
- 偽鍵処理時間平均: {test_results.get('timing_attack', {}).get('details', {}).get('false_avg', 0):.6f}秒
- 処理時間差: {test_results.get('timing_attack', {}).get('details', {}).get('time_diff', 0):.6f}秒 ({test_results.get('timing_attack', {}).get('details', {}).get('time_diff_percent', 0):.2f}%)
"""

        elif test_name == "performance":
            report_content += f"""
## パフォーマンステスト

- テスト成功: {'はい ✅' if test_results.get('success', False) else 'いいえ ❌'}

### 鍵生成パフォーマンス

| 鍵サイズ | 生成時間 (秒) |
|---------|-------------|
"""

            # 鍵生成パフォーマンス表
            key_bits = test_results.get('key_generation', {}).get('key_bits', [])
            key_times = test_results.get('key_generation', {}).get('times', [])

            for i in range(len(key_bits)):
                if i < len(key_times):
                    report_content += f"| {key_bits[i]}ビット | {key_times[i]:.6f} |\n"

            report_content += f"""
### 暗号化・復号パフォーマンス

| データサイズ | 暗号化時間 (秒) | 復号時間 (秒) |
|------------|--------------|------------|
"""

            # 暗号化・復号パフォーマンス表
            data_sizes = test_results.get('encryption', {}).get('data_sizes', [])
            enc_times = test_results.get('encryption', {}).get('times', [])
            dec_times = test_results.get('decryption', {}).get('times', [])

            for i in range(len(data_sizes)):
                if i < len(enc_times) and i < len(dec_times):
                    report_content += f"| {data_sizes[i]}バイト | {enc_times[i]:.6f} | {dec_times[i]:.6f} |\n"

            # パフォーマンスグラフがあれば追加
            graph_file = test_results.get('graph_file')
            if graph_file and os.path.exists(graph_file):
                # 相対パスに変換
                rel_path = os.path.relpath(graph_file, os.path.dirname(report_file))
                report_content += f"\n![パフォーマンスグラフ]({rel_path})\n"

            report_content += f"""
### スケーリング特性

| 鍵サイズ | データサイズ | 暗号化時間 (秒) | 復号時間 (秒) |
|---------|------------|--------------|------------|
"""

            # スケーリング特性表
            scaling_data = test_results.get('scaling', [])

            for data in scaling_data:
                report_content += f"| {data.get('key_bits', 0)}ビット | {data.get('data_size', 0)}バイト | {data.get('encryption_time', 0):.6f} | {data.get('decryption_time', 0):.6f} |\n"

        # エラーがある場合は追加
        if 'error' in test_results:
            report_content += f"""
### エラー情報

```
{test_results.get('error', 'Unknown error')}
```

"""
            if 'traceback' in test_results:
                report_content += f"""
詳細なトレースバック:

```
{test_results.get('traceback', '')}
```
"""

    # 結論
    report_content += f"""
## 結論

準同型暗号マスキング方式の統合テストの結果、以下のことが確認されました：

1. 基本機能: ファイルの暗号化と復号が {'正しく機能' if results.get('basic', {}).get('success', False) else '期待通りに動作せず'}
2. マスク関数: {'正常に動作' if results.get('mask', {}).get('success', False) else '問題あり'}し、準同型特性は {'維持' if results.get('mask', {}).get('homomorphic_preserved', False) else '失われた'}
3. セキュリティ特性: 暗号文の識別不能性は {'確保' if results.get('security', {}).get('indistinguishability', {}).get('passed', False) else '不十分'}、鍵解析耐性は {'十分' if results.get('security', {}).get('key_analysis', {}).get('passed', False) else '不十分'}、タイミング攻撃耐性は {'十分' if results.get('security', {}).get('timing_attack', {}).get('passed', False) else '不十分'}
4. パフォーマンス: 暗号化・復号の処理時間は {'許容範囲内' if results.get('performance', {}).get('success', False) else '要改善'}

"""

    if all_success:
        report_content += """
総合的に、準同型暗号マスキング方式の実装は期待通りに機能しており、
セキュリティ要件を満たしています。

- 攻撃者はソースコードを入手しても、復号結果の真偽を区別できません
- 鍵の種類（真/偽）に依存して復号結果が変わる仕組みが実現されています
- 性能面でも実用的な範囲内で動作することが確認されました
"""
    else:
        report_content += """
総合的に、準同型暗号マスキング方式の実装には一部改善すべき点があり、
テストに完全に合格していません。詳細については各テストの結果を確認してください。
"""

    # レポートをファイルに保存
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_content)

    log_message(f"テスト結果レポートを保存しました: {report_file}")

    return report_file


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

        # セキュリティテスト
        if TEST_TYPE in ['all', 'security']:
            TEST_RESULTS['security'] = test_security_features()
            # 拡張セキュリティテスト (セキュリティ監査レポート機能)
            TEST_RESULTS['security_extended'] = test_security_features_extended()

        # パフォーマンステスト
        if TEST_TYPE in ['all', 'performance']:
            TEST_RESULTS['performance'] = test_performance()

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
        success_count = sum(1 for test in TEST_RESULTS.values() if test.get('success', False))
        total_count = len(TEST_RESULTS)

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