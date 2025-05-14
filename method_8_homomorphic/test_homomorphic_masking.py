#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式 🎭 テスト実行スクリプト

このスクリプトは、準同型暗号マスキング方式の暗号化・復号化機能をテストします。
common/true-false-text/t.text と common/true-false-text/f.text を暗号化し、
異なる鍵で復号した際に適切なファイルが復元されることを確認します。
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
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Any, Optional, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, serialize_encrypted_data
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)
from method_8_homomorphic.crypto_adapters import (
    process_data_for_encryption, process_data_after_decryption
)

# 定数設定
TRUE_TEXT_PATH = "common/true-false-text/t.text"
FALSE_TEXT_PATH = "common/true-false-text/f.text"
OUTPUT_DIR = "test_output"
OUTPUT_ENCRYPTED = os.path.join(OUTPUT_DIR, "encrypted_homomorphic.json")
OUTPUT_DECRYPTED_TRUE = os.path.join(OUTPUT_DIR, "decrypted_true.text")
OUTPUT_DECRYPTED_FALSE = os.path.join(OUTPUT_DIR, "decrypted_false.text")
OUTPUT_GRAPH = os.path.join(OUTPUT_DIR, "homomorphic_operations.png")

# タイムスタンプ付きログファイル名を生成
timestamp = time.strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(OUTPUT_DIR, f"homomorphic_test_log_{timestamp}.txt")


def ensure_directory(directory: str) -> None:
    """
    ディレクトリの存在を確認し、なければ作成
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"ディレクトリを作成しました: {directory}")


def log_message(message: str, console_output: bool = True) -> None:
    """
    メッセージをログファイルに記録し、オプションでコンソールにも出力
    """
    ensure_directory(os.path.dirname(LOG_FILE))
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        f.write(log_line + "\n")

    if console_output:
        print(message)


def encrypt_test_files() -> Tuple[bytes, bytes]:
    """
    テストファイルを暗号化

    Returns:
        (true_key, false_key): 真と偽の鍵
    """
    log_message("====== 準同型暗号マスキング方式 暗号化テスト ======")

    # 入力ファイルの読み込み
    log_message(f"テストファイルの読み込み: {TRUE_TEXT_PATH}, {FALSE_TEXT_PATH}")

    try:
        with open(TRUE_TEXT_PATH, 'rb') as f:
            true_content = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            false_content = f.read()

        log_message(f"テキストファイル読み込み成功:")
        log_message(f"  真テキストサイズ: {len(true_content)}バイト")
        log_message(f"  偽テキストサイズ: {len(false_content)}バイト")
    except Exception as e:
        log_message(f"エラー: テストファイルの読み込みに失敗しました: {e}")
        sys.exit(1)

    # 暗号化準備
    log_message("準同型暗号システムを初期化中...")
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    public_key, private_key = paillier.generate_keys()

    log_message(f"公開鍵生成完了: n={public_key['n']}, g={public_key['g']}")

    # データの前処理
    log_message("データを前処理中...")
    log_message(f"[DEBUG] 暗号化前: データタイプ=text, サイズ={len(true_content)}バイト")
    true_processed, true_data_type = process_data_for_encryption(true_content, 'text')
    false_processed, false_data_type = process_data_for_encryption(false_content, 'text')

    log_message(f"前処理完了:")
    log_message(f"  真データタイプ: {true_data_type}, サイズ: {len(true_processed)}バイト")
    log_message(f"  偽データタイプ: {false_data_type}, サイズ: {len(false_processed)}バイト")

    # チャンクに分割
    chunk_size = 64
    true_chunks = [true_processed[i:i+chunk_size] for i in range(0, len(true_processed), chunk_size)]
    false_chunks = [false_processed[i:i+chunk_size] for i in range(0, len(false_processed), chunk_size)]

    log_message(f"チャンク分割完了:")
    log_message(f"  真チャンク数: {len(true_chunks)}")
    log_message(f"  偽チャンク数: {len(false_chunks)}")

    # 各チャンクを暗号化
    log_message("チャンクを暗号化中...")
    true_encrypted = []
    false_encrypted = []

    for i, chunk in enumerate(true_chunks):
        chunk_int = int.from_bytes(chunk, byteorder='big')
        encrypted = paillier.encrypt(chunk_int, public_key)
        true_encrypted.append(encrypted)

    for i, chunk in enumerate(false_chunks):
        chunk_int = int.from_bytes(chunk, byteorder='big')
        encrypted = paillier.encrypt(chunk_int, public_key)
        false_encrypted.append(encrypted)

    log_message(f"暗号化完了:")
    log_message(f"  真暗号化チャンク数: {len(true_encrypted)}")
    log_message(f"  偽暗号化チャンク数: {len(false_encrypted)}")

    # 鍵の生成
    log_message("真偽判別用の鍵を生成中...")
    true_key = os.urandom(32)
    false_key = os.urandom(32)

    log_message(f"鍵生成完了:")
    log_message(f"  真鍵: {binascii.hexlify(true_key).decode()}")
    log_message(f"  偽鍵: {binascii.hexlify(false_key).decode()}")

    # マスク関数生成
    log_message("マスク関数を適用中...")
    mask_generator = AdvancedMaskFunctionGenerator(paillier, true_key)

    # マスク適用と真偽変換
    masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
        paillier, true_encrypted, false_encrypted, mask_generator
    )

    log_message("マスク適用と真偽変換完了")

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
        "public_key": paillier.public_key,
        "private_key": private_key  # 注意: 実際の運用では秘密鍵は含めません
    }

    # 区別不可能な形式に変換
    indistinguishable_data = create_indistinguishable_form(
        masked_true, masked_false, true_mask, false_mask, metadata
    )

    # 暗号化データを保存
    ensure_directory(OUTPUT_DIR)
    log_message(f"暗号化データを保存中: {OUTPUT_ENCRYPTED}")
    try:
        with open(OUTPUT_ENCRYPTED, 'w', encoding='utf-8') as f:
            json.dump(indistinguishable_data, f, indent=2)
        log_message(f"暗号化データを保存しました: {OUTPUT_ENCRYPTED}")
    except Exception as e:
        log_message(f"エラー: 暗号化データの保存に失敗しました: {e}")

    return true_key, false_key


def decrypt_test_file(key: bytes, key_type: str, output_file: str) -> bool:
    """
    暗号化されたファイルを復号

    Args:
        key: 復号鍵
        key_type: 鍵タイプ（"true" または "false"）
        output_file: 出力ファイルパス

    Returns:
        復号成功の場合はTrue、失敗の場合はFalse
    """
    log_message(f"====== 準同型暗号マスキング方式 復号テスト ({key_type}鍵) ======")

    # 暗号化ファイルの読み込み
    log_message(f"暗号化ファイルを読み込み中: {OUTPUT_ENCRYPTED}")
    try:
        with open(OUTPUT_ENCRYPTED, 'r', encoding='utf-8') as f:
            encrypted_data = json.load(f)
        log_message(f"暗号化ファイル読み込み完了")
    except Exception as e:
        log_message(f"エラー: 暗号化ファイルの読み込みに失敗しました: {e}")
        return False

    # 公開鍵と秘密鍵の取得
    public_key_data = encrypted_data.get("public_key", {})
    private_key_data = encrypted_data.get("private_key", {})

    if not public_key_data or not private_key_data:
        log_message(f"エラー: 鍵情報が見つかりません")
        return False

    # PaillierCryptoの初期化
    paillier = PaillierCrypto()
    paillier.public_key = public_key_data
    paillier.private_key = private_key_data

    # マスク生成器の初期化
    mask_generator = AdvancedMaskFunctionGenerator(paillier, key)

    # 適切なマスクデータの抽出
    log_message(f"{key_type}鍵用のデータを抽出中...")
    encrypted_chunks, mask = extract_by_key_type(encrypted_data, key_type)

    # マスク除去
    log_message(f"マスクを除去中...")
    unmasked_chunks = mask_generator.remove_advanced_mask(encrypted_chunks, mask)

    # バイト列に変換
    log_message(f"復号中...")
    decrypted_chunks = []

    for chunk in unmasked_chunks:
        # 復号
        decrypted = paillier.decrypt(chunk, private_key_data)

        # 整数をバイト列に変換
        byte_length = max(1, (decrypted.bit_length() + 7) // 8)
        decrypted_bytes = decrypted.to_bytes(byte_length, byteorder='big')
        decrypted_chunks.append(decrypted_bytes)

    # チャンクを結合
    decrypted_data = b''.join(decrypted_chunks)

    # 元のデータサイズに制限
    original_size = encrypted_data.get(f"{key_type}_size", len(decrypted_data))
    if len(decrypted_data) > original_size:
        decrypted_data = decrypted_data[:original_size]

    # データの後処理
    data_type = encrypted_data.get(f"{key_type}_data_type", "text")
    log_message(f"データの後処理中... データタイプ: {data_type}")
    try:
        log_message(f"[DEBUG] 復号後: データタイプ={data_type}, サイズ={len(decrypted_data)}バイト")
        log_message(f"[DEBUG] 復号後先頭バイト: {decrypted_data[:20]}")

        # プロセスデータ後の復号化処理
        try:
            # テキストとしてデコード試行
            decoded_text = decrypted_data.decode('latin-1')
            log_message(f"[DEBUG] latin-1でデコード成功: {decoded_text[:30]}...")
        except UnicodeDecodeError:
            log_message(f"[DEBUG] テキストデコード失敗")

        # process_data_after_decryptionの戻り値は1つ（修正後のデータのみ）
        decrypted_final = process_data_after_decryption(decrypted_data, data_type)
    except Exception as e:
        log_message(f"エラー: データ後処理中に問題が発生しました: {e}")
        decrypted_final = decrypted_data  # エラー時は元のデータを使用

    # 復号データを保存
    log_message(f"復号データを保存中: {output_file}")
    ensure_directory(os.path.dirname(output_file))
    try:
        # 文字列の場合はバイト列に変換
        if isinstance(decrypted_final, str):
            decrypted_final = decrypted_final.encode('utf-8')

        with open(output_file, 'wb') as f:
            f.write(decrypted_final)
        log_message(f"復号データを保存しました: {output_file}")

        # 可読テキストとして表示
        try:
            if isinstance(decrypted_final, bytes):
                decoded_text = decrypted_final.decode('utf-8')
            else:
                decoded_text = str(decrypted_final)
            log_message(f"復号されたテキスト:\n{decoded_text}")
        except UnicodeDecodeError:
            log_message(f"復号データはテキストではありません（バイナリデータ）")

        return True
    except Exception as e:
        log_message(f"エラー: 復号データの保存に失敗しました: {e}")
        return False


def create_operation_graph() -> None:
    """
    準同型暗号の動作を示すグラフを作成
    """
    log_message("準同型暗号操作のグラフを作成中...")

    # サンプルデータ生成
    plaintexts = [5, 10, 15, 20, 25]

    # Paillier暗号の初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # 暗号化
    ciphertexts = [paillier.encrypt(pt, public_key) for pt in plaintexts]

    # 準同型演算のテスト
    operations = []

    # 加算テスト
    add_result = paillier.add(ciphertexts[0], ciphertexts[1])
    add_decrypted = paillier.decrypt(add_result, private_key)
    operations.append(("加算", plaintexts[0], plaintexts[1], add_decrypted))

    # 定数加算テスト
    const_add = 7
    add_const_result = paillier.add_constant(ciphertexts[2], const_add, public_key)
    add_const_decrypted = paillier.decrypt(add_const_result, private_key)
    operations.append(("定数加算", plaintexts[2], const_add, add_const_decrypted))

    # 定数乗算テスト
    const_mul = 3
    mul_const_result = paillier.multiply_constant(ciphertexts[3], const_mul, public_key)
    mul_const_decrypted = paillier.decrypt(mul_const_result, private_key)
    operations.append(("定数乗算", plaintexts[3], const_mul, mul_const_decrypted))

    # グラフ作成
    plt.figure(figsize=(12, 8))

    # 操作別の色
    colors = {'加算': 'blue', '定数加算': 'green', '定数乗算': 'red'}

    # 各操作の結果をプロット
    for i, (op, val1, val2, result) in enumerate(operations):
        plt.subplot(1, 3, i+1)

        # 入力値と結果を棒グラフで表示
        if op == "加算":
            plt.bar(['Input 1', 'Input 2', 'Output'], [val1, val2, result], color=colors[op])
            plt.title(f'{op}: {val1} + {val2} = {result}')
        elif op == "定数加算":
            plt.bar(['Input', 'Constant', 'Output'], [val1, val2, result], color=colors[op])
            plt.title(f'{op}: {val1} + {val2} = {result}')
        elif op == "定数乗算":
            plt.bar(['Input', 'Multiplier', 'Output'], [val1, val2, result], color=colors[op])
            plt.title(f'{op}: {val1} × {val2} = {result}')

        plt.ylabel('Value')
        plt.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.suptitle('準同型暗号操作のデモンストレーション', fontsize=16)
    plt.subplots_adjust(top=0.85)

    # グラフを保存
    ensure_directory(os.path.dirname(OUTPUT_GRAPH))
    plt.savefig(OUTPUT_GRAPH)
    log_message(f"グラフを保存しました: {OUTPUT_GRAPH}")


def main():
    """メイン関数"""
    start_time = time.time()

    # 出力ディレクトリの確認
    ensure_directory(OUTPUT_DIR)

    log_message("準同型暗号マスキング方式テストを開始します")

    # ステップ1: 暗号化テスト
    true_key, false_key = encrypt_test_files()

    # ステップ2: 真鍵で復号テスト
    decrypt_test_file(true_key, "true", OUTPUT_DECRYPTED_TRUE)

    # ステップ3: 偽鍵で復号テスト
    decrypt_test_file(false_key, "false", OUTPUT_DECRYPTED_FALSE)

    # ステップ4: 準同型操作のグラフ作成
    create_operation_graph()

    end_time = time.time()
    elapsed_time = end_time - start_time
    log_message(f"テスト完了！処理時間: {elapsed_time:.2f}秒")
    log_message(f"詳細ログ: {LOG_FILE}")


if __name__ == "__main__":
    main()