#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
セキュアな準同型暗号マスキング方式のデモスクリプト

このスクリプトは、準同型暗号を使用して真偽両方の情報を安全に暗号化し、
暗号文からどちらが真の情報かを区別できないようにするデモです。
"""

import os
import sys
import time
import json
import argparse
import hashlib
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 安全な準同型暗号実装をインポート
from method_8_homomorphic.indistinguishable_crypto import (
    SecureHomomorphicCrypto, encrypt_file_with_dual_keys, decrypt_file_with_key
)

# 出力ディレクトリの確認
os.makedirs("test_output", exist_ok=True)

def print_header(text):
    """ヘッダーテキストを出力"""
    print("\n" + "=" * 80)
    print(f" {text} ".center(80, "="))
    print("=" * 80)

def print_subheader(text):
    """サブヘッダーテキストを出力"""
    print("\n" + "-" * 60)
    print(f" {text} ".center(60, "-"))
    print("-" * 60)

def create_sample_files():
    """サンプルファイルを作成"""
    print_subheader("サンプルファイルの作成")

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
    true_path = "test_output/true_content.txt"
    false_path = "test_output/false_content.txt"

    with open(true_path, 'w', encoding='utf-8') as f:
        f.write(true_content)

    with open(false_path, 'w', encoding='utf-8') as f:
        f.write(false_content)

    print(f"真のコンテンツをファイルに保存: {true_path}")
    print(f"偽のコンテンツをファイルに保存: {false_path}")

    return true_path, false_path

def encrypt_sample_files(true_file, false_file, key_bits=1024):
    """サンプルファイルを暗号化"""
    print_subheader("準同型暗号による暗号化")

    # 現在時刻を含んだファイル名
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    encrypted_file = f"test_output/encrypted_{timestamp}.hmc"

    # 暗号化の実行
    print("暗号化中...")
    start_time = time.time()

    encrypt_file_with_dual_keys(
        true_file, false_file, encrypted_file,
        key_bits=key_bits, use_advanced_masks=True
    )

    end_time = time.time()
    print(f"暗号化完了: {end_time - start_time:.2f}秒")

    # サイズを表示
    true_size = os.path.getsize(true_file)
    false_size = os.path.getsize(false_file)
    encrypted_size = os.path.getsize(encrypted_file)

    print(f"真のファイルサイズ: {true_size} バイト")
    print(f"偽のファイルサイズ: {false_size} バイト")
    print(f"暗号化ファイルサイズ: {encrypted_size} バイト")
    print(f"膨張率: {encrypted_size / (true_size + false_size):.2f}倍")

    return encrypted_file

def decrypt_sample_file(encrypted_file, key_type):
    """サンプルファイルを復号"""
    print_subheader(f"{key_type}キーでの復号")

    # タイムスタンプを含む出力ファイル名
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = f"test_output/decrypted_{key_type}_{timestamp}.txt"

    # 復号の実行
    print("復号中...")
    start_time = time.time()

    decrypt_file_with_key(
        encrypted_file, output_file, key_type=key_type
    )

    end_time = time.time()
    print(f"復号完了: {end_time - start_time:.2f}秒")

    # 復号されたファイルの内容を表示
    try:
        with open(output_file, 'rb') as f:
            content_bytes = f.read()

        # まずUTF-8でのデコードを試みる
        try:
            content = content_bytes.decode('utf-8', errors='replace')
            is_text = True
        except UnicodeDecodeError:
            # テキストとして解釈できない場合はバイナリとして扱う
            content = f"バイナリデータ ({len(content_bytes)} バイト)"
            is_text = False

        print("\n復号されたコンテンツのプレビュー:")
        print("-" * 40)

        if is_text:
            # 最初の5行だけ表示
            preview_lines = content.split('\n')[:5]
            print('\n'.join(preview_lines))
            if len(preview_lines) < len(content.split('\n')):
                print("...")
        else:
            # バイナリデータの場合は16進ダンプを表示
            hex_dump = ' '.join(f'{b:02x}' for b in content_bytes[:30])
            print(f"16進数表示: {hex_dump}...")

        print("-" * 40)
    except Exception as e:
        print(f"ファイル読み込み中にエラーが発生: {e}")

    return output_file

def compare_performance():
    """パフォーマンス比較グラフを生成"""
    print_subheader("パフォーマンス比較")

    # テスト用のファイルサイズ
    sizes = [100, 1000, 10000, 100000]
    encryption_times = []
    true_decryption_times = []
    false_decryption_times = []

    print("各サイズでのパフォーマンスを測定中...")
    for size in sizes:
        print(f"サイズ: {size} バイト")

        # テスト用データ
        true_data = os.urandom(size)
        false_data = os.urandom(size)

        # 一時ファイル
        true_file = f"test_output/temp_true_{size}.bin"
        false_file = f"test_output/temp_false_{size}.bin"
        encrypted_file = f"test_output/temp_encrypted_{size}.bin"

        with open(true_file, 'wb') as f:
            f.write(true_data)

        with open(false_file, 'wb') as f:
            f.write(false_data)

        # 暗号化時間測定
        crypto = SecureHomomorphicCrypto(key_bits=1024)
        crypto.generate_keys()

        start_time = time.time()
        with open(true_file, 'rb') as f:
            true_content = f.read()
        with open(false_file, 'rb') as f:
            false_content = f.read()
        encrypted_data = crypto.encrypt_dual_content(true_content, false_content)
        crypto.save_encrypted_data(encrypted_data, encrypted_file)
        encryption_time = time.time() - start_time
        encryption_times.append(encryption_time)

        # 復号時間測定
        for key_type, times_list in [("true", true_decryption_times), ("false", false_decryption_times)]:
            start_time = time.time()
            decrypted = crypto.decrypt_content(encrypted_data, key_type)
            times_list.append(time.time() - start_time)

        # 一時ファイルの削除
        for file in [true_file, false_file, encrypted_file]:
            if os.path.exists(file):
                os.remove(file)

    # グラフの作成
    plt.figure(figsize=(12, 8))

    # 暗号化時間グラフ
    plt.subplot(2, 1, 1)
    plt.plot(sizes, encryption_times, 'o-', label="暗号化時間")
    for i, (size, time_val) in enumerate(zip(sizes, encryption_times)):
        plt.annotate(f"{time_val:.3f}秒", (size, time_val),
                    textcoords="offset points", xytext=(0,10), ha='center')

    plt.title('ファイルサイズと暗号化時間の関係')
    plt.xlabel('ファイルサイズ (バイト)')
    plt.ylabel('処理時間 (秒)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.xscale('log')

    # 復号時間グラフ
    plt.subplot(2, 1, 2)
    plt.plot(sizes, true_decryption_times, 'o-', label="真の復号時間")
    plt.plot(sizes, false_decryption_times, 's-', label="偽の復号時間")

    for i, ((size, t_time), f_time) in enumerate(zip(zip(sizes, true_decryption_times), false_decryption_times)):
        plt.annotate(f"{t_time:.3f}秒", (size, t_time),
                    textcoords="offset points", xytext=(0,10), ha='center')
        plt.annotate(f"{f_time:.3f}秒", (size, f_time),
                    textcoords="offset points", xytext=(0,-15), ha='center')

    plt.title('ファイルサイズと復号時間の関係')
    plt.xlabel('ファイルサイズ (バイト)')
    plt.ylabel('処理時間 (秒)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.xscale('log')

    plt.tight_layout()

    # 保存
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    performance_file = f"test_output/performance_{timestamp}.png"
    plt.savefig(performance_file)

    # 最新版としても保存
    latest_file = "test_output/performance_latest.png"
    plt.savefig(latest_file)

    plt.close()

    print(f"パフォーマンスグラフを保存しました: {performance_file}")
    print(f"最新のパフォーマンスグラフ: {latest_file}")

    return performance_file

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description="セキュアな準同型暗号マスキング方式のデモ")
    parser.add_argument("--mode", choices=["all", "create", "encrypt", "decrypt-true", "decrypt-false", "performance"],
                       default="all", help="実行するデモのモード")
    parser.add_argument("--true-file", help="真のファイルパス（暗号化時に使用）")
    parser.add_argument("--false-file", help="偽のファイルパス（暗号化時に使用）")
    parser.add_argument("--encrypted-file", help="暗号化ファイルパス（復号時に使用）")
    parser.add_argument("--key-bits", type=int, default=1024, help="鍵のビット数")

    args = parser.parse_args()

    print_header("セキュアな準同型暗号マスキング方式デモ")

    try:
        # モードに応じた処理
        if args.mode == "all" or args.mode == "create":
            true_file, false_file = create_sample_files()
        else:
            true_file = args.true_file
            false_file = args.false_file

        if args.mode == "all" or args.mode == "encrypt":
            if true_file and false_file:
                encrypted_file = encrypt_sample_files(true_file, false_file, args.key_bits)
            else:
                print("暗号化にはtrue_fileとfalse_fileが必要です。")
                if args.mode == "encrypt":
                    return
        else:
            encrypted_file = args.encrypted_file

        if args.mode == "all" or args.mode == "decrypt-true":
            if encrypted_file:
                decrypt_sample_file(encrypted_file, "true")
            else:
                print("復号にはencrypted_fileが必要です。")
                if args.mode == "decrypt-true":
                    return

        if args.mode == "all" or args.mode == "decrypt-false":
            if encrypted_file:
                decrypt_sample_file(encrypted_file, "false")
            else:
                print("復号にはencrypted_fileが必要です。")
                if args.mode == "decrypt-false":
                    return

        if args.mode == "all" or args.mode == "performance":
            compare_performance()

        print("\nデモが完了しました。")
        print("出力ファイルは test_output/ ディレクトリにあります。")

    except Exception as e:
        print(f"エラーが発生しました: {e}")

if __name__ == "__main__":
    main()