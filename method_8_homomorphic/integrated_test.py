#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の統合テスト

暗号化と復号の一連の流れをテストするためのスクリプト
"""

import os
import sys
import json
import base64
import hashlib
import time
import random
import binascii
import tempfile
import shutil
import argparse
from typing import Dict, List, Any, Optional, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 暗号化/復号モジュールをインポート
from method_8_homomorphic.encrypt import (
    encrypt_files,
    parse_arguments as encrypt_parse_arguments
)
from method_8_homomorphic.decrypt import (
    decrypt_file,
    parse_arguments as decrypt_parse_arguments
)
# 暗号モジュールをインポート
from method_8_homomorphic.homomorphic import (
    PaillierCrypto,
    derive_key_from_password,
    load_keys
)
# 鍵解析モジュールをインポート
from method_8_homomorphic.key_analyzer import (
    analyze_key_type,
    debug_analyze_key
)
# マスク関数モジュールをインポート
from method_8_homomorphic.crypto_mask import (
    transform_between_true_false
)
# アダプターモジュールをインポート
from method_8_homomorphic.crypto_adapters import (
    process_data_for_encryption,
    process_data_after_decryption
)
# デバッグユーティリティをインポート
from method_8_homomorphic.debug_utils import (
    debug_print_key_info,
    debug_print_json
)
# 識別不能性モジュールをインポート
from method_8_homomorphic.indistinguishable import IndistinguishableWrapper

# 結果を保存するディレクトリ
TEST_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'test_output')

def ensure_test_output_dir():
    """テスト出力ディレクトリを確保"""
    if not os.path.exists(TEST_OUTPUT_DIR):
        os.makedirs(TEST_OUTPUT_DIR)
        print(f"テスト出力ディレクトリを作成しました: {TEST_OUTPUT_DIR}")

def plot_encryption_statistics(
    original_sizes: Dict[str, int],
    encrypted_sizes: Dict[str, int],
    encryption_times: Dict[str, float],
    decryption_times: Dict[str, float]
):
    """暗号化統計情報をプロット"""
    # 出力ディレクトリを確保
    ensure_test_output_dir()

    # フォントのプロパティ設定
    plt.rcParams.update({
        'font.size': 12,
        'axes.titlesize': 14,
        'axes.labelsize': 12
    })

    # プロット領域を確保（2x2のサブプロット）
    fig, axs = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('準同型暗号マスキング方式 - パフォーマンス統計', fontsize=16)

    # 1. ファイルサイズのバープロット
    files = list(original_sizes.keys())
    orig_sizes = [original_sizes[f] for f in files]
    enc_sizes = [encrypted_sizes[f] for f in files]

    axs[0, 0].bar(files, orig_sizes, label='元のサイズ', alpha=0.7, color='blue')
    axs[0, 0].bar(files, enc_sizes, label='暗号化後サイズ', alpha=0.7, color='red')
    axs[0, 0].set_ylabel('サイズ (バイト)')
    axs[0, 0].set_title('ファイルサイズ比較')
    axs[0, 0].legend()
    axs[0, 0].grid(True, alpha=0.3)

    # 2. 暗号化率のバープロット
    enc_ratios = [enc_sizes[i] / orig_sizes[i] if orig_sizes[i] > 0 else 0 for i in range(len(files))]
    axs[0, 1].bar(files, enc_ratios, alpha=0.7, color='green')
    axs[0, 1].set_ylabel('暗号化サイズ倍率')
    axs[0, 1].set_title('暗号化サイズ倍率')
    for i, ratio in enumerate(enc_ratios):
        axs[0, 1].text(i, ratio + 0.1, f"{ratio:.2f}x", ha='center')
    axs[0, 1].grid(True, alpha=0.3)

    # 3. 処理時間のバープロット
    enc_times = [encryption_times[f] for f in files]
    dec_times = [decryption_times[f] for f in files]

    axs[1, 0].bar(files, enc_times, label='暗号化時間', alpha=0.7, color='orange')
    axs[1, 0].bar(files, dec_times, label='復号時間', alpha=0.7, color='purple')
    axs[1, 0].set_ylabel('処理時間 (秒)')
    axs[1, 0].set_title('処理時間比較')
    axs[1, 0].legend()
    axs[1, 0].grid(True, alpha=0.3)

    # 4. 暗号化スループット (バイト/秒)
    enc_throughput = [orig_sizes[i] / enc_times[i] if enc_times[i] > 0 else 0 for i in range(len(files))]
    dec_throughput = [enc_sizes[i] / dec_times[i] if dec_times[i] > 0 else 0 for i in range(len(files))]

    axs[1, 1].bar(files, enc_throughput, label='暗号化スループット', alpha=0.7, color='cyan')
    axs[1, 1].bar(files, dec_throughput, label='復号スループット', alpha=0.7, color='magenta')
    axs[1, 1].set_ylabel('スループット (バイト/秒)')
    axs[1, 1].set_title('処理スループット')
    axs[1, 1].legend()
    axs[1, 1].grid(True, alpha=0.3)

    # レイアウト調整とプロット保存
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(os.path.join(TEST_OUTPUT_DIR, 'homomorphic_operations.png'), dpi=300)
    print(f"統計情報プロットをファイルに保存しました: {os.path.join(TEST_OUTPUT_DIR, 'homomorphic_operations.png')}")

    # メモリリーク防止のためプロットをクローズ
    plt.close(fig)

def run_encryption_test(true_file, false_file, output_path):
    """暗号化テストを実行"""
    print("\n=== 暗号化テスト ===")
    print("=== 準同型暗号マスキング方式の暗号化テスト ===")

    start_time = time.time()
    stats = {
        "start_time": start_time,
        "success": False,
        "true_file": true_file,
        "false_file": false_file,
        "output_path": output_path
    }

    # 引数の準備
    class Args:
        pass

    args = Args()
    args.true_file = true_file
    args.false_file = false_file
    args.output = output_path
    args.algorithm = 'paillier'
    args.key = None
    args.password = "test_password_for_encryption"
    args.advanced_mask = True
    args.key_bits = 1024  # 小さい値にして高速化
    args.save_keys = False
    args.keys_dir = None
    args.verbose = False
    args.force_data_type = 'auto'
    args.indistinguishable = True
    args.noise_intensity = 0.05
    args.redundancy_factor = 1
    args.shuffle_seed = None

    try:
        # 暗号化を実行
        master_key, encrypted_data = encrypt_files(args)

        # 鍵の導出
        seed = hashlib.sha256(master_key).digest()
        true_key = hashlib.pbkdf2_hmac('sha256', seed, b'true', 10000, 32)
        false_key = hashlib.pbkdf2_hmac('sha256', seed, b'false', 10000, 32)

        # 結果の統計情報を収集
        end_time = time.time()
        stats["end_time"] = end_time
        stats["elapsed"] = end_time - start_time
        stats["success"] = True
        stats["encrypted_size"] = os.path.getsize(output_path)
        stats["true_size"] = os.path.getsize(true_file)
        stats["false_size"] = os.path.getsize(false_file)

        # メタデータの収集
        stats["metadata"] = encrypted_data.get("metadata", {})

        return stats, true_key, false_key

    except Exception as e:
        print(f"暗号化中に問題が発生しました: {e}")
        stats["error"] = str(e)
        raise

def run_decryption_test(
    encrypted_file_path: str,
    true_key: bytes,
    false_key: bytes,
    true_output_path: str,
    false_output_path: str
) -> Dict[str, Any]:
    """
    復号テストを実行

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        true_key: 真鍵
        false_key: 偽鍵
        true_output_path: 真鍵での復号結果の出力パス
        false_output_path: 偽鍵での復号結果の出力パス

    Returns:
        結果情報辞書
    """
    print(f"=== 準同型暗号マスキング方式の復号テスト ===")

    # 統計情報用の辞書を初期化
    stats = {
        'encrypted_file': os.path.basename(encrypted_file_path),
        'true_output': os.path.basename(true_output_path),
        'false_output': os.path.basename(false_output_path),
        'true_decryption_time': 0,
        'false_decryption_time': 0,
        'true_success': False,
        'false_success': False
    }

    # 真鍵での復号
    print("真鍵での復号を実行中...")
    start_time = time.time()
    true_result = decrypt_file(
        input_file=encrypted_file_path,
        output_file=true_output_path,
        key_bytes=true_key,
        use_enhanced_security=True
    )
    true_decryption_time = time.time() - start_time

    # 偽鍵での復号
    print("偽鍵での復号を実行中...")
    start_time = time.time()
    false_result = decrypt_file(
        input_file=encrypted_file_path,
        output_file=false_output_path,
        key_bytes=false_key,
        use_enhanced_security=True
    )
    false_decryption_time = time.time() - start_time

    # 結果を記録
    stats['true_decryption_time'] = true_decryption_time
    stats['false_decryption_time'] = false_decryption_time
    stats['true_success'] = true_result.get('success', False)
    stats['false_success'] = false_result.get('success', False)

    if os.path.exists(true_output_path):
        stats['true_output_size'] = os.path.getsize(true_output_path)

    if os.path.exists(false_output_path):
        stats['false_output_size'] = os.path.getsize(false_output_path)

    return stats

def integrated_test():
    """統合テストを実行"""
    # テスト出力ディレクトリを確保
    ensure_test_output_dir()

    # テスト対象ファイル
    true_file = TRUE_TEXT_PATH
    false_file = FALSE_TEXT_PATH

    # 出力ファイルパス
    encrypted_file = os.path.join(TEST_OUTPUT_DIR, 'encrypted_data.json')
    true_output_file = os.path.join(TEST_OUTPUT_DIR, 'decrypted_true.txt')
    false_output_file = os.path.join(TEST_OUTPUT_DIR, 'decrypted_false.txt')

    # 暗号化テスト
    print("\n=== 暗号化テスト ===")
    try:
        encryption_stats, true_key, false_key = run_encryption_test(
            true_file_path=true_file,
            false_file_path=false_file,
            output_path=encrypted_file,
            password="test_password_123"
        )

        # 暗号化結果の表示
        print(f"暗号化完了: {encryption_stats['output_file']}")
        print(f"暗号化時間: {encryption_stats['encryption_time']:.2f}秒")
        print(f"元ファイルサイズ (真): {encryption_stats['true_size']} バイト")
        print(f"元ファイルサイズ (偽): {encryption_stats['false_size']} バイト")
        print(f"暗号化ファイルサイズ: {encryption_stats['encrypted_size']} バイト")

        if true_key and false_key:
            print(f"真鍵: {true_key.hex()[:16]}...")
            print(f"偽鍵: {false_key.hex()[:16]}...")

        # 復号テスト
        print("\n=== 復号テスト ===")
        decryption_stats = run_decryption_test(
            encrypted_file_path=encrypted_file,
            true_key=true_key,
            false_key=false_key,
            true_output_path=true_output_file,
            false_output_path=false_output_file
        )

        # 復号結果の表示
        print(f"真鍵での復号結果: {'成功' if decryption_stats['true_success'] else '失敗'}")
        print(f"偽鍵での復号結果: {'成功' if decryption_stats['false_success'] else '失敗'}")
        print(f"真鍵での復号時間: {decryption_stats['true_decryption_time']:.2f}秒")
        print(f"偽鍵での復号時間: {decryption_stats['false_decryption_time']:.2f}秒")

        if os.path.exists(true_output_file):
            print(f"真鍵での復号ファイルサイズ: {decryption_stats.get('true_output_size', 0)} バイト")

        if os.path.exists(false_output_file):
            print(f"偽鍵での復号ファイルサイズ: {decryption_stats.get('false_output_size', 0)} バイト")

        # 統計情報のプロット
        plot_encryption_statistics(
            original_sizes={
                '真ファイル': encryption_stats['true_size'],
                '偽ファイル': encryption_stats['false_size']
            },
            encrypted_sizes={
                '真ファイル': encryption_stats['encrypted_size'],
                '偽ファイル': encryption_stats['encrypted_size']
            },
            encryption_times={
                '真ファイル': encryption_stats['encryption_time'],
                '偽ファイル': encryption_stats['encryption_time']
            },
            decryption_times={
                '真ファイル': decryption_stats['true_decryption_time'],
                '偽ファイル': decryption_stats['false_decryption_time']
            }
        )

        # ファイル内容の検証
        print("\n=== 復号ファイルの内容検証 ===")
        if os.path.exists(true_output_file) and os.path.exists(false_output_file):
            # ファイル内容の読み込み
            with open(true_file, 'rb') as f:
                original_true_content = f.read()

            with open(false_file, 'rb') as f:
                original_false_content = f.read()

            with open(true_output_file, 'rb') as f:
                decrypted_true_content = f.read()

            with open(false_output_file, 'rb') as f:
                decrypted_false_content = f.read()

            # 内容の一致を確認
            true_match = original_true_content == decrypted_true_content
            false_match = original_false_content == decrypted_false_content

            # 内容の検証結果を表示
            print(f"真ファイルの内容一致: {'一致' if true_match else '不一致'}")
            print(f"偽ファイルの内容一致: {'一致' if false_match else '不一致'}")

            # 不一致の場合は詳細情報を表示
            if not true_match:
                print(f"[警告] 真ファイルの内容が一致しません!")
                print(f"元のファイルサイズ: {len(original_true_content)} バイト")
                print(f"復号ファイルサイズ: {len(decrypted_true_content)} バイト")
                print(f"元のファイル先頭: {original_true_content[:50]}")
                print(f"復号ファイル先頭: {decrypted_true_content[:50]}")

            if not false_match:
                print(f"[警告] 偽ファイルの内容が一致しません!")
                print(f"元のファイルサイズ: {len(original_false_content)} バイト")
                print(f"復号ファイルサイズ: {len(decrypted_false_content)} バイト")
                print(f"元のファイル先頭: {original_false_content[:50]}")
                print(f"復号ファイル先頭: {decrypted_false_content[:50]}")

        # テスト結果のまとめ
        print("\n=== テスト結果のまとめ ===")
        success = decryption_stats['true_success'] and decryption_stats['false_success']
        print(f"総合テスト結果: {'成功' if success else '失敗'}")

        return success

    except Exception as e:
        print(f"テスト実行中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # 現在の時刻を表示
    print(f"テスト開始時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # テストを実行
    success = integrated_test()

    # 終了時刻と結果を表示
    print(f"テスト終了時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"テスト結果: {'成功' if success else '失敗'}")

    # 終了コード
    sys.exit(0 if success else 1)