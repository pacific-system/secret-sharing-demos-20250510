#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式のファイル暗号化・復号テスト

このスクリプトは、準同型暗号マスキング方式によるファイル暗号化・復号の
基本機能をテストします。
"""

import os
import sys
import json
import time
import hashlib
import base64
import argparse
from typing import Dict, List, Any, Tuple, Optional

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 必要なモジュールをインポート
from config import (
    TRUE_TEXT_PATH,
    FALSE_TEXT_PATH,
    TEST_OUTPUT_DIR,
    KEY_SIZE_BYTES
)

from homomorphic import derive_key_from_password

from encrypt import encrypt_files
from decrypt import decrypt_file

from crypto_adapters import DataAdapter

def file_encryption_decryption_test(true_file_path: str, false_file_path: str, output_dir: str) -> bool:
    """
    ファイル暗号化・復号のテスト

    Args:
        true_file_path: 真のファイルパス
        false_file_path: 偽のファイルパス
        output_dir: 出力ディレクトリ

    Returns:
        テスト成功の場合はTrue
    """
    print("\n===== 準同型暗号マスキング方式のファイル暗号化・復号テスト =====")

    # 出力ディレクトリの確保
    os.makedirs(output_dir, exist_ok=True)

    # 出力ファイルパス
    encrypted_path = os.path.join(output_dir, "encrypted_test.hmc")
    true_output_path = os.path.join(output_dir, "decrypted_true.txt")
    false_output_path = os.path.join(output_dir, "decrypted_false.txt")

    # テスト用パスワード
    test_password = "test_password_for_file_encryption"

    try:
        # 1. 暗号化
        print("\n1. ファイル暗号化テスト")
        print(f"真ファイル: {true_file_path}")
        print(f"偽ファイル: {false_file_path}")
        print(f"出力ファイル: {encrypted_path}")

        # 引数の準備
        class Args:
            pass

        args = Args()
        args.true_file = true_file_path
        args.false_file = false_file_path
        args.output = encrypted_path
        args.algorithm = 'paillier'
        args.key = None
        args.password = test_password
        args.advanced_mask = True
        args.key_bits = 1024  # 小さめの値で高速化
        args.save_keys = False
        args.keys_dir = None
        args.verbose = True
        args.force_data_type = 'auto'
        args.indistinguishable = True
        args.noise_intensity = 0.05
        args.redundancy_factor = 1
        args.shuffle_seed = None

        # 暗号化処理
        print("暗号化を実行中...")
        start_time = time.time()
        master_key, encrypted_data = encrypt_files(args)
        encryption_time = time.time() - start_time

        # 暗号化結果の確認
        print(f"暗号化完了。所要時間: {encryption_time:.2f}秒")
        print(f"出力ファイルサイズ: {os.path.getsize(encrypted_path)} バイト")

        # マスターキーから真/偽の鍵を導出
        seed = hashlib.sha256(master_key).digest()
        true_key = hashlib.pbkdf2_hmac('sha256', seed, b'true', 10000, KEY_SIZE_BYTES)
        false_key = hashlib.pbkdf2_hmac('sha256', seed, b'false', 10000, KEY_SIZE_BYTES)

        # 2. 真鍵で復号
        print("\n2. 真鍵での復号テスト")
        print(f"入力ファイル: {encrypted_path}")
        print(f"出力ファイル: {true_output_path}")

        start_time = time.time()
        true_result = decrypt_file(
            input_file=encrypted_path,
            output_file=true_output_path,
            key_bytes=true_key,
            key_type="true",
            verbose=True
        )
        true_decryption_time = time.time() - start_time

        print(f"真鍵での復号完了。所要時間: {true_decryption_time:.2f}秒")
        if true_result.get("success", False):
            print("✅ 真鍵での復号に成功")

            # 元のファイルと復号ファイルの比較
            with open(true_file_path, 'rb') as f:
                original_content = f.read()

            with open(true_output_path, 'rb') as f:
                decrypted_content = f.read()

            if original_content == decrypted_content:
                print("✅ 復号されたファイルは元のファイルと完全に一致")
            else:
                print("⚠️ 復号されたファイルは元のファイルと一致しません")
                print(f"元のファイルサイズ: {len(original_content)} バイト")
                print(f"復号ファイルサイズ: {len(decrypted_content)} バイト")
        else:
            print("❌ 真鍵での復号に失敗")
            if "error" in true_result:
                print(f"エラー: {true_result['error']}")

        # 3. 偽鍵で復号
        print("\n3. 偽鍵での復号テスト")
        print(f"入力ファイル: {encrypted_path}")
        print(f"出力ファイル: {false_output_path}")

        start_time = time.time()
        false_result = decrypt_file(
            input_file=encrypted_path,
            output_file=false_output_path,
            key_bytes=false_key,
            key_type="false",
            verbose=True
        )
        false_decryption_time = time.time() - start_time

        print(f"偽鍵での復号完了。所要時間: {false_decryption_time:.2f}秒")
        if false_result.get("success", False):
            print("✅ 偽鍵での復号に成功")

            # 元のファイルと復号ファイルの比較
            with open(false_file_path, 'rb') as f:
                original_content = f.read()

            with open(false_output_path, 'rb') as f:
                decrypted_content = f.read()

            if original_content == decrypted_content:
                print("✅ 復号されたファイルは元のファイルと完全に一致")
            else:
                print("⚠️ 復号されたファイルは元のファイルと一致しません")
                print(f"元のファイルサイズ: {len(original_content)} バイト")
                print(f"復号ファイルサイズ: {len(decrypted_content)} バイト")
        else:
            print("❌ 偽鍵での復号に失敗")
            if "error" in false_result:
                print(f"エラー: {false_result['error']}")

        # テスト結果のサマリー
        print("\n===== テスト結果サマリー =====")
        print(f"暗号化時間: {encryption_time:.2f}秒")
        print(f"真鍵復号時間: {true_decryption_time:.2f}秒")
        print(f"偽鍵復号時間: {false_decryption_time:.2f}秒")
        print(f"暗号化ファイルサイズ: {os.path.getsize(encrypted_path)} バイト")

        # テスト成功の判定
        success = (
            os.path.exists(encrypted_path) and
            os.path.exists(true_output_path) and
            os.path.exists(false_output_path) and
            true_result.get("success", False) and
            false_result.get("success", False)
        )

        return success

    except Exception as e:
        import traceback
        print(f"テスト実行中にエラーが発生しました: {e}")
        traceback.print_exc()
        return False

def main():
    """メイン関数"""
    # コマンドライン引数の解析
    parser = argparse.ArgumentParser(description="準同型暗号マスキング方式のファイルテスト")
    parser.add_argument("--true", type=str, default=TRUE_TEXT_PATH, help="真のファイルパス")
    parser.add_argument("--false", type=str, default=FALSE_TEXT_PATH, help="偽のファイルパス")
    parser.add_argument("--output", type=str, default=TEST_OUTPUT_DIR, help="出力ディレクトリ")
    args = parser.parse_args()

    # テストの実行
    result = file_encryption_decryption_test(args.true, args.false, args.output)

    # 終了コード
    return 0 if result else 1

if __name__ == "__main__":
    print(f"テスト開始時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    exit_code = main()

    print(f"テスト終了時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"テスト結果: {'成功' if exit_code == 0 else '失敗'}")

    sys.exit(exit_code)