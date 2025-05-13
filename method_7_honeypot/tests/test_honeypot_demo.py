#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - デモンストレーションとテスト

このスクリプトは、ハニーポット方式の基本機能をデモし、
簡単な機能テストを実行します。
"""

import os
import sys
import tempfile
import shutil
import time
import random
import base64
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Any

# パスを調整してインポートできるようにする
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# ハニーポット方式の簡易実装をインポート
from method_7_honeypot.honeypot_simple import (
    generate_key_pair, encrypt_file, decrypt_file,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)


def create_test_files() -> Tuple[str, str]:
    """
    テスト用の一時ファイルを作成

    Returns:
        (true_file, false_file): 正規ファイルと非正規ファイルのパスのタプル
    """
    # 一時ディレクトリを作成
    temp_dir = tempfile.mkdtemp()

    # テストデータ
    true_data = "これは正規データです。🎉"
    false_data = "これは非正規データです。☠️"

    # ファイルに書き込み
    true_file = os.path.join(temp_dir, "true.txt")
    false_file = os.path.join(temp_dir, "false.txt")

    with open(true_file, 'w', encoding='utf-8') as f:
        f.write(true_data)

    with open(false_file, 'w', encoding='utf-8') as f:
        f.write(false_data)

    return true_file, false_file


def cleanup_temp_files(files: List[str], temp_dir: str = None):
    """
    一時ファイルをクリーンアップ

    Args:
        files: 削除するファイルのリスト
        temp_dir: 削除する一時ディレクトリ
    """
    for file in files:
        try:
            if os.path.exists(file):
                os.remove(file)
        except Exception as e:
            print(f"警告: ファイル '{file}' の削除に失敗しました: {e}")

    if temp_dir and os.path.exists(temp_dir):
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"警告: ディレクトリ '{temp_dir}' の削除に失敗しました: {e}")


def test_basic_functionality():
    """
    基本機能のテスト
    """
    print("\n=== 基本機能のテスト ===")

    # テストファイルを作成
    true_file, false_file = create_test_files()
    temp_dir = os.path.dirname(true_file)

    try:
        # 出力ファイルのパスを設定
        encrypted_file = os.path.join(temp_dir, "encrypted.json")
        decrypted_true_file = os.path.join(temp_dir, "decrypted_true.txt")
        decrypted_false_file = os.path.join(temp_dir, "decrypted_false.txt")

        # 暗号化
        print("1. ファイルの暗号化...")
        keys = encrypt_file(true_file, false_file, encrypted_file)
        print(f"  - 正規鍵: {base64.b64encode(keys[KEY_TYPE_TRUE]).decode()[:16]}...")
        print(f"  - 非正規鍵: {base64.b64encode(keys[KEY_TYPE_FALSE]).decode()[:16]}...")
        print(f"  - 暗号化ファイル: {encrypted_file}")

        # 正規鍵での復号
        print("\n2. 正規鍵での復号...")
        key_type = decrypt_file(encrypted_file, keys[KEY_TYPE_TRUE], decrypted_true_file)
        print(f"  - 検出された鍵タイプ: {key_type}")

        # 非正規鍵での復号
        print("\n3. 非正規鍵での復号...")
        key_type = decrypt_file(encrypted_file, keys[KEY_TYPE_FALSE], decrypted_false_file)
        print(f"  - 検出された鍵タイプ: {key_type}")

        # 復号結果の検証
        print("\n4. 復号結果の検証...")
        with open(true_file, 'r', encoding='utf-8') as f:
            original_true_data = f.read()

        with open(false_file, 'r', encoding='utf-8') as f:
            original_false_data = f.read()

        with open(decrypted_true_file, 'r', encoding='utf-8') as f:
            decrypted_true_data = f.read()

        with open(decrypted_false_file, 'r', encoding='utf-8') as f:
            decrypted_false_data = f.read()

        true_success = original_true_data == decrypted_true_data
        false_success = original_false_data == decrypted_false_data

        print(f"  - 正規データの一致: {'成功 ✓' if true_success else '失敗 ✗'}")
        print(f"  - 非正規データの一致: {'成功 ✓' if false_success else '失敗 ✗'}")

        if true_success and false_success:
            print("\nテスト結果: 成功 ✓")
        else:
            print("\nテスト結果: 失敗 ✗")

    finally:
        # 一時ファイルをクリーンアップ
        cleanup_temp_files([
            encrypted_file, decrypted_true_file, decrypted_false_file
        ], temp_dir)


def test_real_files():
    """
    実際のファイルを使用したテスト
    """
    print("\n=== 実際のファイルを使用したテスト ===")

    # 実際のファイルのパス
    true_file = "common/true-false-text/true.text"
    false_file = "common/true-false-text/false.text"

    # 出力先のディレクトリ
    output_dir = "test_output"
    os.makedirs(output_dir, exist_ok=True)

    # 現在の時刻を含む一意なファイル名を生成
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    encrypted_file = f"{output_dir}/honeypot_demo_{timestamp}.json"
    decrypted_true_file = f"{output_dir}/honeypot_demo_true_{timestamp}.text"
    decrypted_false_file = f"{output_dir}/honeypot_demo_false_{timestamp}.text"

    try:
        # 暗号化
        print("1. ファイルの暗号化...")
        keys = encrypt_file(true_file, false_file, encrypted_file)
        print(f"  - 正規鍵: {base64.b64encode(keys[KEY_TYPE_TRUE]).decode()[:16]}...")
        print(f"  - 非正規鍵: {base64.b64encode(keys[KEY_TYPE_FALSE]).decode()[:16]}...")
        print(f"  - 暗号化ファイル: {encrypted_file}")

        # 正規鍵での復号
        print("\n2. 正規鍵での復号...")
        key_type = decrypt_file(encrypted_file, keys[KEY_TYPE_TRUE], decrypted_true_file)
        print(f"  - 検出された鍵タイプ: {key_type}")
        print(f"  - 復号されたファイル: {decrypted_true_file}")

        # 非正規鍵での復号
        print("\n3. 非正規鍵での復号...")
        key_type = decrypt_file(encrypted_file, keys[KEY_TYPE_FALSE], decrypted_false_file)
        print(f"  - 検出された鍵タイプ: {key_type}")
        print(f"  - 復号されたファイル: {decrypted_false_file}")

        # 復号結果の検証
        print("\n4. 復号結果の検証...")
        with open(true_file, 'rb') as f:
            original_true_data = f.read()

        with open(false_file, 'rb') as f:
            original_false_data = f.read()

        with open(decrypted_true_file, 'rb') as f:
            decrypted_true_data = f.read()

        with open(decrypted_false_file, 'rb') as f:
            decrypted_false_data = f.read()

        true_success = original_true_data == decrypted_true_data
        false_success = original_false_data == decrypted_false_data

        print(f"  - 正規データの一致: {'成功 ✓' if true_success else '失敗 ✗'}")
        print(f"  - 非正規データの一致: {'成功 ✓' if false_success else '失敗 ✗'}")

        if true_success and false_success:
            print("\nテスト結果: 成功 ✓")
            print(f"\n復号されたファイルは以下に保存されています:")
            print(f"  - 正規データ: {decrypted_true_file}")
            print(f"  - 非正規データ: {decrypted_false_file}")
        else:
            print("\nテスト結果: 失敗 ✗")

    except Exception as e:
        print(f"\nエラー: テスト実行中に例外が発生しました: {e}")
        import traceback
        traceback.print_exc()


def test_invalid_keys():
    """
    無効な鍵を使用したテスト
    """
    print("\n=== 無効な鍵を使用したテスト ===")

    # テストファイルを作成
    true_file, false_file = create_test_files()
    temp_dir = os.path.dirname(true_file)

    try:
        # 出力ファイルのパスを設定
        encrypted_file = os.path.join(temp_dir, "encrypted.json")
        decrypted_file = os.path.join(temp_dir, "decrypted.txt")

        # 暗号化
        print("1. ファイルの暗号化...")
        keys = encrypt_file(true_file, false_file, encrypted_file)

        # ランダムな無効な鍵を生成
        invalid_key = os.urandom(len(keys[KEY_TYPE_TRUE]))
        print(f"  - 無効な鍵: {base64.b64encode(invalid_key).decode()[:16]}...")

        # 無効な鍵での復号を試行
        print("\n2. 無効な鍵での復号を試行...")
        try:
            decrypt_file(encrypted_file, invalid_key, decrypted_file)
            print("  - エラー: 無効な鍵が受け入れられました！")
            success = False
        except Exception as e:
            print(f"  - 期待通りのエラーが発生: {str(e)}")
            success = True

        print(f"\nテスト結果: {'成功 ✓' if success else '失敗 ✗'}")

    finally:
        # 一時ファイルをクリーンアップ
        cleanup_temp_files([
            encrypted_file, decrypted_file
        ], temp_dir)


def test_timing_resistance():
    """
    タイミング攻撃耐性のテスト
    """
    print("\n=== タイミング攻撃耐性のテスト ===")

    # テストファイルを作成
    true_file, false_file = create_test_files()
    temp_dir = os.path.dirname(true_file)

    try:
        # 出力ファイルのパスを設定
        encrypted_file = os.path.join(temp_dir, "encrypted.json")
        decrypted_true_file = os.path.join(temp_dir, "decrypted_true.txt")
        decrypted_false_file = os.path.join(temp_dir, "decrypted_false.txt")

        # 暗号化
        print("1. ファイルの暗号化...")
        keys = encrypt_file(true_file, false_file, encrypted_file)

        # 複数回の復号でタイミングを測定
        iterations = 10
        true_times = []
        false_times = []

        print(f"\n2. 正規鍵と非正規鍵の復号時間を{iterations}回測定...")

        for i in range(iterations):
            # 正規鍵での復号時間を測定
            start_time = time.time()
            decrypt_file(encrypted_file, keys[KEY_TYPE_TRUE], decrypted_true_file)
            true_times.append(time.time() - start_time)

            # 非正規鍵での復号時間を測定
            start_time = time.time()
            decrypt_file(encrypted_file, keys[KEY_TYPE_FALSE], decrypted_false_file)
            false_times.append(time.time() - start_time)

        # 統計情報を計算
        avg_true_time = sum(true_times) / len(true_times)
        avg_false_time = sum(false_times) / len(false_times)
        time_diff = abs(avg_true_time - avg_false_time)
        relative_diff = time_diff / max(avg_true_time, avg_false_time) * 100

        print("\n3. タイミング分析...")
        print(f"  - 正規鍵の平均復号時間: {avg_true_time:.6f} 秒")
        print(f"  - 非正規鍵の平均復号時間: {avg_false_time:.6f} 秒")
        print(f"  - 時間差: {time_diff:.6f} 秒 ({relative_diff:.2f}%)")

        # 結果の判定（時間差が10%未満なら成功）
        if relative_diff < 10:
            print("\nテスト結果: 成功 ✓ (時間差が十分に小さい)")
        else:
            print("\nテスト結果: 要注意 ⚠ (時間差が大きめ)")

    finally:
        # 一時ファイルをクリーンアップ
        cleanup_temp_files([
            encrypted_file, decrypted_true_file, decrypted_false_file
        ], temp_dir)


def run_all_tests():
    """
    すべてのテストを実行
    """
    print("=== 暗号学的ハニーポット方式 - テスト開始 ===")
    print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 基本機能のテスト
    test_basic_functionality()

    # 実際のファイルを使用したテスト
    test_real_files()

    # 無効な鍵を使用したテスト
    test_invalid_keys()

    # タイミング攻撃耐性のテスト
    test_timing_resistance()

    print("\n=== すべてのテストが完了しました ===")


if __name__ == "__main__":
    run_all_tests()