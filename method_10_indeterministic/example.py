#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - サンプル実行スクリプト

暗号化と復号の一連の流れを実行するサンプルスクリプトです。
正規・非正規の両方の鍵で復号し、結果を比較します。
"""

import os
import sys
import time
import binascii
import hashlib
import tempfile
from typing import Tuple, Dict, Any

# 相対インポートのためにパスを追加
current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(current_dir)
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

try:
    # パッケージとして実行する場合
    from method_10_indeterministic.encrypt import encrypt_files
    from method_10_indeterministic.decrypt import decrypt_file
    from method_10_indeterministic.config import TRUE_TEXT_PATH, FALSE_TEXT_PATH
except ImportError:
    # ローカルモジュールとして実行する場合
    from encrypt import encrypt_files
    from decrypt import decrypt_file
    from config import TRUE_TEXT_PATH, FALSE_TEXT_PATH


def prepare_test_files() -> Tuple[str, str, str]:
    """
    テスト用の一時ファイルを準備

    Returns:
        (正規ファイルパス, 非正規ファイルパス, 暗号化ファイルパス)
    """
    # 共通ディレクトリの確認
    common_dir = os.path.join(project_dir, "common", "true-false-text")
    os.makedirs(common_dir, exist_ok=True)

    # テスト用の文字列
    true_content = "これは正規のファイルです。正しい鍵で復号されたことを示します。"
    false_content = "これは非正規のファイルです。不正な鍵で復号されたことを示します。"

    # ファイルがなければ作成
    if not os.path.exists(TRUE_TEXT_PATH):
        with open(TRUE_TEXT_PATH, "w", encoding="utf-8") as f:
            f.write(true_content)

    if not os.path.exists(FALSE_TEXT_PATH):
        with open(FALSE_TEXT_PATH, "w", encoding="utf-8") as f:
            f.write(false_content)

    # 一時ファイルパスの生成
    temp_dir = tempfile.gettempdir()
    encrypted_path = os.path.join(temp_dir, "example_encrypted.indet")

    return TRUE_TEXT_PATH, FALSE_TEXT_PATH, encrypted_path


def test_encryption_decryption() -> Dict[str, Any]:
    """
    暗号化・復号のテスト

    Returns:
        テスト結果の辞書
    """
    results = {}

    print("=== 不確定性転写暗号化方式 サンプル実行 ===")

    # テストファイルの準備
    true_path, false_path, encrypted_path = prepare_test_files()
    print(f"テストファイル準備完了:")
    print(f"  正規ファイル: {true_path}")
    print(f"  非正規ファイル: {false_path}")
    print(f"  暗号化出力先: {encrypted_path}")

    # 暗号化の実行
    print("\n--- 暗号化処理開始 ---")
    start_time = time.time()
    key, metadata = encrypt_files(true_path, false_path, encrypted_path)
    encryption_time = time.time() - start_time

    print(f"暗号化処理時間: {encryption_time:.2f}秒")
    print(f"生成された鍵: {binascii.hexlify(key).decode('ascii')}")
    print(f"メタデータ: {metadata}")

    # 正規復号の実行
    print("\n--- 正規復号処理開始 ---")
    true_output_path = os.path.join(tempfile.gettempdir(), "example_true_decrypted.txt")
    start_time = time.time()
    decrypt_file(encrypted_path, key, true_output_path)
    true_decryption_time = time.time() - start_time

    # 復号結果の確認
    with open(true_output_path, "rb") as f:
        true_decrypted = f.read()

    print(f"正規復号結果: {true_decrypted.decode('utf-8', errors='replace')}")
    print(f"正規復号処理時間: {true_decryption_time:.2f}秒")

    # 非正規鍵の生成（元の鍵を少し変更）
    false_key = bytearray(key)
    false_key[0] ^= 0xFF  # 最初のバイトを反転
    false_key = bytes(false_key)

    # 非正規復号の実行
    print("\n--- 非正規復号処理開始 ---")
    false_output_path = os.path.join(tempfile.gettempdir(), "example_false_decrypted.txt")
    start_time = time.time()
    decrypt_file(encrypted_path, false_key, false_output_path)
    false_decryption_time = time.time() - start_time

    # 復号結果の確認
    with open(false_output_path, "rb") as f:
        false_decrypted = f.read()

    print(f"非正規復号結果: {false_decrypted.decode('utf-8', errors='replace')}")
    print(f"非正規復号処理時間: {false_decryption_time:.2f}秒")

    # 結果の検証
    with open(true_path, "rb") as f:
        original_true = f.read()

    with open(false_path, "rb") as f:
        original_false = f.read()

    # 正規鍵で元の正規テキストが復元されたか
    true_match = original_true in true_decrypted

    # 非正規鍵で元の非正規テキストが復元されたか
    false_match = original_false in false_decrypted

    # 真偽テキストが相互に含まれていないか（コンタミがないか）
    no_contamination = original_true not in false_decrypted and original_false not in true_decrypted

    print("\n--- 検証結果 ---")
    print(f"正規鍵での復号結果が正規テキストと一致: {true_match}")
    print(f"非正規鍵での復号結果が非正規テキストと一致: {false_match}")
    print(f"テキスト間のコンタミネーションなし: {no_contamination}")

    # 結果をまとめて返す
    results["encryption_time"] = encryption_time
    results["true_decryption_time"] = true_decryption_time
    results["false_decryption_time"] = false_decryption_time
    results["true_match"] = true_match
    results["false_match"] = false_match
    results["no_contamination"] = no_contamination
    results["encrypted_size"] = os.path.getsize(encrypted_path)
    results["original_true_size"] = len(original_true)
    results["original_false_size"] = len(original_false)
    results["true_key"] = binascii.hexlify(key).decode('ascii')
    results["false_key"] = binascii.hexlify(false_key).decode('ascii')

    return results


def display_summary(results: Dict[str, Any]):
    """
    テスト結果のサマリーを表示

    Args:
        results: テスト結果の辞書
    """
    print("\n=== サマリー ===")
    print(f"暗号化時間: {results['encryption_time']:.2f}秒")
    print(f"正規復号時間: {results['true_decryption_time']:.2f}秒")
    print(f"非正規復号時間: {results['false_decryption_time']:.2f}秒")

    print(f"\n暗号化ファイルサイズ: {results['encrypted_size']} バイト")
    print(f"オリジナル正規ファイルサイズ: {results['original_true_size']} バイト")
    print(f"オリジナル非正規ファイルサイズ: {results['original_false_size']} バイト")

    expansion_ratio = results['encrypted_size'] / (results['original_true_size'] + results['original_false_size'])
    print(f"サイズ拡大率: {expansion_ratio:.2f}倍")

    all_tests_passed = results["true_match"] and results["false_match"] and results["no_contamination"]
    print(f"\n全てのテストに合格: {'はい' if all_tests_passed else 'いいえ'}")

    if not all_tests_passed:
        if not results["true_match"]:
            print("  - 正規鍵での復号が正しくありません")
        if not results["false_match"]:
            print("  - 非正規鍵での復号が正しくありません")
        if not results["no_contamination"]:
            print("  - テキスト間にコンタミネーションがあります")


def main():
    """
    メイン関数
    """
    try:
        results = test_encryption_decryption()
        display_summary(results)
        return 0 if results["true_match"] and results["false_match"] else 1

    except Exception as e:
        print(f"エラー: サンプル実行中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
