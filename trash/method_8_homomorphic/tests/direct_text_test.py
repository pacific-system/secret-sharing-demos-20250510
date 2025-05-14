#!/usr/bin/env python3
"""
準同型暗号マスキング方式の直接テキスト処理テスト

direct_text_processor.pyを使用して様々なテキストデータで暗号化と復号をテストします。
"""

import os
import sys
import time
import subprocess
from typing import Dict, List, Tuple, Optional, Any, Union

# テスト用ディレクトリの設定
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_output")
os.makedirs(TEST_DIR, exist_ok=True)

# 鍵用ディレクトリの設定
KEYS_DIR = os.path.join(TEST_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

def run_command(cmd, cwd=None) -> Tuple[str, str, int]:
    """
    コマンドを実行して結果を返す

    Args:
        cmd: 実行するコマンド（引数を含む）
        cwd: 現在の作業ディレクトリ

    Returns:
        (標準出力, 標準エラー, 終了コード)
    """
    print(f"実行コマンド: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=cwd, universal_newlines=True
    )
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"エラー (コード {process.returncode}):")
        print(stderr)

    return stdout, stderr, process.returncode

def create_test_file(content: str, filename: str) -> str:
    """
    テスト用ファイルを作成

    Args:
        content: ファイルの内容
        filename: ファイル名

    Returns:
        作成したファイルの絶対パス
    """
    filepath = os.path.join(TEST_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath

def run_direct_test(test_name: str, text_content: str) -> bool:
    """
    直接テキスト処理器を使ったテストを実行

    Args:
        test_name: テスト名
        text_content: テストするテキスト内容

    Returns:
        テストが成功したかどうか
    """
    print(f"\n===== テスト開始: {test_name} =====")
    print(f"テキスト内容: {text_content[:50]}{'...' if len(text_content) > 50 else ''}")

    # テスト用ファイルを作成
    input_file = create_test_file(text_content, f"direct_test_{test_name}.txt")
    encrypted_file = os.path.join(TEST_DIR, f"direct_test_{test_name}.bin")
    decrypted_file = os.path.join(TEST_DIR, f"direct_test_{test_name}_decrypted.txt")

    # 暗号化を実行
    encrypt_cmd = [
        "python3", "direct_text_processor.py",
        "encrypt",
        "--input", input_file,
        "--output", encrypted_file,
        "--keys-dir", KEYS_DIR,
        "--verbose"
    ]

    start_time = time.time()
    stdout, stderr, encrypt_rc = run_command(encrypt_cmd)
    encrypt_time = time.time() - start_time

    if encrypt_rc != 0:
        print("暗号化に失敗しました")
        return False

    print(f"暗号化が完了しました ({encrypt_time:.2f}秒)")

    # 鍵ファイルのパスを取得
    key_file = os.path.join(KEYS_DIR, "paillier_private.json")

    # 復号を実行
    decrypt_cmd = [
        "python3", "direct_text_processor.py",
        "decrypt",
        "--input", encrypted_file,
        "--output", decrypted_file,
        "--key", key_file,
        "--key-type", "true",
        "--verbose"
    ]

    start_time = time.time()
    stdout, stderr, decrypt_rc = run_command(decrypt_cmd)
    decrypt_time = time.time() - start_time

    if decrypt_rc != 0:
        print("復号に失敗しました")
        return False

    print(f"復号が完了しました ({decrypt_time:.2f}秒)")

    # 復号されたテキストと元のテキストを比較
    try:
        with open(decrypted_file, "r", encoding="utf-8") as f:
            decrypted_text = f.read()

        success = text_content == decrypted_text

        print(f"\n===== テスト結果: {test_name} =====")
        print(f"元のテキスト: {text_content[:50]}{'...' if len(text_content) > 50 else ''}")
        print(f"復号されたテキスト: {decrypted_text[:50]}{'...' if len(decrypted_text) > 50 else ''}")
        print(f"テスト結果: {'成功' if success else '失敗'}")

        if not success:
            print(f"元テキスト長: {len(text_content)}, 復号テキスト長: {len(decrypted_text)}")

            # 文字ごとの比較
            min_len = min(len(text_content), len(decrypted_text))
            for i in range(min_len):
                if text_content[i] != decrypted_text[i]:
                    print(f"最初の不一致: インデックス {i}")
                    print(f"元テキスト: '{text_content[max(0, i-10):i+10]}'")
                    print(f"復号テキスト: '{decrypted_text[max(0, i-10):i+10]}'")
                    break

        return success

    except Exception as e:
        print(f"テスト結果の確認中にエラーが発生しました: {e}")
        return False

def run_tests():
    """
    すべてのテストケースを実行
    """
    # テストケース
    test_cases = [
        {
            "name": "simple",
            "content": "これは単純なテキストです。Hello, World!"
        },
        {
            "name": "special_chars",
            "content": "特殊文字テスト: !@#$%^&*()_+-={}[]|\\:;\"'<>,.?/\n\t\r"
        },
        {
            "name": "japanese",
            "content": """
            吾輩は猫である。名前はまだ無い。
            どこで生れたかとんと見当がつかぬ。何でも薄暗いじめじめした所でニャーニャー泣いていた事だけは記憶している。
            吾輩はここで始めて人間というものを見た。しかもあとで聞くとそれは書生という人間中で一番獰悪な種族であったそうだ。
            この書生というのは時々我々を捕えて煮て食うという話である。
            """
        },
        {
            "name": "long",
            "content": "これは長いテキストのテストです。" * 100
        }
    ]

    # 結果を記録
    results = []

    # 各テストケースを実行
    for test_case in test_cases:
        success = run_direct_test(test_case["name"], test_case["content"])
        results.append({
            "name": test_case["name"],
            "success": success
        })

    # 結果の表示
    print("\n===== テスト結果サマリー =====")
    success_count = sum(1 for r in results if r["success"])
    print(f"成功: {success_count}/{len(results)} ({success_count/len(results)*100:.1f}%)")

    for result in results:
        status = "✅" if result["success"] else "❌"
        print(f"{status} {result['name']}")

    # 結果レポートを作成
    report_file = os.path.join(TEST_DIR, "direct_text_test_report.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# 準同型暗号マスキング方式 直接テキスト処理テスト結果\n\n")
        f.write("## 概要\n\n")
        f.write("多段エンコーディング（utf8 -> latin1 -> base64）を使用したテキストデータの暗号化・復号テストを実施しました。\n\n")

        f.write("## テスト結果\n\n")
        f.write("| テスト名 | 結果 |\n")
        f.write("|---------|------|\n")

        for result in results:
            status = "成功 ✅" if result["success"] else "失敗 ❌"
            f.write(f"| {result['name']} | {status} |\n")

        f.write(f"\n**成功率**: {success_count}/{len(results)} ({success_count/len(results)*100:.1f}%)\n\n")

        f.write("## 実装詳細\n\n")
        f.write("このテストでは、テキストデータに対して以下の多段エンコーディング処理を適用しています：\n\n")
        f.write("1. **UTF-8エンコーディング**: テキストをUTF-8バイト列に変換\n")
        f.write("2. **Latin-1変換**: UTF-8バイト列をLatin-1としてデコードし、再度Latin-1としてエンコード\n")
        f.write("3. **Base64エンコーディング**: 変換されたバイト列をBase64エンコード\n")
        f.write("4. **ヘッダー付加**: 「TXT-MULTI:utf8-latin1-base64:」というヘッダーを付加\n\n")

        f.write("復号時には上記の逆の処理を行い、元のテキストを復元します。\n\n")

        if success_count == len(results):
            f.write("すべてのテストが成功しており、多段エンコーディング方式は正常に機能しています。\n")
        else:
            f.write("一部のテストが失敗しており、多段エンコーディング方式にはさらなる改善が必要です。\n")

    print(f"\nテスト結果レポートを {report_file} に保存しました")

if __name__ == "__main__":
    print("===== 準同型暗号マスキング方式 直接テキスト処理テスト =====\n")
    run_tests()