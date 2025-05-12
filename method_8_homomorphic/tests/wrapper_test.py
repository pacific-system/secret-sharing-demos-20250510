#!/usr/bin/env python3
"""
準同型暗号マスキング方式の改良テキスト処理ラッパーテスト

improved_text_processor.pyを使用してテキストファイルの暗号化と復号をテストします。
"""

import os
import sys
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

def run_test(test_name: str, true_text: str, false_text: str) -> bool:
    """
    暗号化と復号のテストを実行

    Args:
        test_name: テスト名
        true_text: 真のテキスト
        false_text: 偽のテキスト

    Returns:
        テストが成功したかどうか
    """
    print(f"\n===== テスト開始: {test_name} =====")
    print(f"真のテキスト: {true_text[:50]}{'...' if len(true_text) > 50 else ''}")

    # テストファイルの作成
    true_file = create_test_file(true_text, f"wrapper_true_{test_name}.txt")
    false_file = create_test_file(false_text, f"wrapper_false_{test_name}.txt")
    encrypted_file = os.path.join(TEST_DIR, f"wrapper_encrypted_{test_name}.bin")
    decrypted_file = os.path.join(TEST_DIR, f"wrapper_decrypted_{test_name}")

    # 暗号化を実行（ラッパーを使用）
    encrypt_cmd = [
        "python3", "improved_text_processor.py",
        "encrypt",
        "--true-file", true_file,
        "--false-file", false_file,
        "--output", encrypted_file,
        "--keys-dir", KEYS_DIR,
        "--verbose"
    ]

    stdout, stderr, encrypt_rc = run_command(encrypt_cmd)

    if encrypt_rc != 0:
        print("暗号化に失敗しました")
        return False

    print("暗号化が完了しました")

    # 鍵ファイルのパスを取得
    key_file = os.path.join(KEYS_DIR, "paillier_private.json")

    # 復号を実行（ラッパーを使用）
    decrypt_cmd = [
        "python3", "improved_text_processor.py",
        "decrypt",
        "--encrypted-file", encrypted_file,
        "--key-file", key_file,
        "--key-type", "true",
        "--output", decrypted_file,
        "--verbose"
    ]

    stdout, stderr, decrypt_rc = run_command(decrypt_cmd)

    if decrypt_rc != 0:
        print("復号に失敗しました")
        return False

    print("復号が完了しました")

    # 復号されたテキストを読み込む（処理後のファイル）
    processed_file = decrypted_file + ".processed"
    try:
        with open(processed_file, "r", encoding="utf-8") as f:
            decrypted_text = f.read()
    except FileNotFoundError:
        print(f"処理後のファイル {processed_file} が見つかりません")
        return False

    # 結果を比較
    success = true_text == decrypted_text

    print(f"\n===== テスト結果: {test_name} =====")
    print(f"元のテキスト: {true_text[:50]}{'...' if len(true_text) > 50 else ''}")
    print(f"復号されたテキスト: {decrypted_text[:50]}{'...' if len(decrypted_text) > 50 else ''}")
    print(f"テスト結果: {'成功' if success else '失敗'}")

    if not success:
        print(f"元テキスト長: {len(true_text)}, 復号テキスト長: {len(decrypted_text)}")

        # 文字ごとの比較
        min_len = min(len(true_text), len(decrypted_text))
        for i in range(min_len):
            if true_text[i] != decrypted_text[i]:
                print(f"最初の不一致: インデックス {i}")
                print(f"元テキスト: '{true_text[max(0, i-10):i+10]}'")
                print(f"復号テキスト: '{decrypted_text[max(0, i-10):i+10]}'")
                break

    return success

def run_tests():
    """
    すべてのテストを実行
    """
    # テスト用テキスト
    tests = [
        {
            "name": "simple_text",
            "true": "これは単純なテキストです。Hello, World!",
            "false": "これは偽のデータです。"
        },
        {
            "name": "special_chars",
            "true": "特殊文字テスト: !@#$%^&*()_+-={}[]|\\:;\"'<>,.?/\n\t\r",
            "false": "特殊文字を含まない偽のデータです。"
        },
        {
            "name": "japanese_text",
            "true": """
            吾輩は猫である。名前はまだ無い。
            どこで生れたかとんと見当がつかぬ。何でも薄暗いじめじめした所でニャーニャー泣いていた事だけは記憶している。
            吾輩はここで始めて人間というものを見た。しかもあとで聞くとそれは書生という人間中で一番獰悪な種族であったそうだ。
            この書生というのは時々我々を捕えて煮て食うという話である。
            """,
            "false": "これは太宰治の「走れメロス」とは関係のない偽のデータです。"
        },
        {
            "name": "long_text",
            "true": "これは長いテキストのテストです。" * 100,
            "false": "これは長い偽のデータです。" * 100
        }
    ]

    # 全テストを実行
    results = []
    for test in tests:
        success = run_test(test["name"], test["true"], test["false"])
        results.append({
            "name": test["name"],
            "success": success
        })

    # 結果の表示
    print("\n===== テスト結果サマリー =====")
    success_count = sum(1 for r in results if r["success"])
    print(f"成功: {success_count}/{len(results)} ({success_count/len(results)*100:.1f}%)")

    for result in results:
        status = "✅" if result["success"] else "❌"
        print(f"{status} {result['name']}")

if __name__ == "__main__":
    print("===== 準同型暗号マスキング方式 改良テキスト処理ラッパーテスト =====\n")
    run_tests()