#!/usr/bin/env python3
"""
準同型暗号マスキング方式のエンコーディング統合テスト

encrypt.pyとdecrypt.pyを実行して、暗号化と復号の過程でテキストが
正しく保存されるかを検証します。
"""

import os
import sys
import time
import tempfile
import subprocess
import base64
import json
from typing import Tuple, Dict, Any, List, Optional

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

# テキストの暗号化復号をデバッグするためにインポート
from method_8_homomorphic.crypto_adapters import (
    TextAdapter, process_data_for_encryption, process_data_after_decryption
)

# テスト用ディレクトリの設定
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_output")
os.makedirs(TEST_DIR, exist_ok=True)

# 鍵用ディレクトリの設定
KEYS_DIR = os.path.join(TEST_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

def run_command(cmd, cwd=None) -> Tuple[str, str, int]:
    """
    コマンドを実行してその結果を返す

    Args:
        cmd: 実行するコマンドとその引数のリスト
        cwd: コマンドを実行するディレクトリ

    Returns:
        (標準出力, 標準エラー, リターンコード)
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

def encrypt_text(true_text: str, false_text: str, output_file: str) -> bool:
    """
    テキストを暗号化

    Args:
        true_text: 真のテキスト
        false_text: 偽のテキスト
        output_file: 出力ファイル名

    Returns:
        成功したかどうか
    """
    # テストファイルの作成
    true_file = create_test_file(true_text, f"true_{output_file}.txt")
    false_file = create_test_file(false_text, f"false_{output_file}.txt")
    output_path = os.path.join(TEST_DIR, f"encrypted_{output_file}.bin")

    # 暗号化の実行
    encrypt_cmd = [
        "python3", "../encrypt.py",
        "--true-file", true_file,
        "--false-file", false_file,
        "--output", output_path,
        "--save-keys",
        "--keys-dir", KEYS_DIR,
        "--force-data-type", "text",
        "--verbose"
    ]

    stdout, stderr, rc = run_command(encrypt_cmd)

    if rc != 0:
        print("暗号化に失敗しました")
        return False

    print(f"暗号化が完了しました: {output_path}")
    return True

def decrypt_file(encrypted_file: str, output_file: str, key_type: str = "true") -> str:
    """
    ファイルを復号

    Args:
        encrypted_file: 暗号化されたファイル名
        output_file: 出力ファイル名
        key_type: 使用する鍵のタイプ ("true" または "false")

    Returns:
        復号されたテキスト、失敗した場合は空文字列
    """
    # 鍵ファイルのパスを取得
    key_file = os.path.join(KEYS_DIR, "paillier_private.json")

    # 入出力ファイルのパスを設定
    encrypted_path = os.path.join(TEST_DIR, f"encrypted_{encrypted_file}.bin")
    output_path = os.path.join(TEST_DIR, f"decrypted_{output_file}")

    # 復号の実行
    decrypt_cmd = [
        "python3", "../decrypt.py",
        encrypted_path,
        "--output", output_path,
        "--key", key_file,
        "--key-type", key_type,
        "--data-type", "text",
        "--verbose"
    ]

    stdout, stderr, rc = run_command(decrypt_cmd)

    if rc != 0:
        print("復号に失敗しました")
        return ""

    print(f"復号が完了しました: {output_path}")

    # 復号されたテキストを読み込む
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            decrypted_text = f.read()
        return decrypted_text
    except UnicodeDecodeError:
        # UTF-8で読めない場合はバイナリモードで読み込む
        with open(output_path, "rb") as f:
            binary_data = f.read()
        print(f"UTF-8でデコードできません。バイナリ長: {len(binary_data)}バイト")

        # 他のエンコーディングを試す
        for encoding in ['latin-1', 'shift-jis', 'euc-jp']:
            try:
                decrypted_text = binary_data.decode(encoding)
                print(f"{encoding}でデコードに成功")
                return decrypted_text
            except UnicodeDecodeError:
                continue

        # デコードできなかった場合はバイナリデータの先頭を表示
        print(f"バイナリデータ先頭: {binary_data[:50]}")
        return ""

def run_encrypt_decrypt_test(test_name: str, true_text: str, false_text: str) -> bool:
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

    # 直接テキストアダプタでテスト
    print("\n----- アダプタテスト -----")
    adapter = TextAdapter()
    text_bytes = true_text.encode('utf-8')
    processed = adapter.to_processable(text_bytes)
    restored = adapter.from_processable(processed)
    adapter_success = true_text == restored
    print(f"アダプタテスト結果: {'成功' if adapter_success else '失敗'}")

    # encrypt.pyとdecrypt.pyを使ったテスト
    print("\n----- 暗号化/復号テスト -----")
    if not encrypt_text(true_text, false_text, test_name):
        return False

    # 復号
    decrypted_text = decrypt_file(test_name, test_name)

    if not decrypted_text:
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

def run_end_to_end_tests():
    """
    エンドツーエンドのテストを実行
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
        success = run_encrypt_decrypt_test(test["name"], test["true"], test["false"])
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

def run_manual_debug():
    """
    手動でデバッグするための関数
    """
    # テスト用のテキストデータ
    test_text = "これは単純なテキストです。Hello, World!"

    # 暗号化前の処理
    print("\n===== 暗号化前処理 =====")
    text_bytes = test_text.encode('utf-8')
    processed_data, data_type = process_data_for_encryption(text_bytes, force_type="text")

    print(f"元テキスト: {test_text}")
    print(f"バイト変換後: {len(text_bytes)}バイト")
    print(f"処理後: {len(processed_data)}バイト、タイプ: {data_type}")
    print(f"処理後データ先頭: {processed_data[:50]}")

    # 復号後の処理
    print("\n===== 復号後処理 =====")
    decrypted_result = process_data_after_decryption(processed_data, data_type)

    if isinstance(decrypted_result, str):
        decrypted_text = decrypted_result
    else:
        try:
            decrypted_text = decrypted_result.decode('utf-8')
        except UnicodeDecodeError:
            decrypted_text = decrypted_result.decode('latin-1')

    print(f"復号後テキスト: {decrypted_text}")
    success = test_text == decrypted_text
    print(f"結果: {'成功' if success else '失敗'}")

if __name__ == "__main__":
    print("===== 準同型暗号マスキング方式 エンコーディング統合テスト =====\n")

    # テスト実行
    run_end_to_end_tests()

    # 必要に応じて手動デバッグを実行
    # run_manual_debug()