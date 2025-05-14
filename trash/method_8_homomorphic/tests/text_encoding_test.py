#!/usr/bin/env python3
"""
準同型暗号マスキング方式のテキストエンコーディング処理テスト
"""

import os
import sys
import tempfile
import subprocess
from typing import Tuple

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

# テスト用ディレクトリの設定
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_output")
os.makedirs(TEST_DIR, exist_ok=True)

# 鍵用ディレクトリの設定
KEYS_DIR = os.path.join(TEST_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

def run_command(cmd, cwd=None) -> Tuple[str, str, int]:
    """
    コマンドを実行してその結果を返す
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

def test_text_encoding(text: str, filename: str = "text_test.txt") -> bool:
    """
    テキストデータの暗号化・復号テスト

    Args:
        text: テストするテキスト
        filename: 保存するファイル名

    Returns:
        テストが成功したかどうか
    """
    print(f"\n===== テスト開始: '{text[:30]}...' =====")

    # テスト用のテキストファイルを作成
    true_file = os.path.join(TEST_DIR, f"true_{filename}")
    false_file = os.path.join(TEST_DIR, f"false_{filename}")
    encrypted_file = os.path.join(TEST_DIR, f"encrypted_{filename}.bin")
    decrypted_file = os.path.join(TEST_DIR, f"decrypted_{filename}")

    # 真のデータをファイルに書き込む
    with open(true_file, "w", encoding="utf-8") as f:
        f.write(text)

    # 偽のデータをファイルに書き込む
    with open(false_file, "w", encoding="utf-8") as f:
        f.write("これは偽のデータです。" * 5)

    # 暗号化の実行
    encrypt_cmd = [
        "python3", "../encrypt.py",
        "--true-file", true_file,
        "--false-file", false_file,
        "--output", encrypted_file,
        "--save-keys",
        "--keys-dir", KEYS_DIR,
        "--force-data-type", "text",
        "--verbose"
    ]

    encrypt_stdout, encrypt_stderr, encrypt_rc = run_command(encrypt_cmd)

    if encrypt_rc != 0:
        print("暗号化に失敗しました")
        return False

    print("暗号化が完了しました")

    # 鍵ファイルのパスを取得
    key_file = os.path.join(KEYS_DIR, "paillier_private.json")

    # 復号の実行
    decrypt_cmd = [
        "python3", "../decrypt.py",
        encrypted_file,
        "--output", decrypted_file,
        "--key", key_file,
        "--key-type", "true",
        "--data-type", "text",
        "--verbose"
    ]

    decrypt_stdout, decrypt_stderr, decrypt_rc = run_command(decrypt_cmd)

    if decrypt_rc != 0:
        print("復号に失敗しました")
        return False

    print("復号が完了しました")

    # 復号されたテキストを読み込む
    try:
        with open(decrypted_file, "r", encoding="utf-8") as f:
            decrypted_text = f.read()
    except UnicodeDecodeError:
        # UTF-8で読めない場合はバイナリモードで読み込む
        with open(decrypted_file, "rb") as f:
            binary_data = f.read()
        print(f"UTF-8でデコードできません。バイナリ長: {len(binary_data)}バイト")
        print(f"バイナリデータ先頭: {binary_data[:50]}")

        # 他のエンコーディングを試す
        for encoding in ['latin-1', 'shift-jis', 'euc-jp']:
            try:
                decrypted_text = binary_data.decode(encoding)
                print(f"{encoding}でデコードに成功")
                break
            except UnicodeDecodeError:
                continue
        else:
            print("どのエンコーディングでもデコードできません")
            return False

    # 元のテキストと復号されたテキストを比較
    is_success = text == decrypted_text

    print(f"\n===== テスト結果 =====")
    print(f"元のテキスト: {text[:50]}{'...' if len(text) > 50 else ''}")
    print(f"復号されたテキスト: {decrypted_text[:50]}{'...' if len(decrypted_text) > 50 else ''}")
    print(f"テスト結果: {'成功' if is_success else '失敗'}")

    if not is_success:
        print("\n===== 詳細な比較 =====")
        print(f"元テキスト長: {len(text)}, 復号テキスト長: {len(decrypted_text)}")

        # 文字ごとの比較
        min_len = min(len(text), len(decrypted_text))
        for i in range(min_len):
            if text[i] != decrypted_text[i]:
                print(f"最初の不一致: インデックス {i}")
                print(f"元テキスト: '{text[max(0, i-10):i+10]}'")
                print(f"復号テキスト: '{decrypted_text[max(0, i-10):i+10]}'")
                break

    return is_success

def main():
    """
    メイン関数
    """
    # シンプルなテキストのテスト
    simple_text = "これは単純なテキストです。Hello, World!"
    test_text_encoding(simple_text, "simple.txt")

    # 日本語を含む長いテキストのテスト
    japanese_text = """
    吾輩は猫である。名前はまだ無い。
    どこで生れたかとんと見当がつかぬ。何でも薄暗いじめじめした所でニャーニャー泣いていた事だけは記憶している。
    吾輩はここで始めて人間というものを見た。しかもあとで聞くとそれは書生という人間中で一番獰悪な種族であったそうだ。
    この書生というのは時々我々を捕えて煮て食うという話である。
    """
    test_text_encoding(japanese_text, "japanese.txt")

    # 特殊文字を含むテキストのテスト
    special_chars = "特殊文字テスト: !@#$%^&*()_+-={}[]|\\:;\"'<>,.?/\n\t\r"
    test_text_encoding(special_chars, "special_chars.txt")

    # 非常に長いテキストのテスト
    long_text = "これは長いテキストのテストです。" * 100
    test_text_encoding(long_text, "long.txt")

if __name__ == "__main__":
    main()