#!/usr/bin/env python3
"""
準同型暗号マスキング方式のテキスト暗号化・復号テスト
"""

import os
import sys
import tempfile
import subprocess

# 現在のディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(current_dir))

def run_command(cmd, cwd=None):
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

def main():
    # テスト用のテキストファイルを作成
    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_output")
    os.makedirs(test_dir, exist_ok=True)

    # true.textの作成
    original_text = "これは読めるテキストです。暗号化と復号のテストに使用します。"
    true_file = os.path.join(test_dir, "true.text")

    with open(true_file, "w", encoding="utf-8") as f:
        f.write(original_text)

    # false.textの作成
    false_text = "これは偽のテキストです。不正な鍵で復号した場合に表示されます。"
    false_file = os.path.join(test_dir, "false.text")

    with open(false_file, "w", encoding="utf-8") as f:
        f.write(false_text)

    print(f"オリジナルテキスト (true): {original_text}")
    print(f"偽のテキスト (false): {false_text}")

    # 暗号化
    encrypt_path = os.path.join(current_dir, "encrypt.py")
    encrypted_file = os.path.join(test_dir, "encrypted.bin")
    keys_dir = os.path.join(test_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    encrypt_cmd = [
        "python3", encrypt_path,
        "--true-file", true_file,  # 正規ファイル
        "--false-file", false_file,  # 偽のファイル
        "--output", encrypted_file,  # 出力ファイル
        "--algorithm", "paillier",  # 暗号化アルゴリズム
        "--save-keys",  # 鍵を保存
        "--keys-dir", keys_dir,  # 鍵を保存するディレクトリ
        "--force-data-type", "text",  # データタイプを明示的に指定
        "--verbose"  # 詳細なログを表示
    ]

    stdout, stderr, returncode = run_command(encrypt_cmd)

    if returncode != 0:
        print("暗号化に失敗しました。")
        return 1

    print("暗号化成功")
    print(stdout)

    # 鍵ファイルを探す
    key_files = [f for f in os.listdir(keys_dir) if f.endswith(".key")]
    if not key_files:
        # 新しいフォーマットの鍵ファイルを探す
        key_file = os.path.join(keys_dir, "encryption_key.bin")
        if not os.path.exists(key_file):
            print("鍵ファイルが見つかりません")
            return 1
    else:
        key_file = os.path.join(keys_dir, key_files[0])

    print(f"使用する鍵ファイル: {key_file}")

    # 復号
    decrypt_path = os.path.join(current_dir, "decrypt.py")
    decrypted_file = os.path.join(test_dir, "decrypted.txt")

    decrypt_cmd = [
        "python3", decrypt_path,
        encrypted_file,  # 暗号化ファイル（位置引数）
        "--key", key_file,  # 鍵ファイル
        "--output", decrypted_file,  # 出力ファイル
        "--data-type", "text",  # データタイプを明示的に指定
        "--verbose"  # 詳細なログを表示
    ]

    stdout, stderr, returncode = run_command(decrypt_cmd)

    if returncode != 0:
        print("復号に失敗しました。")
        return 1

    print("復号成功")
    print(stdout)

    # 復号されたテキストを読み込む
    try:
        with open(decrypted_file, "r", encoding="utf-8") as f:
            decrypted_text = f.read()

        print(f"復号されたテキスト: {decrypted_text}")

        # 元のテキストと復号されたテキストを比較
        if original_text == decrypted_text:
            print("テスト成功: 元のテキストと復号されたテキストが一致しています。")
            return 0
        else:
            print("テスト失敗: 元のテキストと復号されたテキストが一致していません。")
            print(f"元のテキスト長: {len(original_text)}")
            print(f"復号テキスト長: {len(decrypted_text)}")
            return 1
    except UnicodeDecodeError:
        print("テスト失敗: 復号されたファイルはテキストとして読めません。")
        # バイナリとして読み込んで内容を確認
        with open(decrypted_file, "rb") as f:
            binary_content = f.read()
        print(f"バイナリ内容 (最初の50バイト): {binary_content[:50]}")
        return 1

if __name__ == "__main__":
    sys.exit(main())