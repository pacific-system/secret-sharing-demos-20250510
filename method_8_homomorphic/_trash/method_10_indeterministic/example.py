#!/usr/bin/env python3
"""
不確定性転写暗号化方式の使用例

暗号化と復号の基本的な使用方法を示します。
"""

import os
import sys
import time
import argparse
from typing import Dict, List, Tuple, Optional, Union, Any

# パッケージとして利用する場合と直接実行する場合でインポートを切り替え
if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.append(current_dir)
    from encrypt import encrypt_file_cli
    from decrypt import decrypt_file_cli
    from probability_engine import TRUE_PATH, FALSE_PATH
else:
    from .encrypt import encrypt_file_cli
    from .decrypt import decrypt_file_cli
    from .probability_engine import TRUE_PATH, FALSE_PATH


def create_sample_file(content: str, file_path: str) -> bool:
    """
    サンプルファイルの作成

    Args:
        content: ファイルの内容
        file_path: 出力ファイルのパス

    Returns:
        成功した場合はTrue、失敗した場合はFalse
    """
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"サンプルファイルの作成に失敗しました: {e}", file=sys.stderr)
        return False


def run_example(input_file: str = None, true_password: str = None, false_password: str = None) -> None:
    """
    暗号化と復号の例を実行

    Args:
        input_file: 入力ファイル（指定がない場合は一時ファイルを作成）
        true_password: TRUE鍵のパスワード（指定がない場合はランダム生成）
        false_password: FALSE鍵のパスワード（指定がない場合はランダム生成）
    """
    # 一時ディレクトリの作成
    temp_dir = os.path.join(os.getcwd(), "temp")
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # 入力ファイルの準備
        if not input_file:
            # サンプルの入力ファイルを作成
            input_file = os.path.join(temp_dir, "sample_input.txt")
            content = """これは不確定性転写暗号化方式のテストファイルです。

秘密情報: パスワードは「password123」です。
重要度: 高

このファイルは暗号化された後も、TRUE/FALSE 2種類の鍵で復号できますが、
その結果は異なります。「不確定性」により、攻撃者にとっては
どちらの情報が真実かを判断することはできません。
"""
            if not create_sample_file(content, input_file):
                print("サンプルファイルの作成に失敗しました。終了します。")
                return

        # パスワードの準備
        if not true_password:
            true_password = "true_password_123"  # 実運用時はより強力なパスワードを使用すべき
        if not false_password:
            false_password = "false_password_123"  # 実運用時はより強力なパスワードを使用すべき

        # 暗号化ファイルの準備
        encrypted_file = os.path.join(temp_dir, "encrypted.bin")
        true_decrypted_file = os.path.join(temp_dir, "decrypted_true.txt")
        false_decrypted_file = os.path.join(temp_dir, "decrypted_false.txt")

        print("===== 不確定性転写暗号化方式のデモ =====")
        print(f"入力ファイル: {input_file}")
        print(f"TRUE鍵パスワード: {true_password}")
        print(f"FALSE鍵パスワード: {false_password}")

        # TRUEモードで暗号化
        print("\n----- TRUEモードで暗号化 -----")
        encrypt_success = encrypt_file_cli(
            input_file,
            encrypted_file,
            true_password,
            false_password,
            TRUE_PATH
        )

        if not encrypt_success:
            print("暗号化に失敗しました。終了します。")
            return

        # 暗号化ファイル情報の表示
        encrypted_file_size = os.path.getsize(encrypted_file)
        print(f"暗号化ファイル: {encrypted_file} ({encrypted_file_size} バイト)")

        # TRUEモードで復号
        print("\n----- TRUEモードで復号 -----")
        true_decrypt_success = decrypt_file_cli(
            encrypted_file,
            true_decrypted_file,
            true_password,
            TRUE_PATH
        )

        if not true_decrypt_success:
            print("TRUEモードでの復号に失敗しました。")
        else:
            print(f"TRUEモードで復号: {true_decrypted_file}")
            with open(true_decrypted_file, "r", encoding="utf-8") as f:
                print("\n--- 復号結果 (TRUE) ---")
                print(f.read())

        # FALSEモードで復号
        print("\n----- FALSEモードで復号 -----")
        false_decrypt_success = decrypt_file_cli(
            encrypted_file,
            false_decrypted_file,
            false_password,
            FALSE_PATH
        )

        if not false_decrypt_success:
            print("FALSEモードでの復号に失敗しました。")
        else:
            print(f"FALSEモードで復号: {false_decrypted_file}")
            with open(false_decrypted_file, "r", encoding="utf-8") as f:
                print("\n--- 復号結果 (FALSE) ---")
                print(f.read())

        # 復号結果の比較
        if true_decrypt_success and false_decrypt_success:
            with open(true_decrypted_file, "r", encoding="utf-8") as f_true:
                true_content = f_true.read()
            with open(false_decrypted_file, "r", encoding="utf-8") as f_false:
                false_content = f_false.read()

            same_content = (true_content == false_content)
            print("\n----- 結果比較 -----")
            print(f"復号結果は同一: {'はい' if same_content else 'いいえ'}")

            if same_content:
                print("警告: TRUE/FALSEモードで同じ結果が得られました。")
                print("これは予期しない動作です。鍵の設定を確認してください。")

        print("\n===== デモ完了 =====")

    except Exception as e:
        print(f"デモの実行中にエラーが発生しました: {e}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式のデモ")
    parser.add_argument("--input", help="入力ファイルのパス")
    parser.add_argument("--true-password", help="TRUE鍵のパスワード")
    parser.add_argument("--false-password", help="FALSE鍵のパスワード")

    args = parser.parse_args()

    run_example(args.input, args.true_password, args.false_password)