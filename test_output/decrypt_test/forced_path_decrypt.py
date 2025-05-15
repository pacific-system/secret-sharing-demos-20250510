#!/usr/bin/env python3
"""
強制的な実行パスによる復号テスト

指定した鍵と暗号文から、実行パスを強制的に変更して復号テストを行います。
"""

import sys
import os
import argparse
import tempfile

# method_10_indeterministic モジュールのインポート
sys.path.insert(0, os.path.abspath('../..'))
from method_10_indeterministic.decrypt import (
    decrypt, determine_execution_path, decrypt_file
)
from method_10_indeterministic.probability_engine import TRUE_PATH, FALSE_PATH

# オリジナルの関数を一時保存
original_determine_execution_path = determine_execution_path

# モンキーパッチ: 常にTRUE_PATHを返す関数
def force_true_path(key, metadata):
    """常にTRUE_PATHを返す関数"""
    print(f"実行パスを強制的に{TRUE_PATH}に変更します")
    return TRUE_PATH

# モンキーパッチ: 常にFALSE_PATHを返す関数
def force_false_path(key, metadata):
    """常にFALSE_PATHを返す関数"""
    print(f"実行パスを強制的に{FALSE_PATH}に変更します")
    return FALSE_PATH

def main():
    parser = argparse.ArgumentParser(description='強制実行パス復号テスト')
    parser.add_argument('encrypted_file', help='暗号化ファイルのパス')
    parser.add_argument('key', help='復号鍵（16進数文字列）')
    parser.add_argument('--true', action='store_true', help='強制的にTRUEパスで復号')
    parser.add_argument('--false', action='store_true', help='強制的にFALSEパスで復号')
    parser.add_argument('--output-true', help='TRUEパス出力ファイル')
    parser.add_argument('--output-false', help='FALSEパス出力ファイル')

    args = parser.parse_args()

    # 入力チェック
    if not os.path.exists(args.encrypted_file):
        print(f"エラー: 暗号化ファイル '{args.encrypted_file}' が見つかりません")
        return 1

    if not args.true and not args.false:
        # デフォルトは両方のパスを試す
        args.true = True
        args.false = True

    # TRUEパスでの復号
    if args.true:
        true_output = args.output_true or f"{args.encrypted_file}_true_decrypted.txt"
        print(f"\n=== TRUEパスでの復号を試行します ===")

        # パッチを適用
        import method_10_indeterministic.decrypt
        method_10_indeterministic.decrypt.determine_execution_path = force_true_path

        # 復号実行
        success = decrypt(args.encrypted_file, args.key, true_output)

        if success:
            print(f"TRUEパスでの復号が成功しました: {true_output}")
        else:
            print(f"TRUEパスでの復号に失敗しました")

    # FALSEパスでの復号
    if args.false:
        false_output = args.output_false or f"{args.encrypted_file}_false_decrypted.txt"
        print(f"\n=== FALSEパスでの復号を試行します ===")

        # パッチを適用
        import method_10_indeterministic.decrypt
        method_10_indeterministic.decrypt.determine_execution_path = force_false_path

        # 復号実行
        success = decrypt(args.encrypted_file, args.key, false_output)

        if success:
            print(f"FALSEパスでの復号が成功しました: {false_output}")
        else:
            print(f"FALSEパスでの復号に失敗しました")

    # 元の関数に戻す
    method_10_indeterministic.decrypt.determine_execution_path = original_determine_execution_path
    print("\n元の実行パス決定ロジックに戻しました")

    return 0

if __name__ == "__main__":
    sys.exit(main())