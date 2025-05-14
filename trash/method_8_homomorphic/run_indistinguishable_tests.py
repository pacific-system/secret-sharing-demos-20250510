#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
識別不能性機能のテスト実行スクリプト

このスクリプトは各種テストを一括で実行し、結果を表示します。
"""

import os
import sys
import subprocess
import time
from datetime import datetime
from pathlib import Path

# 親ディレクトリをパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(os.path.dirname(current_dir))  # プロジェクトのルートディレクトリを追加

# テスト出力ディレクトリの設定
TEST_OUTPUT_DIR = os.path.join(parent_dir, "test_output")
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

def generate_timestamp() -> str:
    """タイムスタンプ文字列を生成"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def run_test(script_path: str, output_prefix: str) -> str:
    """テストスクリプトを実行し、出力を保存"""
    timestamp = generate_timestamp()
    output_file = os.path.join(TEST_OUTPUT_DIR, f"{output_prefix}_{timestamp}.log")

    print(f"テスト実行中: {script_path}")
    print(f"出力ファイル: {output_file}")

    with open(output_file, "w") as f:
        start_time = time.time()
        result = subprocess.run(
            [sys.executable, script_path],
            stdout=f,
            stderr=subprocess.STDOUT,
            cwd=current_dir
        )
        elapsed_time = time.time() - start_time

        f.write(f"\n\n実行時間: {elapsed_time:.2f}秒\n")
        f.write(f"終了コード: {result.returncode}\n")

    return output_file

def main():
    """メイン関数"""
    print(f"=== 識別不能性機能テスト一括実行 ({generate_timestamp()}) ===")

    # 実行するテストスクリプトとその出力プレフィックス
    test_scripts = [
        ("tests/test_indistinguishable.py", "component_tests"),
        ("main_indistinguishable_test.py", "main_test")
    ]

    # 結果ファイルのリスト
    output_files = []

    # 各テストを実行
    for script_path, output_prefix in test_scripts:
        script_full_path = os.path.join(current_dir, script_path)
        output_file = run_test(script_full_path, output_prefix)
        output_files.append((script_path, output_file))

    # 実行結果のサマリーを表示
    print("\n=== テスト実行結果サマリー ===")
    for script_path, output_file in output_files:
        print(f"スクリプト: {script_path}")
        print(f"ログファイル: {output_file}")

        # ログファイルの最後の数行を表示
        try:
            with open(output_file, "r") as f:
                lines = f.readlines()
                last_lines = lines[-10:] if len(lines) >= 10 else lines
                print("最終出力:")
                for line in last_lines:
                    print(f"  {line.strip()}")
        except Exception as e:
            print(f"  ログファイル読み込みエラー: {e}")

        print()

    print(f"テスト出力ディレクトリ: {TEST_OUTPUT_DIR}")
    print(f"=== テスト一括実行終了 ({generate_timestamp()}) ===")

if __name__ == "__main__":
    main()