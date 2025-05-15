#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
パス設定のチェックスクリプト

このスクリプトは、準同型暗号マスキング方式で使用されるパス設定が
正しく設定されているかを確認します。
"""

import os
import sys

# プロジェクトのルートパスを取得
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# カレントディレクトリの設定
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# config.pyをインポート
try:
    from config import (
        TRUE_TEXT_PATH,
        FALSE_TEXT_PATH,
        TEST_OUTPUT_DIR
    )
except ImportError:
    print("config.pyのインポートに失敗しました。パスの設定に問題があります。")
    print(f"現在のディレクトリ: {os.getcwd()}")
    print(f"スクリプトディレクトリ: {SCRIPT_DIR}")
    print(f"プロジェクトルート: {PROJECT_ROOT}")
    print(f"Pythonパス: {sys.path}")
    sys.exit(1)

def check_paths():
    """
    パス設定が正しく機能しているかをチェック
    """
    print("\n===== パス設定チェック =====")
    print(f"カレントディレクトリ: {os.getcwd()}")
    print(f"スクリプトディレクトリ: {SCRIPT_DIR}")
    print(f"プロジェクトルート: {PROJECT_ROOT}")

    # true.textとfalse.textのパスを確認
    print("\n--- 真偽ファイルのパス ---")
    print(f"TRUE_TEXT_PATH: {TRUE_TEXT_PATH}")
    print(f"FALSE_TEXT_PATH: {FALSE_TEXT_PATH}")

    # ファイルの存在を確認
    print("\n--- ファイルの存在確認 ---")
    if os.path.exists(TRUE_TEXT_PATH):
        print(f"✅ {TRUE_TEXT_PATH} が存在します")
        print(f"   サイズ: {os.path.getsize(TRUE_TEXT_PATH)} バイト")
    else:
        print(f"❌ {TRUE_TEXT_PATH} が見つかりません")

    if os.path.exists(FALSE_TEXT_PATH):
        print(f"✅ {FALSE_TEXT_PATH} が存在します")
        print(f"   サイズ: {os.path.getsize(FALSE_TEXT_PATH)} バイト")
    else:
        print(f"❌ {FALSE_TEXT_PATH} が見つかりません")

    # 出力ディレクトリの確認
    print("\n--- 出力ディレクトリの確認 ---")
    print(f"TEST_OUTPUT_DIR: {TEST_OUTPUT_DIR}")

    if os.path.exists(TEST_OUTPUT_DIR):
        print(f"✅ {TEST_OUTPUT_DIR} が存在します")
    else:
        print(f"❌ {TEST_OUTPUT_DIR} が見つかりません")
        try:
            os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)
            print(f"✅ {TEST_OUTPUT_DIR} を作成しました")
        except Exception as e:
            print(f"❌ {TEST_OUTPUT_DIR} の作成に失敗しました: {e}")

    # インポートパスの確認
    print("\n--- インポートパスの確認 ---")
    for path in sys.path:
        print(f"- {path}")

    return True

if __name__ == "__main__":
    check_paths()