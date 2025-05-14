"""
不確定性転写暗号化方式 - テスト用ユーティリティ

テストに必要な共通関数やユーティリティを提供します。
"""

import os
import time
import hashlib
import random
import string
import tempfile
from typing import Dict, List, Tuple, Optional, Any

# パスの設定
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(TEST_DIR))
COMMON_DIR = os.path.join(PROJECT_ROOT, "common")
TRUE_TEXT_PATH = os.path.join(COMMON_DIR, "true-false-text", "true.text")
FALSE_TEXT_PATH = os.path.join(COMMON_DIR, "true-false-text", "false.text")
TEST_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "test_output")


def ensure_test_files():
    """テストファイルの存在を確認し、ない場合は作成"""
    os.makedirs(os.path.join(COMMON_DIR, "true-false-text"), exist_ok=True)
    os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

    if not os.path.exists(TRUE_TEXT_PATH):
        with open(TRUE_TEXT_PATH, "w") as f:
            f.write("これは正規のファイルです。正しい鍵で復号されたことを示します。")

    if not os.path.exists(FALSE_TEXT_PATH):
        with open(FALSE_TEXT_PATH, "w") as f:
            f.write("これは非正規のファイルです。不正な鍵で復号されたことを示します。")


def generate_random_key(size=32):
    """テスト用のランダムな鍵を生成"""
    return os.urandom(size)


def generate_test_data(size=1024):
    """テスト用のランダムデータを生成"""
    return os.urandom(size)


def time_execution(func, *args, **kwargs):
    """関数の実行時間を計測"""
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    return result, end_time - start_time


def verify_data_equality(data1, data2):
    """2つのデータが同一かどうか検証"""
    return data1 == data2


def create_temp_file(data=None):
    """一時ファイルを作成"""
    temp = tempfile.NamedTemporaryFile(delete=False)
    if data:
        if isinstance(data, str):
            temp.write(data.encode('utf-8'))
        else:
            temp.write(data)
    temp.close()
    return temp.name


def cleanup_temp_file(filename):
    """一時ファイルを削除"""
    try:
        os.unlink(filename)
    except:
        pass


def get_timestamp_str():
    """タイムスタンプ文字列を取得（ファイル名用）"""
    return time.strftime("%Y%m%d_%H%M%S")


class TestResult:
    """テスト結果を保持・表示するクラス"""

    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.results = []

    def add_result(self, test_name, passed, message=None, duration=None):
        """テスト結果を追加"""
        self.total += 1
        if passed:
            self.passed += 1
        else:
            self.failed += 1

        self.results.append({
            "name": test_name,
            "passed": passed,
            "message": message,
            "duration": duration
        })

    def print_summary(self):
        """テスト結果のサマリーを表示"""
        print(f"\n=== テスト結果サマリー ===")
        print(f"合計: {self.total}")
        print(f"成功: {self.passed}")
        print(f"失敗: {self.failed}")

        if self.failed > 0:
            print("\n失敗したテスト:")
            for result in self.results:
                if not result["passed"]:
                    print(f"  - {result['name']}: {result['message']}")

        success_rate = (self.passed / self.total) * 100 if self.total > 0 else 0
        print(f"\n成功率: {success_rate:.2f}%")

    def all_passed(self):
        """すべてのテストが成功したかどうかを返す"""
        return self.failed == 0