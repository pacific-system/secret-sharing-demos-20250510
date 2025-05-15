#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式（Method 8）検証スクリプト

このスクリプトは、暗号化・復号の機能を詳細ログを有効にして検証します。
特にUTF-8テキスト、JSON、CSVファイルの暗号化と復号が正しく行われるか、
最終行の欠損問題がないかを検証します。
"""

import os
import sys
import json
import csv
import time
import shutil
import subprocess
import tempfile
from pathlib import Path

# テスト出力ディレクトリの設定
TEST_OUTPUT_DIR = "test_output"
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

# 現在のスクリプトのディレクトリパスを取得
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 上位ディレクトリのパス
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

# テスト用のテンポラリディレクトリを作成
TEMP_DIR = tempfile.mkdtemp(prefix="homomorphic_test_")

# テスト用ファイルのパス
TEST_UTF8_FILE = os.path.join(TEMP_DIR, "test_utf8.txt")
TEST_JSON_FILE = os.path.join(TEMP_DIR, "test_json.json")
TEST_CSV_FILE = os.path.join(TEMP_DIR, "test_csv.csv")

# 暗号化ファイルのパス
ENCRYPTED_UTF8_FILE = os.path.join(TEMP_DIR, "encrypted_utf8.henc")
ENCRYPTED_JSON_FILE = os.path.join(TEMP_DIR, "encrypted_json.henc")
ENCRYPTED_CSV_FILE = os.path.join(TEMP_DIR, "encrypted_csv.henc")

# 復号ファイルのパス
DECRYPTED_UTF8_FILE = os.path.join(TEMP_DIR, "decrypted_utf8.txt")
DECRYPTED_JSON_FILE = os.path.join(TEMP_DIR, "decrypted_json.json")
DECRYPTED_CSV_FILE = os.path.join(TEMP_DIR, "decrypted_csv.csv")

# 暗号化・復号スクリプトのパス
ENCRYPT_SCRIPT = os.path.join(SCRIPT_DIR, "encrypt.py")
DECRYPT_SCRIPT = os.path.join(SCRIPT_DIR, "decrypt.py")

# テストデータ作成関数
def create_test_files():
    """テスト用のファイルを作成する"""
    # UTF-8テキストファイル
    with open(TEST_UTF8_FILE, "w", encoding="utf-8") as f:
        f.write("これはUTF-8テキストファイルです。\n")
        f.write("日本語の文字を含んでいます。\n")
        f.write("改行も含まれています。\n")
        f.write("これは最終行です。最終行が欠損する問題がないかを検証します。")

    # JSONファイル
    json_data = {
        "name": "テスト",
        "values": [1, 2, 3, 4, 5],
        "nested": {
            "key1": "バリュー1",
            "key2": "バリュー2"
        },
        "japanese": "日本語のテキスト"
    }
    with open(TEST_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    # CSVファイル
    csv_data = [
        ["ID", "名前", "値段"],
        [1, "商品A", 1000],
        [2, "商品B", 2000],
        [3, "商品C", 3000],
        [4, "最終行", 9999]
    ]
    with open(TEST_CSV_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(csv_data)

    print(f"テスト用ファイルを作成しました")

def run_command(command, verbose=True):
    """コマンドを実行し、結果を返す"""
    if verbose:
        print(f"実行コマンド: {' '.join(command)}")

    try:
        start_time = time.time()
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        elapsed_time = time.time() - start_time

        if verbose:
            print(f"完了（所要時間: {elapsed_time:.2f}秒）")
            print(f"標準出力:\n{result.stdout}")
            if result.stderr:
                print(f"標準エラー出力:\n{result.stderr}")

        return True, result
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"エラー: コマンド実行に失敗しました（終了コード: {e.returncode}）")
            print(f"標準出力:\n{e.stdout}")
            print(f"標準エラー出力:\n{e.stderr}")
        return False, e
    except Exception as e:
        if verbose:
            print(f"例外が発生しました: {str(e)}")
        return False, e

def create_true_false_files():
    """暗号化時に使用するtrue.textとfalse.textファイルを作成する"""
    true_file = os.path.join(TEMP_DIR, "true.text")
    false_file = os.path.join(TEMP_DIR, "false.text")

    with open(true_file, "w", encoding="utf-8") as f:
        f.write("これは正規のファイルです。\n")
        f.write("秘密情報が含まれています。\n")
        f.write("この内容は「真」の鍵で復号した場合に表示されます。")

    with open(false_file, "w", encoding="utf-8") as f:
        f.write("これは非正規のファイルです。\n")
        f.write("偽の情報が含まれています。\n")
        f.write("この内容は「偽」の鍵で復号した場合に表示されます。")

    return true_file, false_file

def encrypt_file(input_file, output_file, key_file=None, verbose=True):
    """ファイルを暗号化する"""
    # true.text/false.textを作成
    true_file, false_file = create_true_false_files()

    # 暗号化コマンドの準備
    command = [
        sys.executable, ENCRYPT_SCRIPT,
        "--verbose", input_file, false_file,
        "--output", output_file,
        "--save-keys"
    ]

    # 鍵ファイルが指定された場合は追加
    if key_file:
        command.extend(["--key", key_file])

    # コマンド実行
    success, result = run_command(command, verbose)

    # 鍵を取得
    key = None
    if success:
        # 標準出力から鍵を探す
        for line in result.stdout.splitlines():
            if "鍵（安全に保管してください）:" in line:
                key = line.split(":", 1)[1].strip()
                break

    return success, key

def decrypt_file(input_file, output_file, key, verbose=True):
    """ファイルを復号する"""
    # 復号コマンドの準備
    command = [
        sys.executable, DECRYPT_SCRIPT,
        "--verbose", input_file,
        "--key", key,
        "--output", output_file
    ]

    # コマンド実行
    success, result = run_command(command, verbose)
    return success

def verify_file_content(original_file, decrypted_file, file_type="utf8"):
    """ファイルの内容が正しく復号されているか検証する"""
    print(f"ファイル内容の検証中: {os.path.basename(decrypted_file)}")

    if not os.path.exists(decrypted_file):
        print(f"エラー: 復号ファイルが存在しません: {decrypted_file}")
        return False

    try:
        # ファイルタイプごとの検証
        if file_type == "utf8":
            # テキストファイルの場合
            with open(original_file, "r", encoding="utf-8") as f1:
                original_content = f1.read()

            with open(decrypted_file, "r", encoding="utf-8") as f2:
                decrypted_content = f2.read()

            if original_content == decrypted_content:
                print("✅ テキスト内容が一致しています")
                return True
            else:
                print("❌ テキスト内容が一致していません")
                print(f"元のファイル ({len(original_content)} バイト):")
                print(f"{original_content[:100]}...")
                print(f"復号ファイル ({len(decrypted_content)} バイト):")
                print(f"{decrypted_content[:100]}...")

                # 差分の詳細分析
                if len(original_content) != len(decrypted_content):
                    print(f"サイズが異なります: 元={len(original_content)}, 復号後={len(decrypted_content)}")

                # 最終行の確認
                original_lines = original_content.splitlines()
                decrypted_lines = decrypted_content.splitlines()

                if len(original_lines) != len(decrypted_lines):
                    print(f"行数が異なります: 元={len(original_lines)}, 復号後={len(decrypted_lines)}")

                    if len(original_lines) > len(decrypted_lines):
                        print("最終行が欠損している可能性があります")
                        print(f"元の最終行: {original_lines[-1]}")

                return False

        elif file_type == "json":
            # JSONファイルの場合
            with open(original_file, "r", encoding="utf-8") as f1:
                original_json = json.load(f1)

            try:
                with open(decrypted_file, "r", encoding="utf-8") as f2:
                    decrypted_json = json.load(f2)

                if original_json == decrypted_json:
                    print("✅ JSON内容が一致しています")
                    return True
                else:
                    print("❌ JSON内容が一致していません")
                    print(f"元のJSON: {original_json}")
                    print(f"復号JSON: {decrypted_json}")
                    return False
            except json.JSONDecodeError as e:
                print(f"❌ 復号されたファイルがJSON形式ではありません: {e}")

                # テキストとして内容を表示
                with open(decrypted_file, "r", encoding="utf-8") as f2:
                    decrypted_content = f2.read()
                print(f"復号ファイルの内容: {decrypted_content[:100]}...")
                return False

        elif file_type == "csv":
            # CSVファイルの場合
            original_rows = []
            with open(original_file, "r", encoding="utf-8", newline="") as f1:
                reader = csv.reader(f1)
                original_rows = list(reader)

            try:
                decrypted_rows = []
                with open(decrypted_file, "r", encoding="utf-8", newline="") as f2:
                    reader = csv.reader(f2)
                    decrypted_rows = list(reader)

                if original_rows == decrypted_rows:
                    print("✅ CSV内容が一致しています")
                    return True
                else:
                    print("❌ CSV内容が一致していません")

                    # 行数の確認
                    if len(original_rows) != len(decrypted_rows):
                        print(f"行数が異なります: 元={len(original_rows)}, 復号後={len(decrypted_rows)}")

                        if len(original_rows) > len(decrypted_rows):
                            print("最終行が欠損している可能性があります")
                            print(f"元の最終行: {original_rows[-1]}")

                    # 内容の比較
                    print("元のCSV:")
                    for row in original_rows[:3]:
                        print(row)
                    if len(original_rows) > 3:
                        print(f"...および他 {len(original_rows) - 3} 行")

                    print("復号CSV:")
                    for row in decrypted_rows[:3]:
                        print(row)
                    if len(decrypted_rows) > 3:
                        print(f"...および他 {len(decrypted_rows) - 3} 行")

                    return False
            except csv.Error as e:
                print(f"❌ 復号されたファイルがCSV形式ではありません: {e}")

                # テキストとして内容を表示
                with open(decrypted_file, "r", encoding="utf-8") as f2:
                    decrypted_content = f2.read()
                print(f"復号ファイルの内容: {decrypted_content[:100]}...")
                return False

    except Exception as e:
        print(f"検証中にエラーが発生しました: {str(e)}")
        return False

def test_format(file_type="utf8"):
    """特定のファイル形式のテストを実行する"""
    print(f"\n===== {file_type.upper()} ファイルのテスト =====")

    # 入力/出力ファイルのパスを決定
    if file_type == "utf8":
        input_file = TEST_UTF8_FILE
        encrypted_file = ENCRYPTED_UTF8_FILE
        decrypted_file = DECRYPTED_UTF8_FILE
    elif file_type == "json":
        input_file = TEST_JSON_FILE
        encrypted_file = ENCRYPTED_JSON_FILE
        decrypted_file = DECRYPTED_JSON_FILE
    elif file_type == "csv":
        input_file = TEST_CSV_FILE
        encrypted_file = ENCRYPTED_CSV_FILE
        decrypted_file = DECRYPTED_CSV_FILE
    else:
        print(f"未対応のファイル形式: {file_type}")
        return False

    # 暗号化
    print(f"\n暗号化: {os.path.basename(input_file)} → {os.path.basename(encrypted_file)}")
    encrypt_success, key = encrypt_file(input_file, encrypted_file)

    if not encrypt_success or not key:
        print(f"暗号化に失敗しました")
        return False

    print(f"暗号化に成功しました。鍵: {key}")

    # 復号
    print(f"\n復号: {os.path.basename(encrypted_file)} → {os.path.basename(decrypted_file)}")
    decrypt_success = decrypt_file(encrypted_file, decrypted_file, key)

    if not decrypt_success:
        print(f"復号に失敗しました")
        return False

    print(f"復号に成功しました")

    # 内容の検証
    verify_result = verify_file_content(input_file, decrypted_file, file_type)

    # テスト結果をレポート
    result_str = "成功" if verify_result else "失敗"
    print(f"\n{file_type.upper()} ファイルテスト結果: {result_str}")

    # テスト結果ファイルをテスト出力ディレクトリにコピー
    if os.path.exists(decrypted_file):
        output_copy = os.path.join(TEST_OUTPUT_DIR, f"decrypted_{file_type}_result.txt")
        shutil.copy2(decrypted_file, output_copy)
        print(f"結果ファイルをコピーしました: {output_copy}")

    return verify_result

def cleanup():
    """テスト用の一時ファイルを削除する"""
    try:
        shutil.rmtree(TEMP_DIR)
        print(f"一時ディレクトリを削除しました: {TEMP_DIR}")
    except Exception as e:
        print(f"一時ディレクトリの削除中にエラーが発生しました: {e}")

def main():
    """メイン関数"""
    print("準同型暗号マスキング方式（Method 8）の検証テストを開始します")
    print(f"テンポラリディレクトリ: {TEMP_DIR}")
    print(f"テスト出力ディレクトリ: {TEST_OUTPUT_DIR}")

    try:
        # テスト用ファイルを作成
        create_test_files()

        # 各形式のテストを実行
        utf8_result = test_format("utf8")
        json_result = test_format("json")
        csv_result = test_format("csv")

        # 結果サマリー
        print("\n===== テスト結果サマリー =====")
        print(f"UTF-8テキスト: {'✅ 成功' if utf8_result else '❌ 失敗'}")
        print(f"JSONファイル: {'✅ 成功' if json_result else '❌ 失敗'}")
        print(f"CSVファイル: {'✅ 成功' if csv_result else '❌ 失敗'}")

        # 総合結果
        overall_result = utf8_result and json_result and csv_result
        print(f"\n総合結果: {'✅ すべてのテストに成功しました' if overall_result else '❌ 一部のテストに失敗しました'}")

        # 結果を総合レポートファイルに出力
        report_file = os.path.join(TEST_OUTPUT_DIR, "verification_report.txt")
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("準同型暗号マスキング方式（Method 8）検証レポート\n")
            f.write("===================================\n\n")
            f.write(f"実施日時: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("テスト結果サマリー:\n")
            f.write(f"- UTF-8テキスト: {'成功' if utf8_result else '失敗'}\n")
            f.write(f"- JSONファイル: {'成功' if json_result else '失敗'}\n")
            f.write(f"- CSVファイル: {'成功' if csv_result else '失敗'}\n\n")
            f.write(f"総合結果: {'すべてのテストに成功' if overall_result else '一部のテストに失敗'}\n")

        print(f"検証レポートを作成しました: {report_file}")

        return 0 if overall_result else 1

    except Exception as e:
        print(f"テスト実行中にエラーが発生しました: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # 後片付け
        cleanup()

if __name__ == "__main__":
    sys.exit(main())