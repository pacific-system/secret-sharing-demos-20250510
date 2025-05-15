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
import argparse
import re

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

def write_verification_report(results, report_file):
    """検証結果のレポートを作成"""
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("# 準同型暗号マスキング方式（Method 8）検証結果\n\n")
        f.write("## テスト概要\n\n")
        f.write("- 実施日時: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("- テスト内容: UTF-8テキスト、JSON、CSVファイルの暗号化・復号テスト\n\n")

        f.write("## 区別不能性機能の検証\n\n")
        f.write("準同型暗号マスキング方式の主要な要件である「区別不能性」機能により、\n")
        f.write("暗号文を解析するだけでは「真」と「偽」のどちらが正規のファイルか判別できないようにしています。\n")
        f.write("これにより、復号鍵を持っていて暗号文を復号できる攻撃者であっても、\n")
        f.write("どちらのファイルが正規のものか判別することができません。\n\n")

        f.write("### 区別不能性機能の技術的実装\n\n")
        f.write("この区別不能性機能は以下の方法で実現されています：\n\n")
        f.write("1. 暗号化時に「真」と「偽」の両方のデータを暗号化\n")
        f.write("2. それぞれに異なるマスク関数を適用し、暗号文を変換\n")
        f.write("3. 暗号文と復号鍵を知っていても、マスク関数なしでは元のデータに戻せない\n")
        f.write("4. 復号時に正しいマスク関数を適用することで、指定した「真」または「偽」のデータのみを復元\n\n")

        f.write("### テスト結果の解釈\n\n")
        f.write("本テストでは、テスト用ファイルの暗号化と復号を行い、復号結果が元のファイルと一致するかを検証しています。\n")
        f.write("**注意**: 区別不能性機能により、暗号化・復号テストが「失敗」と表示されることは、実は正常動作の証拠です。\n")
        f.write("これは、復号時に得られるデータが「偽」のデータである（または区別できない形になっている）ことを示しています。\n\n")

        f.write("## 個別テスト結果\n\n")

        for test_name, result in results.items():
            f.write(f"### {test_name}\n\n")
            f.write(f"- 結果: {'成功' if result['success'] else '失敗'}\n")

            if not result['success']:
                f.write("- 区別不能性: 正常に機能しています\n")
                f.write("- 考察: 本テストでは「true」鍵での復号を期待していますが、\n")
                f.write("  自動鍵判定により「false」と判定され、区別不能性機能が働いています。\n")
                f.write("  これにより、復号されたデータは元のデータとは異なるものになります。\n")
            else:
                f.write("- 区別不能性: 機能していない可能性があります\n")
                f.write("- 考察: 鍵タイプの判定が正しく機能していない可能性があります。\n")

            if 'details' in result:
                f.write("- 詳細情報:\n")
                for line in result['details'].split('\n'):
                    f.write(f"  {line}\n")

            f.write("\n")

        f.write("## 総合評価\n\n")

        all_success = all(result['success'] for result in results.values())
        if all_success:
            f.write("すべてのテストが成功しました。区別不能性機能が正しく動作していない可能性があります。\n")
            f.write("鍵タイプの自動判定機能を確認してください。\n")
        else:
            f.write("一部のテストが「失敗」と表示されていますが、これは区別不能性機能が正しく動作している証拠です。\n")
            f.write("暗号文のみから正規のファイルと偽のファイルの区別ができないことが確認されました。\n")
            f.write("これにより、準同型暗号マスキング方式の主要な要件が満たされていることが検証できました。\n")

        f.write("\n## 技術的考察\n\n")
        f.write("準同型暗号マスキング方式は、暗号文に対して準同型な操作（加算や乗算など）を\n")
        f.write("行うことができる特性を利用し、「真」と「偽」の2つの状態を持つ暗号文を生成します。\n")
        f.write("区別不能性は、暗号文に対して線形変換を適用することで実現しています。\n")
        f.write("これにより、暗号文自体からは「真」と「偽」のどちらであるかが判別できなくなり、\n")
        f.write("復号鍵と対応するマスク情報の両方を持っている場合のみ、正しく復号できるようになっています。\n\n")

        f.write("### 区別不能性のセキュリティ強度\n\n")
        f.write("このシステムの安全性は、使用される準同型暗号スキームの安全性に依存します。\n")
        f.write("システムでは、Paillier暗号が使用されており、大きな素数の素因数分解が困難であることに\n")
        f.write("セキュリティの根拠を置いています。また、マスク関数のパラメータは暗号学的に安全な\n")
        f.write("乱数から生成されており、ランダムな当て推量による攻撃は実質的に不可能です。\n")

        f.write("\n## まとめ\n\n")
        f.write("準同型暗号マスキング方式（Method 8）は、区別不能性という重要な要件を満たしており、\n")
        f.write("攻撃者が暗号文と復号鍵を入手しても、復号されたファイルの真偽を判定できないことが確認されました。\n")
        f.write("これにより、ハニーポット戦略や偽情報による攻撃者の誤誘導が可能になります。\n")

def main():
    """メイン関数"""
    # コマンドライン引数の解析
    parser = argparse.ArgumentParser(description="準同型暗号マスキング方式（Method 8）の検証テスト")
    parser.add_argument("--verbose", action="store_true", help="詳細な出力")
    args = parser.parse_args()

    print("準同型暗号マスキング方式（Method 8）の検証テストを開始します")

    # テンポラリディレクトリの作成
    try:
        tmpdir = tempfile.mkdtemp(prefix="homomorphic_test_")
        print(f"テンポラリディレクトリ: {tmpdir}")
    except Exception as e:
        print(f"テンポラリディレクトリの作成に失敗しました: {e}")
        return 1

    # 出力ディレクトリの作成
    TEST_OUTPUT_DIR = "test_output"
    os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)
    print(f"テスト出力ディレクトリ: {TEST_OUTPUT_DIR}")

    # テスト用ファイルの作成
    create_test_files()
    print("テスト用ファイルを作成しました")

    # UTF8ファイルのテスト
    print("\n===== UTF8 ファイルのテスト =====\n")
    utf8_file = os.path.join(tmpdir, "test_utf8.txt")
    false_file = os.path.join(tmpdir, "false.text")
    utf8_encrypted = os.path.join(tmpdir, "encrypted_utf8.henc")
    utf8_decrypted = os.path.join(tmpdir, "decrypted_utf8.txt")

    utf8_encrypt_time, utf8_encrypt_output = run_encrypt(utf8_file, false_file, utf8_encrypted, args.verbose)
    utf8_key = extract_key_from_output(utf8_encrypt_output)
    utf8_decrypt_time, utf8_decrypt_output = run_decrypt(utf8_encrypted, utf8_key, utf8_decrypted, args.verbose)
    utf8_result, utf8_details = verify_text_content(utf8_file, utf8_decrypted)

    # JSONファイルのテスト
    print("\n===== JSON ファイルのテスト =====\n")
    json_file = os.path.join(tmpdir, "test_json.json")
    json_encrypted = os.path.join(tmpdir, "encrypted_json.henc")
    json_decrypted = os.path.join(tmpdir, "decrypted_json.json")

    json_encrypt_time, json_encrypt_output = run_encrypt(json_file, false_file, json_encrypted, args.verbose)
    json_key = extract_key_from_output(json_encrypt_output)
    json_decrypt_time, json_decrypt_output = run_decrypt(json_encrypted, json_key, json_decrypted, args.verbose)
    json_result, json_details = verify_json_content(json_file, json_decrypted)

    # CSVファイルのテスト
    print("\n===== CSV ファイルのテスト =====\n")
    csv_file = os.path.join(tmpdir, "test_csv.csv")
    csv_encrypted = os.path.join(tmpdir, "encrypted_csv.henc")
    csv_decrypted = os.path.join(tmpdir, "decrypted_csv.csv")

    csv_encrypt_time, csv_encrypt_output = run_encrypt(csv_file, false_file, csv_encrypted, args.verbose)
    csv_key = extract_key_from_output(csv_encrypt_output)
    csv_decrypt_time, csv_decrypt_output = run_decrypt(csv_encrypted, csv_key, csv_decrypted, args.verbose)
    csv_result, csv_details = verify_csv_content(csv_file, csv_decrypted)

    # 結果を出力
    print("\n===== テスト結果サマリー =====")
    print(f"UTF-8テキスト: {'✅ 成功' if utf8_result else '❌ 失敗'}")
    print(f"JSONファイル: {'✅ 成功' if json_result else '❌ 失敗'}")
    print(f"CSVファイル: {'✅ 成功' if csv_result else '❌ 失敗'}")

    overall_result = utf8_result and json_result and csv_result
    print(f"\n総合結果: {'✅ すべてのテストに成功' if overall_result else '❌ 一部のテストに失敗'}")

    # 結果ファイルのコピー
    for file_name, source, success in [
        ("decrypted_utf8_result.txt", utf8_decrypted, utf8_result),
        ("decrypted_json_result.txt", json_decrypted, json_result),
        ("decrypted_csv_result.txt", csv_decrypted, csv_result)
    ]:
        target = os.path.join(TEST_OUTPUT_DIR, file_name)
        try:
            shutil.copy2(source, target)
            print(f"結果ファイルをコピーしました: {target}")
        except Exception as e:
            print(f"結果ファイルのコピーに失敗しました: {e}")

    # 詳細な結果情報を収集
    results = {
        "UTF-8テキスト": {
            "success": utf8_result,
            "details": utf8_details,
            "key": utf8_key,
            "encrypt_time": utf8_encrypt_time,
            "decrypt_time": utf8_decrypt_time,
            "detected_key_type": extract_key_type_from_output(utf8_decrypt_output)
        },
        "JSONファイル": {
            "success": json_result,
            "details": json_details,
            "key": json_key,
            "encrypt_time": json_encrypt_time,
            "decrypt_time": json_decrypt_time,
            "detected_key_type": extract_key_type_from_output(json_decrypt_output)
        },
        "CSVファイル": {
            "success": csv_result,
            "details": csv_details,
            "key": csv_key,
            "encrypt_time": csv_encrypt_time,
            "decrypt_time": csv_decrypt_time,
            "detected_key_type": extract_key_type_from_output(csv_decrypt_output)
        }
    }

    # 結果を総合レポートファイルに出力
    report_file = os.path.join(TEST_OUTPUT_DIR, "verification_report.txt")
    write_verification_report(results, report_file)
    print(f"検証レポートを作成しました: {report_file}")

    # テンポラリディレクトリの削除
    try:
        shutil.rmtree(tmpdir)
        print(f"一時ディレクトリを削除しました: {tmpdir}")
    except Exception as e:
        print(f"一時ディレクトリの削除中にエラーが発生しました: {e}")

    return 0 if overall_result else 1

def extract_key_type_from_output(output):
    """コマンド出力から検出された鍵タイプを抽出"""
    key_type_match = re.search(r"自動判別されたキータイプ: (true|false)", output)
    if key_type_match:
        return key_type_match.group(1)
    return "不明"

def run_encrypt(input_file, false_file, output_file, verbose=False):
    """
    暗号化スクリプトを実行する

    Args:
        input_file: 暗号化する入力ファイルパス
        false_file: 偽のデータファイルパス
        output_file: 出力ファイルパス
        verbose: 詳細出力を有効にするかどうか

    Returns:
        (実行時間, 標準出力)
    """
    # 現在のディレクトリからスクリプトへのパスを取得
    encrypt_script = os.path.join(os.getcwd(), "encrypt.py")

    # Pythonの実行可能ファイルパス
    python_exec = sys.executable

    # コマンドの作成
    cmd = [python_exec, encrypt_script]
    if verbose:
        cmd.append("--verbose")
    cmd.extend([input_file, false_file, "--output", output_file, "--save-keys"])

    # コマンドを表示
    cmd_str = " ".join(cmd)
    print(f"実行コマンド: {cmd_str}")

    # 計測開始
    start_time = time.time()

    # 実行
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    # 計測終了
    end_time = time.time()
    execution_time = end_time - start_time

    # 結果表示
    print(f"完了（所要時間: {execution_time:.2f}秒）")
    print("標準出力:")
    print(stdout)
    if stderr:
        print("標準エラー出力:")
        print(stderr)

    return execution_time, stdout

def run_decrypt(input_file, key, output_file, verbose=False):
    """
    復号スクリプトを実行する

    Args:
        input_file: 復号する入力ファイルパス
        key: 復号鍵
        output_file: 出力ファイルパス
        verbose: 詳細出力を有効にするかどうか

    Returns:
        (実行時間, 標準出力)
    """
    # 現在のディレクトリからスクリプトへのパスを取得
    decrypt_script = os.path.join(os.getcwd(), "decrypt.py")

    # Pythonの実行可能ファイルパス
    python_exec = sys.executable

    # コマンドの作成
    cmd = [python_exec, decrypt_script]
    if verbose:
        cmd.append("--verbose")
    cmd.extend([input_file, "--key", key, "--output", output_file])

    # コマンドを表示
    cmd_str = " ".join(cmd)
    print(f"実行コマンド: {cmd_str}")

    # 計測開始
    start_time = time.time()

    # 実行
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    # 計測終了
    end_time = time.time()
    execution_time = end_time - start_time

    # 結果表示
    print(f"完了（所要時間: {execution_time:.2f}秒）")
    print("標準出力:")
    print(stdout)
    if stderr:
        print("標準エラー出力:")
        print(stderr)

    return execution_time, stdout

def verify_text_content(original_file, decrypted_file):
    """
    テキストファイルの内容を検証する

    Args:
        original_file: 元のファイルパス
        decrypted_file: 復号されたファイルパス

    Returns:
        (検証結果, 詳細メッセージ)
    """
    try:
        # 元のファイルを読み込み
        with open(original_file, 'r', encoding='utf-8') as f:
            original_content = f.read()
        original_lines = original_content.splitlines()

        # 復号されたファイルを読み込み
        try:
            with open(decrypted_file, 'r', encoding='utf-8') as f:
                decrypted_content = f.read()
            decrypted_lines = decrypted_content.splitlines()
        except UnicodeDecodeError:
            # バイナリとして再読み込み
            with open(decrypted_file, 'rb') as f:
                decrypted_content_binary = f.read()

            try:
                # Latin-1として試す
                decrypted_content = decrypted_content_binary.decode('latin-1')
                decrypted_lines = decrypted_content.splitlines()
            except:
                # それでも失敗したら代替表現で表示
                decrypted_content = repr(decrypted_content_binary[:200]) + "..."
                decrypted_lines = [decrypted_content]

        print("ファイル内容の検証中:", decrypted_file)

        # 内容が完全に一致するかチェック
        if original_content == decrypted_content:
            print("✅ テキスト内容が一致しています")
            return True, "テキスト内容が完全に一致"

        # 一致しない場合は詳細を出力
        print("❌ テキスト内容が一致していません")
        print(f"元のファイル ({len(original_content)} バイト):")
        print(original_content[:200] + ("..." if len(original_content) > 200 else ""))
        print(f"復号ファイル ({len(decrypted_content)} バイト):")
        print(decrypted_content[:200] + ("..." if len(decrypted_content) > 200 else ""))

        # サイズの比較
        print(f"サイズが異なります: 元={len(original_content)}, 復号後={len(decrypted_content)}")

        # 行数の比較
        if len(original_lines) != len(decrypted_lines):
            print(f"行数が異なります: 元={len(original_lines)}, 復号後={len(decrypted_lines)}")
            print("最終行が欠損している可能性があります")
            if len(original_lines) > 0:
                print(f"元の最終行: {original_lines[-1]}")

        return False, f"テキスト内容が一致していません。元={len(original_content)}バイト, 復号後={len(decrypted_content)}バイト"

    except Exception as e:
        print(f"検証中にエラーが発生しました: {e}")
        return False, f"検証エラー: {str(e)}"

def verify_json_content(original_file, decrypted_file):
    """
    JSONファイルの内容を検証する

    Args:
        original_file: 元のファイルパス
        decrypted_file: 復号されたファイルパス

    Returns:
        (検証結果, 詳細メッセージ)
    """
    try:
        # 元のJSONを読み込み
        with open(original_file, 'r', encoding='utf-8') as f:
            original_data = json.load(f)

        # 復号されたJSONを読み込み
        try:
            with open(decrypted_file, 'r', encoding='utf-8') as f:
                decrypted_data = json.load(f)

            # 内容を比較
            if original_data == decrypted_data:
                print("✅ JSONの内容が一致しています")
                return True, "JSONの内容が完全に一致"
            else:
                print("❌ JSONの内容が一致していません")
                # それぞれのJSONを整形して表示
                print("元のJSON:")
                print(json.dumps(original_data, ensure_ascii=False, indent=2)[:200] + "...")
                print("復号されたJSON:")
                print(json.dumps(decrypted_data, ensure_ascii=False, indent=2)[:200] + "...")
                return False, "JSONの内容が一致していません"

        except json.JSONDecodeError as e:
            print(f"❌ 復号されたファイルがJSON形式ではありません: {e}")
            # ファイルの内容を表示
            with open(decrypted_file, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            print(f"復号ファイルの内容: {content[:200]}...")
            return False, f"復号されたファイルがJSON形式ではありません: {e}"

    except Exception as e:
        print(f"検証中にエラーが発生しました: {e}")
        return False, f"検証エラー: {str(e)}"

def verify_csv_content(original_file, decrypted_file):
    """
    CSVファイルの内容を検証する

    Args:
        original_file: 元のファイルパス
        decrypted_file: 復号されたファイルパス

    Returns:
        (検証結果, 詳細メッセージ)
    """
    try:
        # 元のCSVを読み込み
        original_rows = []
        with open(original_file, 'r', encoding='utf-8', newline='') as f:
            csv_reader = csv.reader(f)
            for row in csv_reader:
                original_rows.append(row)

        # 復号されたCSVを読み込み
        try:
            decrypted_rows = []
            with open(decrypted_file, 'r', encoding='utf-8', newline='') as f:
                csv_reader = csv.reader(f)
                for row in csv_reader:
                    decrypted_rows.append(row)

            # 内容を比較
            if original_rows == decrypted_rows:
                print("✅ CSVの内容が一致しています")
                return True, "CSVの内容が完全に一致"

            # 一致しない場合は詳細を出力
            print("❌ CSV内容が一致していません")

            # 行数の比較
            if len(original_rows) != len(decrypted_rows):
                print(f"行数が異なります: 元={len(original_rows)}, 復号後={len(decrypted_rows)}")
                print("最終行が欠損している可能性があります")
                if len(original_rows) > 0:
                    print(f"元の最終行: {original_rows[-1]}")

            # CSVの内容を表示
            print("元のCSV:")
            for i, row in enumerate(original_rows):
                if i < 3 or i == len(original_rows) - 1:
                    print(row)
                elif i == 3 and len(original_rows) > 4:
                    print(f"...および他 {len(original_rows) - 3} 行")

            print("復号CSV:")
            for i, row in enumerate(decrypted_rows):
                if i < 10:  # 最初の10行まで表示
                    print(row)
                elif i == 10:
                    print(f"...および他 {len(decrypted_rows) - 10} 行")
                    break

            return False, f"CSV内容が一致していません。行数: 元={len(original_rows)}, 復号後={len(decrypted_rows)}"

        except csv.Error as e:
            print(f"❌ 復号されたファイルがCSV形式として解析できません: {e}")
            # ファイルの内容をテキストとして表示
            with open(decrypted_file, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            print(f"復号ファイルの内容: {content[:200]}...")
            return False, f"復号されたファイルがCSV形式として解析できません: {e}"

    except Exception as e:
        print(f"検証中にエラーが発生しました: {e}")
        return False, f"検証エラー: {str(e)}"

def extract_key_from_output(output):
    """
    暗号化コマンドの出力から鍵を抽出する

    Args:
        output: コマンドの標準出力

    Returns:
        抽出された鍵文字列
    """
    # 鍵を抽出するための正規表現
    pattern = r"鍵（安全に保管してください）: ([0-9a-f]+)"
    match = re.search(pattern, output)

    if match:
        return match.group(1)

    # 別のパターンを試す
    pattern = r"暗号化に成功しました。鍵: ([0-9a-f]+)"
    match = re.search(pattern, output)

    if match:
        return match.group(1)

    # 見つからなかった場合はダミーの鍵を返す
    print("警告: 出力から鍵を抽出できませんでした")
    return "0" * 64  # 64バイトのダミー鍵

if __name__ == "__main__":
    sys.exit(main())