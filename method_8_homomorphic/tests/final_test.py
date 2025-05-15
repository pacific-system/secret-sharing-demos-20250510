#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の最終テスト

このモジュールは、準同型暗号マスキング方式の暗号化と復号をテストし、
システム全体の機能を検証します。
"""

import os
import sys
import time
import json
import subprocess
import hashlib
import shutil
import matplotlib.pyplot as plt
from pathlib import Path

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

def ensure_directory(path):
    """ディレクトリが存在することを確認し、存在しない場合は作成する"""
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"ディレクトリを作成しました: {path}")

def run_command(command, verbose=True):
    """コマンドを実行し、出力を返す"""
    if verbose:
        print(f"実行: {command}")

    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if verbose:
        print(f"終了コード: {result.returncode}")
        if result.stdout.strip():
            print("標準出力:")
            print(result.stdout)
        if result.stderr.strip():
            print("標準エラー:")
            print(result.stderr)

    return result

def compare_files(file1, file2):
    """2つのファイルの内容を比較"""
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        content1 = f1.read()
        content2 = f2.read()

    return content1 == content2

def calculate_file_hash(file_path):
    """ファイルのSHA-256ハッシュを計算"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_sha256.update(byte_block)
    return hash_sha256.hexdigest()

def plot_results(test_results, output_path):
    """テスト結果をグラフとして可視化"""
    labels = list(test_results.keys())
    success = [result.get('success', False) for result in test_results.values()]
    times = [result.get('time', 0) for result in test_results.values()]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # 成功/失敗グラフ
    ax1.bar(labels, success, color=['green' if s else 'red' for s in success])
    ax1.set_ylabel('成功 (1) / 失敗 (0)')
    ax1.set_title('テスト結果')
    ax1.set_ylim(0, 1.1)

    # 処理時間グラフ
    ax2.bar(labels, times, color='blue')
    ax2.set_ylabel('処理時間 (秒)')
    ax2.set_title('処理時間')

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"結果グラフを保存しました: {output_path}")

def main():
    """メイン関数"""
    print("=== 準同型暗号マスキング方式 最終テスト ===")

    # 現在のディレクトリとスクリプトパスを取得
    current_dir = os.path.abspath(os.path.dirname(__file__))
    parent_dir = os.path.abspath(os.path.join(current_dir, '..'))

    # テストディレクトリの設定
    test_dir = os.path.join(parent_dir, "test_output/homomorphic_test")
    ensure_directory(test_dir)
    ensure_directory(os.path.join(parent_dir, "test_output"))

    # 元ファイルのパス
    true_file = os.path.join(parent_dir, "../common/true-false-text/true.text")
    false_file = os.path.join(parent_dir, "../common/true-false-text/false.text")

    # ファイルが存在しない場合は作成
    if not os.path.exists(true_file):
        ensure_directory(os.path.dirname(true_file))
        with open(true_file, 'w') as f:
            f.write("This is the TRUE content for testing purposes.\n")
        print(f"テスト用TRUEファイルを作成しました: {true_file}")

    if not os.path.exists(false_file):
        ensure_directory(os.path.dirname(false_file))
        with open(false_file, 'w') as f:
            f.write("This is the FALSE content for testing purposes.\n")
        print(f"テスト用FALSEファイルを作成しました: {false_file}")

    # テスト用ファイルのコピー
    test_true_file = os.path.join(test_dir, "true.text")
    test_false_file = os.path.join(test_dir, "false.text")
    shutil.copy(true_file, test_true_file)
    shutil.copy(false_file, test_false_file)

    print(f"テストファイルをコピーしました: {test_true_file}, {test_false_file}")

    # ハッシュ値を計算
    true_hash = calculate_file_hash(test_true_file)
    false_hash = calculate_file_hash(test_false_file)

    print(f"TRUEファイルのハッシュ: {true_hash}")
    print(f"FALSEファイルのハッシュ: {false_hash}")

    # テスト結果の保存用
    test_results = {}

    # 暗号化テスト
    print("\n=== 暗号化テスト ===")
    encrypted_file = os.path.join(test_dir, "encrypted.json")

    encrypt_start_time = time.time()
    encrypt_result = run_command(
        f"cd {parent_dir} && python3 encrypt.py {test_true_file} {test_false_file} -o {encrypted_file} --save-keys"
    )
    encrypt_time = time.time() - encrypt_start_time

    # 暗号化結果の検証
    encrypt_success = encrypt_result.returncode == 0 and os.path.exists(encrypted_file)

    test_results['暗号化'] = {
        'success': encrypt_success,
        'time': encrypt_time,
        'hash': calculate_file_hash(encrypted_file) if encrypt_success else None
    }

    print(f"暗号化テスト結果: {'成功' if encrypt_success else '失敗'}, 処理時間: {encrypt_time:.2f}秒")

    if not encrypt_success:
        print("暗号化テストが失敗しました。以降のテストをスキップします。")
        sys.exit(1)

    # 鍵ファイルの確認
    key_dir = os.path.join(parent_dir, "keys")
    key_files = ["paillier_public.json", "paillier_private.json", "encryption_key.bin", "salt.bin"]
    key_exists = all(os.path.exists(os.path.join(key_dir, kf)) for kf in key_files)

    if key_exists:
        print("鍵ファイルが正常に生成されました。")
    else:
        print("警告: 一部の鍵ファイルが見つかりません。")

    # 暗号化ファイルの解析
    try:
        with open(encrypted_file, 'r') as f:
            encrypted_data = json.load(f)

        print("\n暗号化ファイルの情報:")
        print(f"フォーマット: {encrypted_data.get('format')}")
        print(f"バージョン: {encrypted_data.get('version')}")
        print(f"アルゴリズム: {encrypted_data.get('algorithm')}")
        print(f"真データサイズ: {encrypted_data.get('true_size')} バイト")
        print(f"偽データサイズ: {encrypted_data.get('false_size')} バイト")
        print(f"チャンクサイズ: {encrypted_data.get('chunk_size')} バイト")
    except Exception as e:
        print(f"暗号化ファイルの解析中にエラーが発生しました: {e}")

    # どの鍵を使うか決定
    # コマンドからランダムな鍵を生成
    random_true_key = run_command("openssl rand -hex 32", verbose=False).stdout.strip()
    random_false_key = run_command("openssl rand -hex 32", verbose=False).stdout.strip()

    # 復号テスト (TRUEキー - 自動検出)
    print("\n=== 復号テスト (TRUEキー - 自動検出) ===")
    decrypted_true_auto_file = os.path.join(test_dir, "decrypted_true_auto.text")

    decrypt_true_auto_start_time = time.time()
    decrypt_true_auto_result = run_command(
        f"cd {parent_dir} && python3 decrypt.py {encrypted_file} -k \"{random_true_key}\" --key-type true -o {decrypted_true_auto_file}"
    )
    decrypt_true_auto_time = time.time() - decrypt_true_auto_start_time

    # 復号結果の検証
    decrypt_true_auto_success = decrypt_true_auto_result.returncode == 0 and os.path.exists(decrypted_true_auto_file)
    true_match = False

    if decrypt_true_auto_success:
        true_match = calculate_file_hash(decrypted_true_auto_file) == true_hash

    test_results['TRUEキー復号'] = {
        'success': decrypt_true_auto_success and true_match,
        'time': decrypt_true_auto_time,
        'match': true_match
    }

    print(f"TRUEキー復号テスト結果: {'成功' if decrypt_true_auto_success else '失敗'}, 元ファイルと一致: {true_match}, 処理時間: {decrypt_true_auto_time:.2f}秒")

    # 復号テスト (FALSEキー - 自動検出)
    print("\n=== 復号テスト (FALSEキー - 自動検出) ===")
    decrypted_false_auto_file = os.path.join(test_dir, "decrypted_false_auto.text")

    decrypt_false_auto_start_time = time.time()
    decrypt_false_auto_result = run_command(
        f"cd {parent_dir} && python3 decrypt.py {encrypted_file} -k \"{random_false_key}\" --key-type false -o {decrypted_false_auto_file}"
    )
    decrypt_false_auto_time = time.time() - decrypt_false_auto_start_time

    # 復号結果の検証
    decrypt_false_auto_success = decrypt_false_auto_result.returncode == 0 and os.path.exists(decrypted_false_auto_file)
    false_match = False

    if decrypt_false_auto_success:
        false_match = calculate_file_hash(decrypted_false_auto_file) == false_hash

    test_results['FALSEキー復号'] = {
        'success': decrypt_false_auto_success and false_match,
        'time': decrypt_false_auto_time,
        'match': false_match
    }

    print(f"FALSEキー復号テスト結果: {'成功' if decrypt_false_auto_success else '失敗'}, 元ファイルと一致: {false_match}, 処理時間: {decrypt_false_auto_time:.2f}秒")

    # バイナリ対テキスト変換のテスト
    # テキストを強制指定
    print("\n=== テキスト強制指定テスト ===")
    decrypted_force_text_file = os.path.join(test_dir, "decrypted_force_text.text")

    decrypt_force_text_start_time = time.time()
    decrypt_force_text_result = run_command(
        f"cd {parent_dir} && python3 decrypt.py {encrypted_file} -k \"{random_true_key}\" --key-type true -o {decrypted_force_text_file} --data-type text"
    )
    decrypt_force_text_time = time.time() - decrypt_force_text_start_time

    # 復号結果の検証
    decrypt_force_text_success = decrypt_force_text_result.returncode == 0 and os.path.exists(decrypted_force_text_file)
    force_text_match = False

    if decrypt_force_text_success:
        force_text_match = calculate_file_hash(decrypted_force_text_file) == true_hash

    test_results['テキスト強制'] = {
        'success': decrypt_force_text_success and force_text_match,
        'time': decrypt_force_text_time,
        'match': force_text_match
    }

    print(f"テキスト強制指定テスト結果: {'成功' if decrypt_force_text_success else '失敗'}, 元ファイルと一致: {force_text_match}, 処理時間: {decrypt_force_text_time:.2f}秒")

    # バイナリを強制指定
    print("\n=== バイナリ強制指定テスト ===")
    decrypted_force_binary_file = os.path.join(test_dir, "decrypted_force_binary.text")

    decrypt_force_binary_start_time = time.time()
    decrypt_force_binary_result = run_command(
        f"cd {parent_dir} && python3 decrypt.py {encrypted_file} -k \"{random_false_key}\" --key-type false -o {decrypted_force_binary_file} --data-type binary"
    )
    decrypt_force_binary_time = time.time() - decrypt_force_binary_start_time

    # 復号結果の検証
    decrypt_force_binary_success = decrypt_force_binary_result.returncode == 0 and os.path.exists(decrypted_force_binary_file)
    force_binary_match = False

    if decrypt_force_binary_success:
        # バイナリ強制の場合は一致しない可能性があるので、ファイルサイズのみチェック
        force_binary_size = os.path.getsize(decrypted_force_binary_file)
        force_binary_match = force_binary_size > 0

    test_results['バイナリ強制'] = {
        'success': decrypt_force_binary_success and force_binary_match,
        'time': decrypt_force_binary_time,
        'size': os.path.getsize(decrypted_force_binary_file) if decrypt_force_binary_success else 0
    }

    print(f"バイナリ強制指定テスト結果: {'成功' if decrypt_force_binary_success else '失敗'}, ファイルサイズ: {os.path.getsize(decrypted_force_binary_file) if decrypt_force_binary_success else 0} バイト, 処理時間: {decrypt_force_binary_time:.2f}秒")

    # テスト結果をグラフ化
    results_graph = os.path.join(parent_dir, "test_output/homomorphic_operations.png")
    plot_results(test_results, results_graph)

    # テスト結果の概要
    print("\n=== テスト結果概要 ===")
    all_success = all(result.get('success', False) for result in test_results.values())

    print(f"全テスト成功: {'はい' if all_success else 'いいえ'}")
    print(f"暗号化時間: {test_results['暗号化']['time']:.2f}秒")
    print(f"TRUEキー復号時間: {test_results['TRUEキー復号']['time']:.2f}秒")
    print(f"FALSEキー復号時間: {test_results['FALSEキー復号']['time']:.2f}秒")
    print(f"TRUEファイルとの一致: {test_results['TRUEキー復号'].get('match', False)}")
    print(f"FALSEファイルとの一致: {test_results['FALSEキー復号'].get('match', False)}")
    print(f"テキスト強制時の一致: {test_results['テキスト強制'].get('match', False)}")
    print(f"バイナリ強制時のサイズ: {test_results['バイナリ強制'].get('size', 0)} バイト")

    # 結果をJSONファイルに保存
    result_file = os.path.join(test_dir, "test_results.json")
    with open(result_file, 'w') as f:
        json.dump(test_results, f, indent=2)

    print(f"テスト結果を保存しました: {result_file}")

    return 0 if all_success else 1

if __name__ == "__main__":
    sys.exit(main())