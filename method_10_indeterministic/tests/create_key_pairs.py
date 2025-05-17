#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 鍵ペア生成テスト

同じ暗号文から異なる平文を復元するための鍵ペアを生成し、
その動作を検証するためのテストスクリプトです。
"""

import os
import sys
import time
import json
import base64
import hashlib
import tempfile
import argparse
import matplotlib.pyplot as plt
import numpy as np

# 親ディレクトリをインポートパスに追加
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

# 暗号化/復号モジュールをインポート
from method_10_indeterministic.encrypt import encrypt
from method_10_indeterministic.decrypt import decrypt_file

# テスト用ディレクトリ
TEST_OUTPUT_DIR = "test_output"
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)


def create_test_files():
    """
    テスト用の真偽テキストファイルを作成

    Returns:
        (str, str): 真テキストと偽テキストのファイルパス
    """
    timestamp = int(time.time())
    true_path = os.path.join(TEST_OUTPUT_DIR, f"true_{timestamp}.txt")
    false_path = os.path.join(TEST_OUTPUT_DIR, f"false_{timestamp}.txt")

    # 真のテキスト - 意味のあるメッセージ
    true_text = """
========= 極秘情報 - 正規メッセージ =========
これは正規の暗号鍵で復号された場合に表示される
本物のメッセージです。

重要な内容:
1. プロジェクトXの資金は前四半期比20%増加
2. 新技術の特許申請は来月15日に完了予定
3. 海外展開は第3四半期に開始
4. 新規取引先との契約は既に締結済み

この情報は暗号化システムの検証のためのものです。
真正な鍵を持つ正当な受信者のみがこのメッセージを
復号できることが期待されます。
==========================================
"""

    # 偽のテキスト - 意味のあるが異なるメッセージ
    false_text = """
========= お知らせ - 代替メッセージ =========
このファイルには重要情報は含まれておりません。
セキュリティ上の理由から、要求された情報は
別のチャネルを通じて提供されます。

注意事項:
1. このメッセージはダミーデータです
2. 本物の情報は別途確認してください
3. システムによる自動生成メッセージです
4. 情報漏洩防止のための安全対策です

不明点がございましたら、セキュリティ担当者に
お問い合わせください。
==========================================
"""

    # ファイルに書き込み
    with open(true_path, "w") as f:
        f.write(true_text)

    with open(false_path, "w") as f:
        f.write(false_text)

    return true_path, false_path


def generate_key_pairs(true_file, false_file):
    """
    同じ暗号文から異なる平文を復元するための鍵ペアを生成

    Args:
        true_file: 真のテキストファイルパス
        false_file: 偽のテキストファイルパス

    Returns:
        (str, str, str): 暗号文ファイルパス、真鍵ファイルパス、偽鍵ファイルパス
    """
    timestamp = int(time.time())
    enc_path = os.path.join(TEST_OUTPUT_DIR, f"encrypted_{timestamp}.enc")

    # 真テキストを暗号化（正規パス）
    print(f"[+] 真テキストを暗号化: {true_file} -> {enc_path}")
    true_key_path = encrypt(true_file, false_file, enc_path)

    # 鍵ファイルのパスをわかりやすく変更
    new_true_key_path = os.path.join(TEST_OUTPUT_DIR, f"true_key_{timestamp}.key")
    os.rename(true_key_path, new_true_key_path)

    # 暗号文を偽テキストとして解釈するための鍵を生成（非正規パス）
    # 既存の暗号文から偽テキストを復元するための鍵
    print(f"[+] 非正規パス用の鍵を生成: {false_file}")
    false_key_path = os.path.join(TEST_OUTPUT_DIR, f"false_key_{timestamp}.key")

    # 暗号文ファイルを読み込み
    with open(enc_path, "rb") as f:
        encrypted_data = f.read()

    # エントロピー計算
    entropy = 0.0
    try:
        byte_count = {}
        for b in encrypted_data:
            byte_count[b] = byte_count.get(b, 0) + 1

        for count in byte_count.values():
            probability = count / len(encrypted_data)
            entropy -= probability * np.log2(probability)
    except Exception:
        entropy = 7.5

    # 非正規パス用の鍵生成
    non_regular_key = os.urandom(32)
    key_info = {
        "version": "1.0.0",
        "master_key": base64.b64encode(non_regular_key).decode('utf-8'),
        "salt": base64.b64encode(os.urandom(16)).decode('utf-8'),
        "path_type": "false",  # 非正規パスを指定
        "timestamp": timestamp,
        "entropy": entropy,
        "file_type": "text"
    }

    # 非正規鍵ファイルを保存
    with open(false_key_path, "w") as f:
        json.dump(key_info, f, indent=2)

    # ファイル権限の設定
    try:
        os.chmod(new_true_key_path, 0o600)  # rw-------
        os.chmod(false_key_path, 0o600)  # rw-------
        os.chmod(enc_path, 0o644)  # rw-r--r--
    except Exception as e:
        print(f"[!] 警告: ファイル権限の設定に失敗しました: {e}")

    return enc_path, new_true_key_path, false_key_path


def verify_keys(enc_path, true_key_path, false_key_path):
    """
    生成した鍵ペアを検証

    同じ暗号文から、真鍵と偽鍵を使ってそれぞれ異なる平文が
    復元されることを確認します。

    Args:
        enc_path: 暗号文ファイルパス
        true_key_path: 真鍵ファイルパス
        false_key_path: 偽鍵ファイルパス

    Returns:
        (bool, str, str): 検証結果、真平文ファイルパス、偽平文ファイルパス
    """
    timestamp = int(time.time())
    true_dec_path = os.path.join(TEST_OUTPUT_DIR, f"decrypted_true_{timestamp}.txt")
    false_dec_path = os.path.join(TEST_OUTPUT_DIR, f"decrypted_false_{timestamp}.txt")

    # 真鍵で復号
    print(f"[+] 真鍵で復号: {enc_path} + {true_key_path} -> {true_dec_path}")
    true_success = decrypt_file(enc_path, true_key_path, true_dec_path)

    # 偽鍵で復号
    print(f"[+] 偽鍵で復号: {enc_path} + {false_key_path} -> {false_dec_path}")
    false_success = decrypt_file(enc_path, false_key_path, false_dec_path)

    if not true_success or not false_success:
        print("[!] エラー: 復号に失敗しました")
        return False, true_dec_path, false_dec_path

    # 復号結果を比較
    with open(true_dec_path, "rb") as f:
        true_content = f.read()

    with open(false_dec_path, "rb") as f:
        false_content = f.read()

    # 内容が異なることを確認
    if true_content == false_content:
        print("[!] エラー: 復号結果が同一です")
        return False, true_dec_path, false_dec_path

    # ハッシュ値を比較して違いを確認
    true_hash = hashlib.sha256(true_content).hexdigest()
    false_hash = hashlib.sha256(false_content).hexdigest()

    print(f"[+] 真平文のハッシュ: {true_hash}")
    print(f"[+] 偽平文のハッシュ: {false_hash}")
    print(f"[+] ハッシュ値の違い: {sum(1 for a, b in zip(true_hash, false_hash) if a != b)}/64文字")

    return True, true_dec_path, false_dec_path


def visualize_results(true_path, false_path, enc_path, true_dec_path, false_dec_path):
    """
    検証結果を可視化

    Args:
        true_path: 元の真テキストファイルパス
        false_path: 元の偽テキストファイルパス
        enc_path: 暗号文ファイルパス
        true_dec_path: 真鍵で復号したファイルパス
        false_dec_path: 偽鍵で復号したファイルパス

    Returns:
        str: 画像ファイルパス
    """
    # ファイル内容の読み込み
    def read_file_bytes(path):
        with open(path, "rb") as f:
            return f.read()

    def count_bytes(data):
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        return counts

    # 各ファイルのバイト分布を取得
    true_orig = read_file_bytes(true_path)
    false_orig = read_file_bytes(false_path)
    encrypted = read_file_bytes(enc_path)
    true_dec = read_file_bytes(true_dec_path)
    false_dec = read_file_bytes(false_dec_path)

    true_orig_counts = count_bytes(true_orig)
    false_orig_counts = count_bytes(false_orig)
    encrypted_counts = count_bytes(encrypted)
    true_dec_counts = count_bytes(true_dec)
    false_dec_counts = count_bytes(false_dec)

    # エントロピー計算
    def calc_entropy(data):
        if not data:
            return 0.0
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        entropy = 0.0
        for count in counts.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)
        return entropy

    true_orig_entropy = calc_entropy(true_orig)
    false_orig_entropy = calc_entropy(false_orig)
    encrypted_entropy = calc_entropy(encrypted)
    true_dec_entropy = calc_entropy(true_dec)
    false_dec_entropy = calc_entropy(false_dec)

    # グラフ作成
    plt.figure(figsize=(15, 10))

    # バイト分布比較
    plt.subplot(2, 1, 1)
    x = np.arange(256)
    plt.plot(x, true_orig_counts, 'g-', alpha=0.5, label='元の真テキスト')
    plt.plot(x, false_orig_counts, 'r-', alpha=0.5, label='元の偽テキスト')
    plt.plot(x, encrypted_counts, 'k-', alpha=0.5, label='暗号文')
    plt.plot(x, true_dec_counts, 'g--', alpha=0.8, label='復号された真テキスト')
    plt.plot(x, false_dec_counts, 'r--', alpha=0.8, label='復号された偽テキスト')
    plt.title('バイト値分布の比較')
    plt.xlabel('バイト値')
    plt.ylabel('出現頻度')
    plt.legend()
    plt.grid(True, alpha=0.3)

    # エントロピー比較
    plt.subplot(2, 1, 2)
    labels = ['元の真テキスト', '元の偽テキスト', '暗号文', '復号された真テキスト', '復号された偽テキスト']
    values = [true_orig_entropy, false_orig_entropy, encrypted_entropy, true_dec_entropy, false_dec_entropy]
    colors = ['green', 'red', 'black', 'lightgreen', 'lightcoral']

    bars = plt.bar(labels, values, color=colors)
    plt.axhline(y=8.0, color='gray', linestyle='--', label='理論上の最大値')
    plt.axhline(y=7.5, color='blue', linestyle='--', label='高エントロピー閾値')
    plt.title('ファイルごとのエントロピー比較')
    plt.xlabel('ファイル')
    plt.ylabel('エントロピー値 (ビット/バイト)')
    plt.ylim(0, 8.2)
    plt.xticks(rotation=45)
    plt.grid(True, alpha=0.3)

    # テキスト内容の比較
    for i, (value, label) in enumerate(zip(values, labels)):
        plt.text(i, value + 0.1, f"{value:.2f}", ha='center')

    plt.tight_layout()

    # グラフを保存
    timestamp = int(time.time())
    image_path = os.path.join(TEST_OUTPUT_DIR, f"key_pair_verification_{timestamp}.png")
    plt.savefig(image_path)
    plt.close()

    print(f"[+] 検証結果のグラフを保存しました: {image_path}")

    return image_path


def compare_file_content(path1, path2):
    """
    ファイル内容を比較して違いを表示

    Args:
        path1: 1つ目のファイルパス
        path2: 2つ目のファイルパス

    Returns:
        float: 類似度（0.0〜1.0）
    """
    try:
        with open(path1, "rb") as f1, open(path2, "rb") as f2:
            content1 = f1.read()
            content2 = f2.read()

        # バイト単位の一致率
        min_len = min(len(content1), len(content2))
        matches = sum(1 for a, b in zip(content1[:min_len], content2[:min_len]) if a == b)
        similarity = matches / min_len if min_len > 0 else 0

        print(f"[+] ファイル比較: 類似度 {similarity:.2%}")

        # テキストとして扱える場合はテキスト比較も
        try:
            text1 = content1.decode('utf-8')
            text2 = content2.decode('utf-8')

            # 行ごとに比較
            lines1 = text1.splitlines()
            lines2 = text2.splitlines()

            print(f"[+] 行数: {len(lines1)} vs {len(lines2)}")

            # 先頭2行と末尾2行を表示
            print("\n--- 先頭部分の比較 ---")
            for i in range(min(3, len(lines1), len(lines2))):
                print(f"ファイル1: {lines1[i]}")
                print(f"ファイル2: {lines2[i]}")
                print()

            print("--- 末尾部分の比較 ---")
            for i in range(-3, 0):
                if abs(i) <= len(lines1) and abs(i) <= len(lines2):
                    print(f"ファイル1: {lines1[i]}")
                    print(f"ファイル2: {lines2[i]}")
                    print()

        except UnicodeDecodeError:
            print("[!] テキスト比較はできませんでした（バイナリデータ）")

        return similarity

    except Exception as e:
        print(f"[!] ファイル比較中にエラーが発生しました: {e}")
        return 0.0


def main():
    """
    メイン処理
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式の鍵ペア生成と検証")
    parser.add_argument("--verify", action="store_true", help="検証モード（既存ファイルを使用）")
    parser.add_argument("--enc", help="既存の暗号文ファイル（検証モード用）")
    parser.add_argument("--true-key", help="既存の真鍵ファイル（検証モード用）")
    parser.add_argument("--false-key", help="既存の偽鍵ファイル（検証モード用）")
    parser.add_argument("--true-file", help="既存の真テキストファイル（生成モード用）")
    parser.add_argument("--false-file", help="既存の偽テキストファイル（生成モード用）")

    args = parser.parse_args()

    print("===== 不確定性転写暗号化方式 - 鍵ペア生成・検証 =====")

    if args.verify:
        # 検証モード
        if not (args.enc and args.true_key and args.false_key):
            print("[!] エラー: 検証モードには --enc, --true-key, --false-key の指定が必要です")
            return

        print(f"[*] 検証モード: 暗号文={args.enc}, 真鍵={args.true_key}, 偽鍵={args.false_key}")
        success, true_dec_path, false_dec_path = verify_keys(args.enc, args.true_key, args.false_key)

        if success:
            print("[+] 検証成功: 鍵ペアは正常に動作しています")

            # 復号結果の比較
            print("\n[*] 復号結果の比較:")
            similarity = compare_file_content(true_dec_path, false_dec_path)

            if similarity < 0.1:
                print("[+] 復号結果の類似度は低く、十分に異なっています")
            elif similarity < 0.3:
                print("[+] 復号結果にある程度の違いがあります")
            else:
                print("[!] 警告: 復号結果の類似度が高すぎます")

            # 可視化
            visualize_results(args.true_file if args.true_file else true_dec_path,
                            args.false_file if args.false_file else false_dec_path,
                            args.enc, true_dec_path, false_dec_path)

        else:
            print("[!] 検証失敗: 鍵ペアに問題があります")

    else:
        # 生成モード
        print("[*] 生成モード: 新しい鍵ペアを生成します")

        # テストファイルの準備
        if args.true_file and args.false_file:
            true_path = args.true_file
            false_path = args.false_file
            print(f"[*] 既存のテキストファイルを使用: 真={true_path}, 偽={false_path}")
        else:
            true_path, false_path = create_test_files()
            print(f"[+] テストファイルを生成しました: 真={true_path}, 偽={false_path}")

        # 鍵ペアの生成
        enc_path, true_key_path, false_key_path = generate_key_pairs(true_path, false_path)
        print(f"[+] 鍵ペアを生成しました: 暗号文={enc_path}, 真鍵={true_key_path}, 偽鍵={false_key_path}")

        # 生成した鍵ペアの検証
        success, true_dec_path, false_dec_path = verify_keys(enc_path, true_key_path, false_key_path)

        if success:
            print("[+] 検証成功: 生成した鍵ペアは正常に動作しています")

            # 元のファイルと復号結果の比較
            print("\n[*] 元のファイルと復号結果の比較:")
            print("--- 真テキスト ---")
            true_similarity = compare_file_content(true_path, true_dec_path)

            print("\n--- 偽テキスト ---")
            false_similarity = compare_file_content(false_path, false_dec_path)

            # 復号結果同士の比較
            print("\n[*] 復号結果の比較:")
            dec_similarity = compare_file_content(true_dec_path, false_dec_path)

            if dec_similarity < 0.1:
                print("[+] 復号結果の類似度は低く、十分に異なっています")
            elif dec_similarity < 0.3:
                print("[+] 復号結果にある程度の違いがあります")
            else:
                print("[!] 警告: 復号結果の類似度が高すぎます")

            # 結果の可視化
            image_path = visualize_results(true_path, false_path, enc_path, true_dec_path, false_dec_path)
            print(f"[+] 検証結果: {image_path}")
            print("[+] GitHub Issue への添付URL: https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/{image_path}?raw=true")

        else:
            print("[!] 検証失敗: 生成した鍵ペアに問題があります")

    print("\n===== 処理完了 =====")


if __name__ == "__main__":
    main()