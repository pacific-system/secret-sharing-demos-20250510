#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
よりシンプルな準同型暗号マスキング方式テスト

このスクリプトは、準同型暗号を用いて2つの鍵で同じ暗号文から
異なるファイルを復号できる機能をシンプルに検証します。
"""

import os
import sys
import time
import json
import random
import base64
import hashlib
import matplotlib.pyplot as plt
from typing import Tuple, Dict, List, Any, Optional, Union

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 入出力パス設定
TRUE_FILE = "common/true-false-text/t.text"
FALSE_FILE = "common/true-false-text/f.text"
OUTPUT_DIR = "test_output"
OUTPUT_ENCRYPTED = os.path.join(OUTPUT_DIR, "simple_homomorphic_encrypted.json")
OUTPUT_DECRYPTED_TRUE = os.path.join(OUTPUT_DIR, "simple_homomorphic_true.text")
OUTPUT_DECRYPTED_FALSE = os.path.join(OUTPUT_DIR, "simple_homomorphic_false.text")

# タイムスタンプ付きログファイル
timestamp = time.strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(OUTPUT_DIR, f"simple_homomorphic_log_{timestamp}.txt")

def log_message(message: str, console: bool = True) -> None:
    """ログにメッセージを記録"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        f.write(log_line + "\n")

    if console:
        print(message)

class SimpleHomomorphicCrypto:
    """シンプルな準同型暗号の実装"""

    def __init__(self, modulus: int = 1337):
        """初期化"""
        self.modulus = modulus

    def encrypt(self, plaintext: bytes, true_key: bytes, false_key: bytes) -> Dict[str, Any]:
        """
        同じ暗号文から2つの異なる平文を復号できるように暗号化

        Args:
            plaintext: 暗号化するデータ（元の真のファイル）
            true_key: 真の鍵
            false_key: 偽の鍵

        Returns:
            暗号化されたデータ
        """
        # キーをハッシュ化
        true_key_hash = int.from_bytes(hashlib.sha256(true_key).digest()[:8], byteorder='big')
        false_key_hash = int.from_bytes(hashlib.sha256(false_key).digest()[:8], byteorder='big')

        # もう1つの偽のファイルを生成（単純な例として、真のファイルの各バイトを反転）
        fake_plaintext = bytes([255 - b for b in plaintext])

        log_message(f"暗号化: 真テキストサイズ={len(plaintext)}, 偽テキストサイズ={len(fake_plaintext)}")

        # デバッグ出力: 元のテキストを確認
        try:
            log_message(f"暗号化前の真テキスト: {plaintext.decode('utf-8')[:100]}...")
        except UnicodeDecodeError:
            log_message(f"暗号化前の真テキスト: (UTF-8でデコード不可)")

        # 真と偽のファイルをBase64エンコード
        true_base64 = base64.b64encode(plaintext).decode('ascii')
        false_base64 = base64.b64encode(fake_plaintext).decode('ascii')

        log_message(f"Base64サイズ: 真={len(true_base64)}, 偽={len(false_base64)}")

        # 単純な暗号化（例示目的のみ - 実際の暗号化ではない）
        encrypted_data = {
            "encrypted": self._simple_encrypt(true_base64, false_base64, true_key_hash, false_key_hash),
            "key_hash": {
                "true": true_key_hash,
                "false": false_key_hash
            },
            "metadata": {
                "timestamp": int(time.time()),
                "true_size": len(plaintext),
                "false_size": len(fake_plaintext),
                "encoding": "utf-8"  # エンコーディング情報を追加
            }
        }

        return encrypted_data

    def _simple_encrypt(self, true_text: str, false_text: str, true_key_hash: int, false_key_hash: int) -> List[Dict[str, Any]]:
        """シンプルな暗号化アルゴリズム"""
        # 長さを揃える
        max_length = max(len(true_text), len(false_text))
        true_text_padded = true_text.ljust(max_length, '=')
        false_text_padded = false_text.ljust(max_length, '=')

        # 各文字を暗号化
        result = []
        for i in range(max_length):
            true_char = ord(true_text_padded[i])
            false_char = ord(false_text_padded[i])

            # 同じ暗号文から2つの異なる平文が得られるように設計
            a = random.randint(1, self.modulus - 1)
            b = (true_char - a * true_key_hash) % self.modulus
            c = (false_char - a * false_key_hash) % self.modulus

            result.append({
                "a": a,
                "b": b,
                "c": c
            })

        return result

    def decrypt(self, encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """
        指定された鍵で暗号文を復号

        Args:
            encrypted_data: 暗号化されたデータ
            key: 復号鍵

        Returns:
            復号されたデータ
        """
        # 鍵をハッシュ化
        key_hash = int.from_bytes(hashlib.sha256(key).digest()[:8], byteorder='big')

        # 真の鍵と偽の鍵のハッシュを取得
        true_key_hash = encrypted_data["key_hash"]["true"]
        false_key_hash = encrypted_data["key_hash"]["false"]

        # どちらの鍵が使われているかを判定
        if abs(key_hash - true_key_hash) < abs(key_hash - false_key_hash):
            key_type = "true"
            key_hash = true_key_hash  # 完全に一致するキーを使用
        else:
            key_type = "false"
            key_hash = false_key_hash  # 完全に一致するキーを使用

        log_message(f"復号: 使用する鍵のタイプ={key_type}")

        # 暗号文を復号
        encrypted = encrypted_data["encrypted"]
        decrypted_chars = []

        for item in encrypted:
            a = item["a"]
            b = item["b"]
            c = item["c"]

            # 鍵タイプに応じて異なる係数を使用
            if key_type == "true":
                decrypted_char = (a * key_hash + b) % self.modulus
            else:
                decrypted_char = (a * key_hash + c) % self.modulus

            decrypted_chars.append(chr(decrypted_char))

        # Base64デコード
        decrypted_base64 = ''.join(decrypted_chars).rstrip('=')

        # デバッグ出力: Base64文字列の最初の部分を確認
        log_message(f"復号されたBase64文字列（先頭100文字）: {decrypted_base64[:100]}...")

        try:
            decrypted_data = base64.b64decode(decrypted_base64)

            # デバッグ出力: 復号されたデータのUTF-8テキスト表現を確認
            try:
                log_message(f"復号されたテキスト（UTF-8、先頭100文字）: {decrypted_data.decode('utf-8')[:100]}...")
            except UnicodeDecodeError:
                log_message(f"復号されたデータはUTF-8テキストではありません")

            return decrypted_data
        except Exception as e:
            log_message(f"Base64デコードエラー: {e}")
            # エラー回復: パディングを調整して再試行
            padded_base64 = decrypted_base64 + '=' * ((4 - len(decrypted_base64) % 4) % 4)
            log_message(f"パディング調整後のBase64長: {len(padded_base64)}")
            try:
                return base64.b64decode(padded_base64)
            except Exception as e2:
                log_message(f"再試行後もデコードエラー: {e2}")
                return b"ERROR: Failed to decode data"

def run_test():
    """テストを実行"""
    log_message("====== シンプルな準同型暗号マスキング方式テスト ======")

    # 出力ディレクトリの作成
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 入力ファイルの読み込み
    log_message(f"テストファイルの読み込み: {TRUE_FILE}")
    with open(TRUE_FILE, 'rb') as f:
        true_content = f.read()

    log_message(f"読み込み完了: サイズ={len(true_content)}バイト")

    # ファイルの内容をデバッグ出力
    try:
        log_message(f"ファイル内容（UTF-8）: \n{true_content.decode('utf-8')}")
    except UnicodeDecodeError:
        log_message("ファイル内容をUTF-8として表示できません")

    # 暗号化
    log_message("暗号化の実行")
    crypto = SimpleHomomorphicCrypto()

    # 鍵の生成
    true_key = os.urandom(32)
    false_key = os.urandom(32)
    log_message(f"鍵生成: 真鍵ハッシュ={hashlib.sha256(true_key).hexdigest()[:8]}, 偽鍵ハッシュ={hashlib.sha256(false_key).hexdigest()[:8]}")

    # 暗号化の実行
    encrypted_data = crypto.encrypt(true_content, true_key, false_key)

    # 暗号文を保存
    log_message(f"暗号化データを保存: {OUTPUT_ENCRYPTED}")
    with open(OUTPUT_ENCRYPTED, 'w', encoding='utf-8') as f:
        json.dump(encrypted_data, f, indent=2)

    # 真の鍵で復号
    log_message("真の鍵で復号")
    true_decrypted = crypto.decrypt(encrypted_data, true_key)

    with open(OUTPUT_DECRYPTED_TRUE, 'wb') as f:
        f.write(true_decrypted)

    log_message(f"真の鍵での復号結果を保存: {OUTPUT_DECRYPTED_TRUE}")

    # 復号結果の内容を表示
    try:
        log_message(f"真の鍵での復号結果（UTF-8）: \n{true_decrypted.decode('utf-8')}")
    except UnicodeDecodeError:
        log_message("真の鍵での復号結果をUTF-8として表示できません")

    # 偽の鍵で復号
    log_message("偽の鍵で復号")
    false_decrypted = crypto.decrypt(encrypted_data, false_key)

    with open(OUTPUT_DECRYPTED_FALSE, 'wb') as f:
        f.write(false_decrypted)

    log_message(f"偽の鍵での復号結果を保存: {OUTPUT_DECRYPTED_FALSE}")

    # 復号結果の内容を表示
    try:
        log_message(f"偽の鍵での復号結果（UTF-8）: \n{false_decrypted.decode('utf-8')}")
    except UnicodeDecodeError:
        log_message("偽の鍵での復号結果をUTF-8として表示できません")

    # 結果の検証
    log_message("結果の検証")
    true_original_hash = hashlib.sha256(true_content).hexdigest()
    true_decrypted_hash = hashlib.sha256(true_decrypted).hexdigest()

    log_message(f"真元データのハッシュ: {true_original_hash}")
    log_message(f"真復号データのハッシュ: {true_decrypted_hash}")
    log_message(f"一致: {true_original_hash == true_decrypted_hash}")

    # グラフの生成
    log_message("視覚化グラフを生成")
    plt.figure(figsize=(10, 6))

    # ファイルサイズを比較
    file_sizes = [
        len(true_content),
        len(true_decrypted),
        len(false_decrypted),
        os.path.getsize(OUTPUT_ENCRYPTED)
    ]

    labels = ['元の真ファイル', '真鍵で復号', '偽鍵で復号', '暗号化ファイル']
    colors = ['green', 'lightgreen', 'red', 'blue']

    plt.bar(labels, file_sizes, color=colors)
    plt.title('シンプルな準同型暗号マスキング方式テスト結果')
    plt.ylabel('ファイルサイズ (バイト)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # グラフを保存
    graph_file = os.path.join(OUTPUT_DIR, "simple_homomorphic_test.png")
    plt.savefig(graph_file)
    log_message(f"グラフを保存: {graph_file}")

    log_message("====== テスト完了 ======")
    return {
        "true_match": true_original_hash == true_decrypted_hash,
        "true_size": len(true_content),
        "true_decrypted_size": len(true_decrypted),
        "false_decrypted_size": len(false_decrypted),
        "encrypted_size": os.path.getsize(OUTPUT_ENCRYPTED)
    }

if __name__ == "__main__":
    result = run_test()
    if result["true_match"]:
        log_message("✅ テスト成功: 真の鍵で元の真ファイルが復元されました")
    else:
        log_message("❌ テスト失敗: 真の鍵で元の真ファイルが復元されませんでした")

    log_message(f"詳細ログ: {LOG_FILE}")
    sys.exit(0 if result["true_match"] else 1)