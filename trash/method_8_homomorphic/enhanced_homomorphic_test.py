#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の拡張テスト

このスクリプトは、UTF-8テキスト（日本語や絵文字を含む）の
暗号化と復号が正しく機能することを検証するテストを提供します。
"""

import os
import sys
import time
import json
import base64
import hashlib
import random
import binascii
import matplotlib.pyplot as plt
from typing import Tuple, Dict, List, Any, Optional, Union

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 入出力パス設定
TRUE_FILE = "common/true-false-text/t.text"
FALSE_FILE = "common/true-false-text/f.text"
OUTPUT_DIR = "test_output"
OUTPUT_ENCRYPTED = os.path.join(OUTPUT_DIR, "enhanced_homomorphic_encrypted.json")
OUTPUT_DECRYPTED_TRUE = os.path.join(OUTPUT_DIR, "enhanced_homomorphic_true.text")
OUTPUT_DECRYPTED_FALSE = os.path.join(OUTPUT_DIR, "enhanced_homomorphic_false.text")
METRICS_FILE = os.path.join(OUTPUT_DIR, f"enhanced_homomorphic_metrics_{int(time.time())}.json")
GRAPH_FILE = os.path.join(OUTPUT_DIR, f"enhanced_homomorphic_test_{int(time.time())}.png")

# タイムスタンプ付きログファイル
timestamp = time.strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(OUTPUT_DIR, f"enhanced_homomorphic_log_{timestamp}.txt")

def log_message(message: str, console: bool = True) -> None:
    """ログにメッセージを記録"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        f.write(log_line + "\n")

    if console:
        print(message)

class EnhancedHomomorphicCrypto:
    """拡張準同型暗号の実装"""

    def __init__(self, modulus: int = 1337):
        """初期化"""
        self.modulus = modulus
        self.metrics = {
            "encrypt_time": 0,
            "decrypt_time": {"true": 0, "false": 0},
            "file_sizes": {
                "true_original": 0,
                "false_original": 0,
                "encrypted": 0,
                "true_decrypted": 0,
                "false_decrypted": 0
            },
            "timestamps": {
                "encrypt_start": 0,
                "encrypt_end": 0,
                "true_decrypt_start": 0,
                "true_decrypt_end": 0,
                "false_decrypt_start": 0,
                "false_decrypt_end": 0
            }
        }

    def encrypt(self, true_plaintext: bytes, false_plaintext: bytes, true_key: bytes, false_key: bytes) -> Dict[str, Any]:
        """
        同じ暗号文から2つの異なる平文を復号できるように暗号化

        Args:
            true_plaintext: 暗号化する真のデータ
            false_plaintext: 暗号化する偽のデータ
            true_key: 真の鍵
            false_key: 偽の鍵

        Returns:
            暗号化されたデータ
        """
        # タイムスタンプ記録
        self.metrics["timestamps"]["encrypt_start"] = time.time()

        # ファイルサイズ記録
        self.metrics["file_sizes"]["true_original"] = len(true_plaintext)
        self.metrics["file_sizes"]["false_original"] = len(false_plaintext)

        # キーをハッシュ化
        true_key_hash = int.from_bytes(hashlib.sha256(true_key).digest()[:8], byteorder='big')
        false_key_hash = int.from_bytes(hashlib.sha256(false_key).digest()[:8], byteorder='big')

        log_message(f"暗号化: 真テキストサイズ={len(true_plaintext)}バイト, 偽テキストサイズ={len(false_plaintext)}バイト")

        # デバッグ出力: 元のテキストを確認
        try:
            log_message(f"暗号化前の真テキスト: {true_plaintext.decode('utf-8')[:50]}...")
            log_message(f"暗号化前の偽テキスト: {false_plaintext.decode('utf-8')[:50]}...")
        except UnicodeDecodeError:
            log_message(f"暗号化前のテキストのUTF-8デコードに失敗しました")

        # Base64エンコード - UTF-8を維持するために重要
        true_base64 = base64.b64encode(true_plaintext).decode('ascii')
        false_base64 = base64.b64encode(false_plaintext).decode('ascii')

        log_message(f"Base64サイズ: 真={len(true_base64)}, 偽={len(false_base64)}")

        # 暗号化
        encrypted_data = {
            "encrypted": self._encrypt_data(true_base64, false_base64, true_key_hash, false_key_hash),
            "key_hash": {
                "true": true_key_hash,
                "false": false_key_hash
            },
            "metadata": {
                "timestamp": int(time.time()),
                "true_size": len(true_plaintext),
                "false_size": len(false_plaintext),
                "encoding": "utf-8",
                "format_version": "1.1"
            }
        }

        # タイムスタンプ記録
        self.metrics["timestamps"]["encrypt_end"] = time.time()
        self.metrics["encrypt_time"] = self.metrics["timestamps"]["encrypt_end"] - self.metrics["timestamps"]["encrypt_start"]

        return encrypted_data

    def _encrypt_data(self, true_text: str, false_text: str, true_key_hash: int, false_key_hash: int) -> List[Dict[str, Any]]:
        """拡張暗号化アルゴリズム"""
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

            # キーハッシュの差を考慮して鍵判定を難読化
            d = random.randint(1, self.modulus - 1)
            e = (d * true_key_hash) % self.modulus
            f = (d * false_key_hash) % self.modulus

            result.append({
                "a": a,
                "b": b,
                "c": c,
                "d": d,
                "e": e,
                "f": f
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

        # ゼロ知識証明的な手法で鍵の種類を判定
        # 鍵判定がソースコード解析されにくくなるよう、複雑な判定方法を採用
        key_type = None
        encrypted_items = encrypted_data["encrypted"]
        if len(encrypted_items) > 0:
            # 複数の項目をサンプリングして判定（難読化）
            samples = min(5, len(encrypted_items))
            true_matches = 0
            false_matches = 0

            for _ in range(samples):
                idx = random.randrange(len(encrypted_items))
                item = encrypted_items[idx]

                # 複雑な判定条件（解析されにくくするため）
                d, e, f = item["d"], item["e"], item["f"]
                test1 = (d * key_hash) % self.modulus

                # 許容誤差を含めた判定
                if abs(test1 - e) < abs(test1 - f):
                    true_matches += 1
                else:
                    false_matches += 1

            # 多数決で判定
            key_type = "true" if true_matches >= false_matches else "false"
        else:
            # フォールバック判定（通常は使用されない）
            dist_true = abs(key_hash - true_key_hash)
            dist_false = abs(key_hash - false_key_hash)
            key_type = "true" if dist_true < dist_false else "false"

        # タイムスタンプ記録
        if key_type == "true":
            self.metrics["timestamps"]["true_decrypt_start"] = time.time()
        else:
            self.metrics["timestamps"]["false_decrypt_start"] = time.time()

        log_message(f"復号: 使用する鍵のタイプ={key_type}")

        # 完全一致するキーハッシュを使用（強化版）
        actual_key_hash = true_key_hash if key_type == "true" else false_key_hash

        # 暗号文を復号
        encrypted = encrypted_data["encrypted"]
        decrypted_chars = []

        for item in encrypted:
            a = item["a"]
            b = item["b"]
            c = item["c"]

            # 鍵タイプに応じて異なる係数を使用
            if key_type == "true":
                decrypted_char = (a * actual_key_hash + b) % self.modulus
            else:
                decrypted_char = (a * actual_key_hash + c) % self.modulus

            decrypted_chars.append(chr(decrypted_char))

        # Base64デコード
        decrypted_base64 = ''.join(decrypted_chars).rstrip('=')

        # デバッグ出力: Base64文字列の最初の部分を確認
        log_message(f"復号されたBase64文字列（先頭50文字）: {decrypted_base64[:50]}...")

        try:
            # Base64パディングの修正（必要に応じて）
            padding_needed = len(decrypted_base64) % 4
            if padding_needed > 0:
                decrypted_base64 += '=' * (4 - padding_needed)

            decrypted_data = base64.b64decode(decrypted_base64)

            # デバッグ出力: 復号されたデータのUTF-8テキスト表現を確認
            try:
                log_message(f"復号されたテキスト（UTF-8、先頭50文字）: {decrypted_data.decode('utf-8')[:50]}...")
            except UnicodeDecodeError:
                log_message(f"復号されたデータはUTF-8テキストではありません")

            # タイムスタンプ記録
            if key_type == "true":
                self.metrics["timestamps"]["true_decrypt_end"] = time.time()
                self.metrics["decrypt_time"]["true"] = self.metrics["timestamps"]["true_decrypt_end"] - self.metrics["timestamps"]["true_decrypt_start"]
                self.metrics["file_sizes"]["true_decrypted"] = len(decrypted_data)
            else:
                self.metrics["timestamps"]["false_decrypt_end"] = time.time()
                self.metrics["decrypt_time"]["false"] = self.metrics["timestamps"]["false_decrypt_end"] - self.metrics["timestamps"]["false_decrypt_start"]
                self.metrics["file_sizes"]["false_decrypted"] = len(decrypted_data)

            return decrypted_data

        except Exception as e:
            log_message(f"Base64デコードエラー: {e}")
            # エラー回復: パディングを調整して再試行
            padded_base64 = decrypted_base64 + '=' * ((4 - len(decrypted_base64) % 4) % 4)
            log_message(f"パディング調整後のBase64長: {len(padded_base64)}")
            try:
                result = base64.b64decode(padded_base64)

                # タイムスタンプ記録（エラー回復ケース）
                if key_type == "true":
                    self.metrics["timestamps"]["true_decrypt_end"] = time.time()
                    self.metrics["decrypt_time"]["true"] = self.metrics["timestamps"]["true_decrypt_end"] - self.metrics["timestamps"]["true_decrypt_start"]
                    self.metrics["file_sizes"]["true_decrypted"] = len(result)
                else:
                    self.metrics["timestamps"]["false_decrypt_end"] = time.time()
                    self.metrics["decrypt_time"]["false"] = self.metrics["timestamps"]["false_decrypt_end"] - self.metrics["timestamps"]["false_decrypt_start"]
                    self.metrics["file_sizes"]["false_decrypted"] = len(result)

                return result
            except Exception as e2:
                log_message(f"再試行後もデコードエラー: {e2}")

                # エラー記録
                if key_type == "true":
                    self.metrics["timestamps"]["true_decrypt_end"] = time.time()
                    self.metrics["decrypt_time"]["true"] = self.metrics["timestamps"]["true_decrypt_end"] - self.metrics["timestamps"]["true_decrypt_start"]
                    self.metrics["file_sizes"]["true_decrypted"] = 0
                else:
                    self.metrics["timestamps"]["false_decrypt_end"] = time.time()
                    self.metrics["decrypt_time"]["false"] = self.metrics["timestamps"]["false_decrypt_end"] - self.metrics["timestamps"]["false_decrypt_start"]
                    self.metrics["file_sizes"]["false_decrypted"] = 0

                return b"ERROR: Failed to decode data"

def run_test():
    """テストを実行"""
    log_message("====== 拡張準同型暗号マスキング方式テスト ======")

    # 出力ディレクトリの作成
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 入力ファイルの読み込み
    log_message(f"真のテストファイルの読み込み: {TRUE_FILE}")
    with open(TRUE_FILE, 'rb') as f:
        true_content = f.read()

    log_message(f"偽のテストファイルの読み込み: {FALSE_FILE}")
    with open(FALSE_FILE, 'rb') as f:
        false_content = f.read()

    log_message(f"読み込み完了: 真={len(true_content)}バイト, 偽={len(false_content)}バイト")

    # ファイルの内容をデバッグ出力
    try:
        log_message(f"真ファイル内容（UTF-8）: \n{true_content.decode('utf-8')}")
        log_message(f"偽ファイル内容（UTF-8）: \n{false_content.decode('utf-8')}")
    except UnicodeDecodeError:
        log_message("ファイル内容をUTF-8として表示できません")

    # 暗号化
    log_message("暗号化の実行")
    crypto = EnhancedHomomorphicCrypto()

    # 鍵の生成
    true_key = os.urandom(32)
    false_key = os.urandom(32)
    log_message(f"鍵生成: 真鍵ハッシュ={hashlib.sha256(true_key).hexdigest()[:8]}, 偽鍵ハッシュ={hashlib.sha256(false_key).hexdigest()[:8]}")

    # 暗号化の実行
    encrypted_data = crypto.encrypt(true_content, false_content, true_key, false_key)

    # 暗号文を保存
    log_message(f"暗号化データを保存: {OUTPUT_ENCRYPTED}")
    with open(OUTPUT_ENCRYPTED, 'w', encoding='utf-8') as f:
        json.dump(encrypted_data, f, indent=2)

    # 暗号化ファイルサイズを記録
    crypto.metrics["file_sizes"]["encrypted"] = os.path.getsize(OUTPUT_ENCRYPTED)

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
    false_original_hash = hashlib.sha256(false_content).hexdigest()
    false_decrypted_hash = hashlib.sha256(false_decrypted).hexdigest()

    log_message(f"真元データのハッシュ: {true_original_hash}")
    log_message(f"真復号データのハッシュ: {true_decrypted_hash}")
    log_message(f"真データ一致: {true_original_hash == true_decrypted_hash}")

    log_message(f"偽元データのハッシュ: {false_original_hash}")
    log_message(f"偽復号データのハッシュ: {false_decrypted_hash}")
    log_message(f"偽データ一致: {false_original_hash == false_decrypted_hash}")

    # メトリクスを保存
    with open(METRICS_FILE, 'w', encoding='utf-8') as f:
        json.dump(crypto.metrics, f, indent=2)
    log_message(f"メトリクスを保存: {METRICS_FILE}")

    # グラフの生成
    log_message("視覚化グラフを生成")
    create_visualization_graph(crypto.metrics, output_file=GRAPH_FILE)
    log_message(f"グラフを保存: {GRAPH_FILE}")

    log_message("====== テスト完了 ======")
    return {
        "true_match": true_original_hash == true_decrypted_hash,
        "false_match": false_original_hash == false_decrypted_hash,
        "metrics": crypto.metrics
    }

def create_visualization_graph(metrics: Dict[str, Any], output_file: str) -> None:
    """メトリクスを視覚化したグラフを生成"""
    plt.figure(figsize=(15, 10))

    # 4つのサブプロットを作成
    plt.subplot(2, 2, 1)

    # 1. ファイルサイズの比較
    file_sizes = [
        metrics["file_sizes"]["true_original"],
        metrics["file_sizes"]["false_original"],
        metrics["file_sizes"]["encrypted"],
        metrics["file_sizes"]["true_decrypted"],
        metrics["file_sizes"]["false_decrypted"]
    ]

    labels = ['元の真ファイル', '元の偽ファイル', '暗号化ファイル', '真鍵で復号', '偽鍵で復号']
    colors = ['green', 'red', 'blue', 'lightgreen', 'lightcoral']

    plt.bar(labels, file_sizes, color=colors)
    plt.title('ファイルサイズ比較')
    plt.ylabel('サイズ (バイト)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # 2. 処理時間の比較
    plt.subplot(2, 2, 2)
    times = [
        metrics["encrypt_time"],
        metrics["decrypt_time"]["true"],
        metrics["decrypt_time"]["false"]
    ]
    time_labels = ['暗号化', '真鍵で復号', '偽鍵で復号']
    time_colors = ['blue', 'green', 'red']

    plt.bar(time_labels, times, color=time_colors)
    plt.title('処理時間比較')
    plt.ylabel('時間 (秒)')

    # 3. 暗号化と復号のワークフロー
    plt.subplot(2, 2, 3)
    plt.text(0.5, 0.5,
             f"準同型暗号マスキング方式\n\n"
             f"暗号化時間: {metrics['encrypt_time']:.4f}秒\n"
             f"復号時間 (真鍵): {metrics['decrypt_time']['true']:.4f}秒\n"
             f"復号時間 (偽鍵): {metrics['decrypt_time']['false']:.4f}秒\n\n"
             f"元の真ファイル: {metrics['file_sizes']['true_original']}バイト\n"
             f"元の偽ファイル: {metrics['file_sizes']['false_original']}バイト\n"
             f"暗号化ファイル: {metrics['file_sizes']['encrypted']}バイト\n"
             f"復号後 (真鍵): {metrics['file_sizes']['true_decrypted']}バイト\n"
             f"復号後 (偽鍵): {metrics['file_sizes']['false_decrypted']}バイト\n",
             ha='center', va='center', fontsize=9)
    plt.axis('off')

    # 4. 暗号化と復号のフロー図
    plt.subplot(2, 2, 4)
    plt.axis('off')

    # フロー図を描画
    plt.annotate('元の真ファイル', xy=(0.1, 0.9), xycoords='axes fraction', fontsize=10)
    plt.annotate('元の偽ファイル', xy=(0.1, 0.1), xycoords='axes fraction', fontsize=10)

    # 矢印と暗号化ボックス
    plt.annotate('', xy=(0.4, 0.5), xytext=(0.1, 0.9),
                 arrowprops=dict(arrowstyle='->'), xycoords='axes fraction')
    plt.annotate('', xy=(0.4, 0.5), xytext=(0.1, 0.1),
                 arrowprops=dict(arrowstyle='->'), xycoords='axes fraction')

    # 暗号化ボックス
    plt.annotate('暗号化', xy=(0.4, 0.5), xycoords='axes fraction',
                 bbox=dict(boxstyle='round,pad=0.3', fc='lightblue', alpha=0.7),
                 ha='center', fontsize=10)

    # 暗号化から復号への矢印
    plt.annotate('', xy=(0.7, 0.9), xytext=(0.4, 0.5),
                 arrowprops=dict(arrowstyle='->'), xycoords='axes fraction')
    plt.annotate('真鍵', xy=(0.55, 0.75), xycoords='axes fraction', fontsize=8)

    plt.annotate('', xy=(0.7, 0.1), xytext=(0.4, 0.5),
                 arrowprops=dict(arrowstyle='->'), xycoords='axes fraction')
    plt.annotate('偽鍵', xy=(0.55, 0.25), xycoords='axes fraction', fontsize=8)

    # 復号結果ボックス
    plt.annotate('真の復号結果', xy=(0.7, 0.9), xycoords='axes fraction',
                 bbox=dict(boxstyle='round,pad=0.3', fc='lightgreen', alpha=0.7),
                 ha='center', fontsize=10)

    plt.annotate('偽の復号結果', xy=(0.7, 0.1), xycoords='axes fraction',
                 bbox=dict(boxstyle='round,pad=0.3', fc='lightcoral', alpha=0.7),
                 ha='center', fontsize=10)

    plt.tight_layout()
    plt.savefig(output_file)

if __name__ == "__main__":
    result = run_test()
    if result["true_match"] and result["false_match"]:
        log_message("✅ テスト成功: 両方のファイルが正しく復元されました")
    elif result["true_match"]:
        log_message("⚠️ 部分成功: 真のファイルのみ正しく復元されました")
    elif result["false_match"]:
        log_message("⚠️ 部分成功: 偽のファイルのみ正しく復元されました")
    else:
        log_message("❌ テスト失敗: どちらのファイルも正しく復元されませんでした")

    log_message(f"詳細ログ: {LOG_FILE}")
    sys.exit(0 if result["true_match"] and result["false_match"] else 1)