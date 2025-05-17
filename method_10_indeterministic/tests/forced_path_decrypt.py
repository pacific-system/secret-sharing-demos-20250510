#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 強制実行パステスト

暗号文に対して特定の実行パス（TRUE/FALSE）を強制的に使用して
復号を行い、復号結果を比較するテストスクリプトです。
"""

import os
import sys
import time
import json
import base64
import hashlib
import argparse
import tempfile
import shutil
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Tuple, Any, List, Optional, Union

# 親ディレクトリをインポートパスに追加
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

# モジュールをインポート
from method_10_indeterministic.decrypt import determine_execution_path, extract_from_state_capsule

# テスト用のディレクトリ
TEST_OUTPUT_DIR = "test_output"
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

# 実行パスタイプ
TRUE_PATH = "true"
FALSE_PATH = "false"


def extract_key_data(key_path: str) -> Tuple[bytes, bytes, Dict[str, Any]]:
    """
    鍵ファイルからキーデータを抽出

    Args:
        key_path: 鍵ファイルのパス

    Returns:
        (master_key, salt, metadata): マスター鍵、ソルト、メタデータ
    """
    try:
        with open(key_path, "r") as f:
            try:
                # JSONとして解析
                key_data = json.load(f)

                # マスター鍵の抽出
                master_key_b64 = key_data.get("master_key", "")
                master_key = base64.b64decode(master_key_b64)

                # ソルトの抽出
                salt_b64 = key_data.get("salt", "")
                salt = base64.b64decode(salt_b64) if salt_b64 else os.urandom(16)

                return master_key, salt, key_data
            except json.JSONDecodeError:
                # 生のキーデータとして扱う
                key_data = f.read().strip()
                if len(key_data) >= 32:
                    master_key = key_data[:32].encode('utf-8')
                    salt = os.urandom(16)
                    return master_key, salt, {"raw_key": True}
                else:
                    raise ValueError(f"無効な鍵データ（長さが不足）: {len(key_data)} バイト")
    except Exception as e:
        print(f"鍵ファイルの読み込み中にエラーが発生しました: {e}")
        raise


def read_encrypted_file(file_path: str) -> Tuple[Dict[str, Any], bytes, bytes]:
    """
    暗号化ファイルを読み込み、メタデータとデータ部分を抽出

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (metadata, header, encrypted_data): メタデータ、ヘッダ、暗号化データ
    """
    try:
        with open(file_path, "rb") as f:
            # ファイル全体を読み込み
            file_contents = f.read()

            if len(file_contents) < 256:
                raise ValueError(f"ファイルサイズが小さすぎます（{len(file_contents)}バイト）")

            # メタデータヘッダを抽出（JSONとして解析）
            header_size = 256  # 固定サイズのヘッダを想定
            header = file_contents[:header_size]

            try:
                # ヘッダからJSONメタデータを抽出
                header_str = header.split(b'\0')[0].decode('utf-8')
                metadata = json.loads(header_str)
            except (UnicodeDecodeError, json.JSONDecodeError):
                # ヘッダが正しいJSONでない場合はデフォルト値を使用
                metadata = {"version": "1.0.0", "timestamp": int(time.time())}

            # 暗号化データを抽出
            encrypted_data = file_contents[header_size:]

            return metadata, header, encrypted_data
    except Exception as e:
        print(f"暗号化ファイルの読み込み中にエラーが発生しました: {e}")
        raise


def force_decrypt(encrypted_path: str, key_path: str, forced_path: str, output_path: Optional[str] = None) -> str:
    """
    指定された実行パスで強制的に復号

    Args:
        encrypted_path: 暗号化ファイルのパス
        key_path: 復号鍵ファイルのパス
        forced_path: 強制する実行パス ("true" または "false")
        output_path: 出力ファイルのパス（省略時は自動生成）

    Returns:
        str: 出力ファイルのパス
    """
    # 実行パスの検証
    if forced_path not in [TRUE_PATH, FALSE_PATH]:
        raise ValueError(f"無効な実行パス: {forced_path} (true または false を指定してください)")

    # 鍵データの抽出
    master_key, salt, key_metadata = extract_key_data(key_path)

    # 暗号化ファイルの読み込み
    metadata, header, encrypted_data = read_encrypted_file(encrypted_path)

    # 出力パスの設定
    if not output_path:
        timestamp = int(time.time())
        base_name = os.path.basename(encrypted_path)
        if "." in base_name:
            prefix, ext = os.path.splitext(base_name)
            output_path = os.path.join(TEST_OUTPUT_DIR, f"{prefix}_forced_{forced_path}_{timestamp}{ext}")
        else:
            output_path = os.path.join(TEST_OUTPUT_DIR, f"{base_name}_forced_{forced_path}_{timestamp}")

    # 分析情報を表示
    print(f"[*] 暗号化ファイル: {encrypted_path} ({len(encrypted_data)} バイト)")
    print(f"[*] 鍵ファイル: {key_path}")
    print(f"[*] 強制実行パス: {forced_path}")
    print(f"[*] 出力先: {output_path}")

    # determine_execution_path関数の結果を取得（正規の判定）
    original_path = determine_execution_path(master_key, metadata)
    print(f"[*] 通常の実行パス判定結果: {original_path}")
    print(f"[*] 強制モードで {forced_path} パスを使用します")

    # カプセルから指定されたパスのデータを抽出
    print(f"[*] カプセルからデータを抽出中...")
    extracted_data = extract_from_state_capsule(encrypted_data, master_key, salt, forced_path)

    # 抽出されたデータをファイルに保存
    with open(output_path, "wb") as f:
        f.write(extracted_data)

    print(f"[+] 処理完了: {output_path} に保存されました（{len(extracted_data)} バイト）")
    return output_path


def compare_results(true_path: str, false_path: str) -> float:
    """
    異なる実行パスでの復号結果を比較

    Args:
        true_path: TRUEパスでの復号結果ファイルパス
        false_path: FALSEパスでの復号結果ファイルパス

    Returns:
        float: 類似度（0.0〜1.0）
    """
    # ファイルを読み込み
    with open(true_path, "rb") as f:
        true_data = f.read()

    with open(false_path, "rb") as f:
        false_data = f.read()

    # サイズの比較
    min_size = min(len(true_data), len(false_data))
    max_size = max(len(true_data), len(false_data))

    print(f"[*] ファイルサイズ: TRUE={len(true_data)} バイト, FALSE={len(false_data)} バイト")
    print(f"[*] サイズ比: {len(true_data)/len(false_data):.2f}")

    # バイト単位の比較
    if min_size == 0:
        # どちらかのファイルが空の場合
        similarity = 0.0 if max_size > 0 else 1.0
    else:
        # 共通の部分について一致するバイトの割合を計算
        same_bytes = sum(1 for a, b in zip(true_data[:min_size], false_data[:min_size]) if a == b)
        similarity = same_bytes / min_size

    print(f"[*] バイト単位の類似度: {similarity:.2%}")

    # ハッシュ値の比較
    true_hash = hashlib.sha256(true_data).hexdigest()
    false_hash = hashlib.sha256(false_data).hexdigest()

    print(f"[*] TRUEパスのハッシュ値: {true_hash}")
    print(f"[*] FALSEパスのハッシュ値: {false_hash}")

    # ハッシュ値の違いを確認
    hash_diff = sum(1 for a, b in zip(true_hash, false_hash) if a != b)
    print(f"[*] ハッシュ値の差異: {hash_diff}/64文字 ({hash_diff/64:.2%})")

    return similarity


def visualize_comparison(true_path: str, false_path: str) -> str:
    """
    復号結果を可視化して比較

    Args:
        true_path: TRUEパスでの復号結果ファイルパス
        false_path: FALSEパスでの復号結果ファイルパス

    Returns:
        str: 生成された画像ファイルのパス
    """
    # ファイルを読み込み
    with open(true_path, "rb") as f:
        true_data = f.read()

    with open(false_path, "rb") as f:
        false_data = f.read()

    # バイト値の分布を計算
    def count_bytes(data):
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        return counts

    true_counts = count_bytes(true_data)
    false_counts = count_bytes(false_data)

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

    true_entropy = calc_entropy(true_data)
    false_entropy = calc_entropy(false_data)

    # 差分の可視化
    plt.figure(figsize=(15, 10))

    # 1. バイト値の分布比較
    plt.subplot(2, 2, 1)
    x = range(256)
    plt.plot(x, true_counts, 'g-', alpha=0.7, label='TRUEパス')
    plt.plot(x, false_counts, 'r-', alpha=0.7, label='FALSEパス')
    plt.title('バイト値の分布比較')
    plt.xlabel('バイト値')
    plt.ylabel('出現頻度')
    plt.legend()
    plt.grid(True, alpha=0.3)

    # 2. バイト値の差分
    plt.subplot(2, 2, 2)
    diff_counts = [abs(t - f) for t, f in zip(true_counts, false_counts)]
    plt.bar(x, diff_counts, alpha=0.7, color='blue')
    plt.title('バイト値分布の差分')
    plt.xlabel('バイト値')
    plt.ylabel('差分値')
    plt.grid(True, alpha=0.3)

    # 3. エントロピー比較
    plt.subplot(2, 2, 3)
    labels = ['TRUEパス', 'FALSEパス']
    values = [true_entropy, false_entropy]
    plt.bar(labels, values, color=['green', 'red'])
    plt.axhline(y=8.0, color='gray', linestyle='--', label='理論上の最大値')
    plt.axhline(y=7.5, color='blue', linestyle='--', label='高エントロピー閾値')
    plt.title('エントロピー比較')
    plt.ylabel('エントロピー値 (ビット/バイト)')
    plt.ylim(0, 8.2)

    # エントロピー値のラベル表示
    for i, v in enumerate(values):
        plt.text(i, v + 0.1, f"{v:.2f}", ha='center')

    # 4. バイト一致率のヒートマップ
    plt.subplot(2, 2, 4)

    # サンプリングして一致率を計算（全データだと処理が重いため）
    sample_size = min(1000, min(len(true_data), len(false_data)))
    true_sample = true_data[:sample_size]
    false_sample = false_data[:sample_size]

    # 2次元グリッドに距離をマッピング
    grid_size = 32
    match_grid = np.zeros((grid_size, grid_size))

    for i in range(grid_size):
        for j in range(grid_size):
            i_start = i * sample_size // grid_size
            i_end = (i + 1) * sample_size // grid_size
            j_start = j * sample_size // grid_size
            j_end = (j + 1) * sample_size // grid_size

            # 各グリッドセル内でのバイト一致率
            matches = sum(1 for a, b in zip(true_sample[i_start:i_end], false_sample[j_start:j_end]) if a == b)
            total = min(i_end - i_start, j_end - j_start)
            match_grid[i, j] = matches / total if total > 0 else 0

    plt.imshow(match_grid, cmap='viridis', aspect='auto')
    plt.colorbar(label='バイト一致率')
    plt.title('データ構造の類似性マップ')
    plt.xlabel('FALSEパスデータ位置')
    plt.ylabel('TRUEパスデータ位置')

    plt.tight_layout()

    # グラフを保存
    timestamp = int(time.time())
    image_path = os.path.join(TEST_OUTPUT_DIR, f"forced_path_comparison_{timestamp}.png")
    plt.savefig(image_path)
    plt.close()

    print(f"[+] 比較結果のグラフを保存しました: {image_path}")
    return image_path


def main():
    """
    メイン処理
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式の強制実行パステスト")
    parser.add_argument("--enc", required=True, help="暗号化ファイルのパス")
    parser.add_argument("--key", required=True, help="鍵ファイルのパス")
    parser.add_argument("--path", choices=[TRUE_PATH, FALSE_PATH], help="強制する実行パス（省略時は両方実行）")
    parser.add_argument("--output", help="出力ファイルのパス（省略時は自動生成）")

    args = parser.parse_args()

    print("===== 不確定性転写暗号化方式 - 強制実行パステスト =====")

    # 共通パラメータ
    enc_path = args.enc
    key_path = args.key

    if not os.path.exists(enc_path):
        print(f"[!] エラー: 暗号化ファイル {enc_path} が見つかりません")
        return

    if not os.path.exists(key_path):
        print(f"[!] エラー: 鍵ファイル {key_path} が見つかりません")
        return

    # 強制実行パスの処理
    if args.path:
        # 単一パスのみ実行
        output_path = args.output
        try:
            result_path = force_decrypt(enc_path, key_path, args.path, output_path)
            print(f"[+] 復号結果: {result_path}")
        except Exception as e:
            print(f"[!] エラー: 復号処理中に例外が発生しました: {e}")
            import traceback
            traceback.print_exc()
    else:
        # 両方のパスを実行して比較
        try:
            # TRUEパスでの復号
            print("\n[*] TRUEパスでの復号を実行:")
            true_result = force_decrypt(enc_path, key_path, TRUE_PATH)

            # FALSEパスでの復号
            print("\n[*] FALSEパスでの復号を実行:")
            false_result = force_decrypt(enc_path, key_path, FALSE_PATH)

            # 結果の比較
            print("\n[*] 復号結果の比較:")
            similarity = compare_results(true_result, false_result)

            # 判定
            if similarity < 0.1:
                print("[+] 復号結果の類似度は低く、十分に異なっています")
            elif similarity < 0.3:
                print("[+] 復号結果にある程度の違いがあります")
            else:
                print("[!] 警告: 復号結果の類似度が高すぎます")

            # 可視化
            image_path = visualize_comparison(true_result, false_result)
            print(f"[+] 比較結果: {image_path}")
            print(f"[+] GitHub Issue への添付URL: https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/{image_path}?raw=true")

        except Exception as e:
            print(f"[!] エラー: 処理中に例外が発生しました: {e}")
            import traceback
            traceback.print_exc()

    print("\n===== 処理完了 =====")


if __name__ == "__main__":
    main()