#!/usr/bin/env python3
"""
鍵ペア生成スクリプト

暗号文の動作テスト用に、正規パスと非正規パスの鍵ペアを生成します。
同じ暗号文から異なる平文が復号できることを確認できます。
"""

import os
import sys
import hashlib
import base64
import json
import argparse
from pathlib import Path

# 内部実装にアクセスするためのパスを追加
sys.path.insert(0, os.path.abspath('../..'))
from method_10_indeterministic.probability_engine import TRUE_PATH, FALSE_PATH
from method_10_indeterministic.decrypt import determine_execution_path


def calculate_path(key: bytes, salt: bytes) -> str:
    """特定の鍵とソルトの組み合わせに対する実行パスを計算"""
    # メタデータを準備
    metadata = {"salt": base64.b64encode(salt).decode('utf-8')}

    # 実行パスを決定
    path = determine_execution_path(key, metadata)

    return path


def find_key_pairs(salt: bytes, num_pairs: int = 5) -> list:
    """
    指定されたソルトに対する真/偽の鍵ペアを生成します

    Args:
        salt: ソルト値
        num_pairs: 生成するペア数

    Returns:
        [(true_key, false_key), ...] の形式のリスト
    """
    true_keys = []
    false_keys = []
    key_pairs = []

    # 必要な数のキーペアを見つけるまで探索
    attempts = 0
    max_attempts = num_pairs * 1000  # 最大試行回数

    print(f"鍵ペアを探索中...")

    while len(key_pairs) < num_pairs and attempts < max_attempts:
        # ランダムな鍵を生成
        key = os.urandom(32)

        # パスを判定
        path = calculate_path(key, salt)

        if path == TRUE_PATH and len(true_keys) < num_pairs:
            # まだ足りていない場合のみ追加
            if key not in true_keys:
                true_keys.append(key)
                print(f"TRUE鍵を発見: {key.hex()[:8]}...")

        elif path == FALSE_PATH and len(false_keys) < num_pairs:
            # まだ足りていない場合のみ追加
            if key not in false_keys:
                false_keys.append(key)
                print(f"FALSE鍵を発見: {key.hex()[:8]}...")

        # ペアを作成
        while len(true_keys) > 0 and len(false_keys) > 0 and len(key_pairs) < num_pairs:
            true_key = true_keys.pop(0)
            false_key = false_keys.pop(0)
            key_pairs.append((true_key, false_key))
            print(f"鍵ペア {len(key_pairs)} を作成しました")

        attempts += 1

        # 進捗表示
        if attempts % 100 == 0:
            print(f"試行回数: {attempts}, 見つかったTRUE鍵: {len(true_keys)}, FALSE鍵: {len(false_keys)}, ペア: {len(key_pairs)}")

    if len(key_pairs) < num_pairs:
        print(f"警告: 要求された{num_pairs}ペアのうち、{len(key_pairs)}ペアしか見つかりませんでした。")

    return key_pairs


def save_key_pairs(key_pairs: list, output_dir: str):
    """
    鍵ペアを保存する

    Args:
        key_pairs: [(true_key, false_key), ...] 形式の鍵ペアリスト
        output_dir: 出力ディレクトリ
    """
    # 出力ディレクトリを作成
    os.makedirs(output_dir, exist_ok=True)

    # 共通のソルト
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode('utf-8')

    # ソルト情報を保存
    with open(os.path.join(output_dir, "salt.json"), "w") as f:
        json.dump({"salt": salt_b64, "salt_hex": salt.hex()}, f, indent=2)

    # 各キーペアを保存
    for idx, (true_key, false_key) in enumerate(key_pairs, 1):
        # TRUE鍵情報
        true_key_info = {
            "version": "1.0.0",
            "key": true_key.hex(),
            "key_b64": base64.b64encode(true_key).decode('utf-8'),
            "path": TRUE_PATH,
            "salt": salt_b64,
            "pair_id": idx
        }

        # FALSE鍵情報
        false_key_info = {
            "version": "1.0.0",
            "key": false_key.hex(),
            "key_b64": base64.b64encode(false_key).decode('utf-8'),
            "path": FALSE_PATH,
            "salt": salt_b64,
            "pair_id": idx
        }

        # ファイルに保存
        true_path = os.path.join(output_dir, f"true_key_{idx}.json")
        false_path = os.path.join(output_dir, f"false_key_{idx}.json")

        with open(true_path, "w") as f:
            json.dump(true_key_info, f, indent=2)

        with open(false_path, "w") as f:
            json.dump(false_key_info, f, indent=2)

        # 単体の鍵ファイル（hex形式）
        with open(os.path.join(output_dir, f"true_key_{idx}.hex"), "w") as f:
            f.write(true_key.hex())

        with open(os.path.join(output_dir, f"false_key_{idx}.hex"), "w") as f:
            f.write(false_key.hex())

        print(f"鍵ペア{idx}を保存しました:")
        print(f"  TRUE鍵: {true_path}")
        print(f"  FALSE鍵: {false_path}")

    # サマリーファイルを作成
    summary = {
        "salt": salt_b64,
        "salt_hex": salt.hex(),
        "pairs": [
            {
                "pair_id": idx,
                "true_key": pair[0].hex(),
                "false_key": pair[1].hex()
            }
            for idx, pair in enumerate(key_pairs, 1)
        ]
    }

    with open(os.path.join(output_dir, "key_pairs_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n鍵ペアの生成が完了しました。合計{len(key_pairs)}ペアが {output_dir} に保存されました。")


def main():
    parser = argparse.ArgumentParser(description="真/偽の鍵ペアを生成するツール")
    parser.add_argument("--pairs", "-n", type=int, default=3, help="生成する鍵ペアの数 (デフォルト: 3)")
    parser.add_argument("--output-dir", "-o", default="key_pairs", help="鍵ペアの出力ディレクトリ")

    args = parser.parse_args()

    # ソルト値を生成
    salt = os.urandom(16)

    # 鍵ペアを生成
    key_pairs = find_key_pairs(salt, args.pairs)

    # 結果を保存
    save_key_pairs(key_pairs, args.output_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())