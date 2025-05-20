#!/usr/bin/env python3
"""
初期化済み暗号化ファイルを生成するスクリプト

全てのシェアIDをガベージシェアで埋めた暗号化ファイルを生成します。
"""

import os
import sys
import json
import base64
import secrets
import uuid
import time
import argparse

# 直接必要なモジュールのみをインポート
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from method_13_shamir_multi_plaintext_system.shamir.constants import ShamirConstants
try:
    from method_13_shamir_multi_plaintext_system.shamir.formats.v3 import FileFormatV3
    V3_FORMAT_AVAILABLE = True
except ImportError:
    V3_FORMAT_AVAILABLE = False
    print("警告: V3形式モジュールがインポートできません。代替手段を使用します。")


def process_with_progress(total_items, operation_name="処理"):
    """
    進捗表示機能付きの処理ラッパー

    Args:
        total_items: 処理する総アイテム数
        operation_name: 操作の名前（表示用）

    Returns:
        進捗表示用の関数
    """
    start_time = time.time()

    def update_progress(current_item):
        """進捗を表示する関数"""
        progress = (current_item + 1) / total_items * 100
        elapsed = time.time() - start_time

        # 残り時間の推定（最低1処理完了後）
        if current_item > 0:
            eta = elapsed / (current_item + 1) * (total_items - current_item - 1)
            eta_str = f"残り時間: {eta:.1f}秒"
        else:
            eta_str = "残り時間: 計算中..."

        # プログレスバー（幅30文字）
        bar_width = 30
        bar_filled = int(bar_width * progress / 100)
        bar = '█' * bar_filled + '░' * (bar_width - bar_filled)

        # 進捗情報をコンソールに表示（同じ行を更新）
        sys.stdout.write(f"\r{operation_name}: {progress:.1f}% |{bar}| {current_item+1}/{total_items} {eta_str}")
        sys.stdout.flush()

        # 最後のアイテムの場合は改行
        if current_item == total_items - 1:
            total_time = time.time() - start_time
            sys.stdout.write(f"\n{operation_name}が完了しました。合計時間: {total_time:.1f}秒\n")
            sys.stdout.flush()

    return update_progress


def generate_empty_encrypted_file(output_dir='./output', chunks=10):
    """
    全てのシェアIDをガベージシェアで埋めた初期化済み暗号化ファイルを生成

    Args:
        output_dir: 出力ディレクトリ
        chunks: 初期化するチャンク数

    Returns:
        生成したファイルのパス
    """
    # 出力ディレクトリの確認・作成
    os.makedirs(output_dir, exist_ok=True)

    # 常に新たなUUIDを生成（既存ファイルは上書きしない）
    file_uuid = str(uuid.uuid4())
    output_path = os.path.join(output_dir, f"encrypted_{file_uuid}.json")

    # ソルト値を生成
    salt = secrets.token_bytes(16)

    # パーティション設計パラメータを確認
    active_shares = ShamirConstants.ACTIVE_SHARES
    garbage_shares = ShamirConstants.GARBAGE_SHARES
    partition_size = ShamirConstants.PARTITION_SIZE
    unassigned_shares = ShamirConstants.UNASSIGNED_SHARES
    share_id_space = ShamirConstants.SHARE_ID_SPACE

    print(f"パーティション設計: ACTIVE_SHARES={active_shares}, " +
          f"GARBAGE_SHARES={garbage_shares}, PARTITION_SIZE={partition_size}, " +
          f"UNASSIGNED_SHARES={unassigned_shares}, SHARE_ID_SPACE={share_id_space}")

    # チャンク数の指定（引数で指定、デフォルトは10）
    total_chunks = chunks  # 初期チャンク数

    # 空の暗号化ファイルデータの作成
    empty_file = {
        "header": {
            "salt": base64.urlsafe_b64encode(salt).decode('ascii')
        },
        "values": []
    }

    # 全シェアを格納する一次元配列を初期化
    total_values = total_chunks * share_id_space
    values = []

    print(f"初期化: {total_chunks}チャンク, {share_id_space}シェアID, 合計{total_values}値を生成")

    # 進捗表示機能を初期化
    progress = process_with_progress(total_values, "ガベージシェア生成")

    # 全てのシェアに対して暗号論的に安全なランダム値を生成
    for i in range(total_values):
        # 大きな素数p未満のランダム値を生成（有限体GF(p)上で均一分布）
        random_value = str(secrets.randbelow(int(ShamirConstants.PRIME - 1)) + 1)
        values.append(random_value)

        # 進捗更新（100値ごと - 処理速度のバランスを取るため）
        if i % 100 == 0 or i == total_values - 1:
            progress(i)

    # 値を設定
    empty_file["values"] = values

    print("完全固定長シリアライズを適用中...")

    # 完全固定長シリアライズを適用
    if V3_FORMAT_AVAILABLE:
        # V3形式のシリアライズ関数を使用
        serialized_data = FileFormatV3.fixed_length_serialize(empty_file)
        FileFormatV3.write_file(serialized_data, output_path)
    else:
        # 代替実装: 値を固定長に変換
        serialized_values = []

        # 進捗表示機能を初期化（シリアライズ用）
        serialize_progress = process_with_progress(len(values), "固定長シリアライズ")

        for i, value in enumerate(values):
            # 指定の固定長でパディング
            serialized_value = value.ljust(ShamirConstants.FIXED_VALUE_LENGTH, '0')
            serialized_values.append(serialized_value)

            # 進捗更新（100値ごと）
            if i % 100 == 0 or i == len(values) - 1:
                serialize_progress(i)

        empty_file["values"] = serialized_values

        # ファイルに書き込み
        print("ファイルを書き込み中...")
        with open(output_path, 'w') as f:
            json.dump(empty_file, f)

    print(f"暗号化ファイルを生成しました: {output_path}")

    return output_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='全てのシェアIDをガベージシェアで埋めた初期化済み暗号化ファイルを生成'
    )

    parser.add_argument('--output-dir', '-o', default='./output',
                       help='出力先ディレクトリ（デフォルト: ./output）')
    parser.add_argument('--chunks', '-c', type=int, default=10,
                       help='初期化するチャンク数（デフォルト: 10）')

    args = parser.parse_args()

    try:
        output_path = generate_empty_encrypted_file(
            output_dir=args.output_dir,
            chunks=args.chunks
        )
        print(f"初期化済み暗号化ファイルを生成しました: {output_path}")
    except Exception as e:
        print(f"エラー: {e}")
        sys.exit(1)