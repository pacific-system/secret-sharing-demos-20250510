#!/usr/bin/env python3
"""
スタンドアロンの初期化済み暗号化ファイル生成スクリプト

全てのシェアIDをガベージシェアで埋めた暗号化ファイルを生成します。
このスクリプトはシャミアモジュールに依存せず、単独で実行できます。
"""

import os
import sys
import json
import base64
import secrets
import uuid
import time
import argparse
from gmpy2 import mpz

# 定数定義（constants.pyから複製）
PRIME = mpz(2**521 - 1)
ACTIVE_SHARES = 2000
GARBAGE_SHARES = 2000
PARTITION_SIZE = ACTIVE_SHARES + GARBAGE_SHARES
UNASSIGNED_SHARES = 4000
SHARE_ID_SPACE = PARTITION_SIZE * 2 + UNASSIGNED_SHARES
CHUNK_SIZE = 64
FIXED_VALUE_LENGTH = 256


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


def fixed_length_serialize(data):
    """
    完全固定長形式でシリアライズ

    Args:
        data: シリアライズするデータ

    Returns:
        固定長シリアライズされたデータ
    """
    # ヘッダー情報を確認
    if "header" not in data or "salt" not in data["header"]:
        raise ValueError("無効なデータ形式です。ヘッダーが正しく構成されていません。")

    salt = data["header"]["salt"]

    # 全てのシェア値を固定長形式でシリアライズ
    if "values" not in data or not isinstance(data["values"], list):
        raise ValueError("無効なデータ形式です。values配列が正しく構成されていません。")

    serialized_values = []
    for value in data["values"]:
        # 各シェア値を固定長に変換
        serialized_value = value.ljust(FIXED_VALUE_LENGTH, '0')
        serialized_values.append(serialized_value)

    # 固定長シリアライズ済みデータを構築
    serialized_data = {
        "header": {
            "salt": salt
        },
        "values": serialized_values
    }

    return serialized_data


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

    # パーティション設計パラメータを表示
    print(f"パーティション設計: ACTIVE_SHARES={ACTIVE_SHARES}, " +
          f"GARBAGE_SHARES={GARBAGE_SHARES}, PARTITION_SIZE={PARTITION_SIZE}, " +
          f"UNASSIGNED_SHARES={UNASSIGNED_SHARES}, SHARE_ID_SPACE={SHARE_ID_SPACE}")

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
    total_values = total_chunks * SHARE_ID_SPACE
    values = []

    print(f"初期化: {total_chunks}チャンク, {SHARE_ID_SPACE}シェアID, 合計{total_values}値を生成")

    # 進捗表示機能を初期化
    progress = process_with_progress(total_values, "ガベージシェア生成")

    # 全てのシェアに対して暗号論的に安全なランダム値を生成
    for i in range(total_values):
        # 大きな素数p未満のランダム値を生成（有限体GF(p)上で均一分布）
        random_value = str(secrets.randbelow(int(PRIME - 1)) + 1)
        values.append(random_value)

        # 進捗更新（100値ごと - 処理速度のバランスを取るため）
        if i % 100 == 0 or i == total_values - 1:
            progress(i)

    # 値を設定
    empty_file["values"] = values

    print("完全固定長シリアライズを適用中...")

    # 値を固定長に変換
    serialized_values = []

    # 進捗表示機能を初期化（シリアライズ用）
    serialize_progress = process_with_progress(len(values), "固定長シリアライズ")

    for i, value in enumerate(values):
        # 指定の固定長でパディング
        serialized_value = value.ljust(FIXED_VALUE_LENGTH, '0')
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