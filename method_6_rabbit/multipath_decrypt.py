#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
多重経路復号プログラム

同一の暗号文を複数のパスワードで復号し、それぞれの結果を出力します。
このプログラムはRabbit暗号の多重パス特性を検証するためのものです。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import time
from typing import Tuple, Dict, Any, List, Optional

# インポートエラーを回避するための処理
if __name__ == "__main__":
    # モジュールとして実行された場合の処理
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        DECRYPT_CHUNK_SIZE,
        DECRYPTED_FILE_PATH,
        VERSION
    )
    from method_6_rabbit.stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
else:
    # パッケージの一部として実行された場合の処理
    from .config import (
        DECRYPT_CHUNK_SIZE,
        DECRYPTED_FILE_PATH,
        VERSION
    )
    from .stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE


def read_encrypted_file(file_path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    暗号化されたファイルを読み込む

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (encrypted_data, metadata): 暗号化データとメタデータ
    """
    try:
        with open(file_path, 'rb') as file:
            # マジックヘッダーを確認
            magic = file.read(len(b'RABBIT_ENCRYPTED_V1\n'))
            if magic != b'RABBIT_ENCRYPTED_V1\n':
                raise ValueError("不正なファイル形式です。Rabbit暗号化ファイルではありません。")

            # メタデータサイズを読み取り
            metadata_size_bytes = file.read(4)
            metadata_size = int.from_bytes(metadata_size_bytes, byteorder='big')

            # メタデータを読み取り
            metadata_bytes = file.read(metadata_size)
            metadata = json.loads(metadata_bytes.decode('utf-8'))

            # バージョン確認
            if metadata.get('version') != VERSION:
                print(f"警告: ファイルバージョン ({metadata.get('version')}) と現在のバージョン ({VERSION}) が一致しません")

            # 暗号化データを読み取り
            encrypted_data = file.read()

            return encrypted_data, metadata

    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません")
        sys.exit(1)
    except Exception as e:
        print(f"エラー: ファイルの読み込みに失敗しました: {e}")
        sys.exit(1)


def decrypt_data(encrypted_data: bytes, password: str, metadata: Dict[str, Any]) -> Tuple[bytes, str]:
    """
    暗号化データをパスワードを使用して復号

    Args:
        encrypted_data: 暗号化データ
        password: 復号用パスワード
        metadata: メタデータ

    Returns:
        (復号されたデータ, パス種別("true"/"false"/"unknown"))
    """
    try:
        # メタデータからソルトを取得
        salt = base64.b64decode(metadata['salt'])

        # データ長を取得
        data_length = metadata['data_length']

        # 暗号化データが短すぎないか確認
        if len(encrypted_data) < data_length:
            raise ValueError(f"暗号化データが短すぎます（{len(encrypted_data)} < {data_length}）")

        # StreamSelectorを初期化してストリームを取得
        selector = StreamSelector(salt)
        stream = selector.get_stream_for_decryption(password, data_length)

        # 鍵種別を判定（"true"か"false"）
        key_type = selector.determine_key_type_for_decryption(password)

        # 鍵種別に応じて適切な部分を選択
        if key_type == KEY_TYPE_TRUE:
            # 正規パスワードなら前半部分を使用
            encrypted_part = encrypted_data[:data_length]
        else:
            # 非正規パスワードなら後半部分を使用
            if len(encrypted_data) >= 2 * data_length:
                encrypted_part = encrypted_data[data_length:2*data_length]
            else:
                # データが足りない場合は前半部分を使用（エラーを防ぐため）
                encrypted_part = encrypted_data[:data_length]

        # XORによる復号
        decrypted = bytearray(data_length)
        for i in range(data_length):
            # 単純なXOR復号
            if i < len(encrypted_part):
                decrypted[i] = encrypted_part[i] ^ stream[i]

        # 復号結果の検証
        path_type = "unknown"
        if len(decrypted) >= 16:
            data_check = hashlib.sha256(decrypted[:16]).hexdigest()[:8]
            true_check = metadata.get('true_path_check')
            false_check = metadata.get('false_path_check')

            if data_check == true_check:
                path_type = "true"
            elif data_check == false_check:
                path_type = "false"

        return bytes(decrypted), path_type

    except Exception as e:
        print(f"エラー: データの復号に失敗しました: {e}")
        if os.environ.get('DEBUG') == '1':
            import traceback
            traceback.print_exc()
        sys.exit(1)


def save_decrypted_file(decrypted_data: bytes, output_path: str) -> None:
    """
    復号されたデータをファイルに保存

    Args:
        decrypted_data: 復号されたデータ
        output_path: 出力ファイルパス
    """
    try:
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        print(f"復号されたデータを '{output_path}' に保存しました")

    except Exception as e:
        print(f"エラー: 復号ファイルの保存に失敗しました: {e}")
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数を解析

    Returns:
        解析された引数オブジェクト
    """
    parser = argparse.ArgumentParser(
        description="多重経路復号ツール - 複数のパスワードで復号できる暗号文を検証",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        help="暗号化ファイルのパス"
    )

    parser.add_argument(
        "-o", "--output-prefix",
        default="decrypted_path",
        help="復号ファイルの出力先のプレフィックス"
    )

    parser.add_argument(
        "-p", "--passwords",
        required=True,
        nargs='+',
        help="復号に使用する複数のパスワード（スペース区切り）"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細なログ出力"
    )

    return parser.parse_args()


def main():
    """メイン関数"""
    # 引数解析
    args = parse_arguments()

    print(f"暗号化ファイル '{args.input}' を読み込んでいます...")
    encrypted_data, metadata = read_encrypted_file(args.input)

    if args.verbose:
        print(f"メタデータ: {json.dumps(metadata, indent=2)}")

    print(f"{len(args.passwords)}個のパスワードでの復号を開始します...")

    # 結果格納用
    results = []

    # 各パスワードで復号を試みる
    for i, password in enumerate(args.passwords):
        print(f"\nパスワード {i+1}/{len(args.passwords)} を使用して復号しています...")

        start_time = time.time()
        decrypted_data, path_type = decrypt_data(encrypted_data, password, metadata)
        end_time = time.time()

        # パス種別に基づいてラベルを決定
        if path_type == "true":
            path_label = "正規"
            output_file = f"{args.output_prefix}_true_{i+1}.text"
        elif path_type == "false":
            path_label = "非正規"
            output_file = f"{args.output_prefix}_false_{i+1}.text"
        else:
            path_label = "不明"
            output_file = f"{args.output_prefix}_unknown_{i+1}.text"

        # 復号結果を保存
        save_decrypted_file(decrypted_data, output_file)
        print(f"パスワード {i+1}: {path_label}パスへの復号結果（{output_file}）")

        # 結果を追加
        results.append({
            "password_index": i+1,
            "password": password[:3] + "..." + password[-3:],  # セキュリティのため一部のみ表示
            "path_type": path_type,
            "decrypt_time": end_time - start_time,
            "output_file": output_file
        })

    # 結果サマリーを表示
    print("\n=== 復号結果サマリー ===")
    print(f"暗号ファイル: {args.input}")
    print(f"試行パスワード数: {len(args.passwords)}")

    true_count = sum(1 for r in results if r["path_type"] == "true")
    false_count = sum(1 for r in results if r["path_type"] == "false")
    unknown_count = sum(1 for r in results if r["path_type"] == "unknown")

    print(f"正規データへの復号: {true_count}件")
    print(f"非正規データへの復号: {false_count}件")
    print(f"不明な復号結果: {unknown_count}件")

    # 詳細表を表示
    if args.verbose:
        print("\n詳細結果:")
        print("-" * 80)
        print(f"{'#':^4} | {'パスワード':^20} | {'種別':^10} | {'処理時間':^10} | {'出力ファイル'}")
        print("-" * 80)

        for r in results:
            path_label = "正規" if r["path_type"] == "true" else "非正規" if r["path_type"] == "false" else "不明"
            print(f"{r['password_index']:^4} | {r['password']:^20} | {path_label:^10} | {r['decrypt_time']:.4f}秒 | {r['output_file']}")

    print("\n多重経路復号が完了しました！")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n処理が中断されました")
        sys.exit(1)
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        if os.environ.get('DEBUG') == '1':
            import traceback
            traceback.print_exc()
        sys.exit(1)
