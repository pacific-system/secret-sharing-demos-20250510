#!/usr/bin/env python3
"""
ハニーポットカプセル検査スクリプト

このスクリプトは実装されたハニーポットカプセル機能を検査し、
実際のファイルを使って暗号化・復号処理が正しく機能するか検証します。
"""

import os
import sys
import hashlib
import time
from datetime import datetime
from pathlib import Path

# 親ディレクトリをPythonパスに追加
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# method_7_honeypotモジュールからのインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.honeypot_capsule import (
    HoneypotCapsuleFactory, create_honeypot_file,
    read_data_from_honeypot_file, extract_data_from_capsule,
    HoneypotCapsule, create_large_honeypot_file
)

# ユーティリティ関数
def print_bytes_info(label, data):
    """バイトデータの情報を表示"""
    if data is None:
        print(f"{label}: None")
        return

    print(f"{label}:")
    print(f"  長さ: {len(data)} バイト")
    hex_data = data.hex()
    hex_preview = hex_data[:64] + "..." if len(hex_data) > 64 else hex_data
    print(f"  内容: {hex_preview}")

    # ASCII表示（表示可能な文字のみ）
    try:
        ascii_data = data.decode('utf-8', errors='replace')
        ascii_preview = ascii_data[:32] + "..." if len(ascii_data) > 32 else ascii_data
        print(f"  ASCII: {ascii_preview}")
    except:
        pass
    print()

def timestamp():
    """タイムスタンプを生成"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def test_with_true_false_text():
    """真偽テキストファイルを使ったテスト"""
    print("\n=== 真偽テキストファイルを使ったテスト ===\n")

    # ファイルパス
    true_file_path = "test_output/honeypot_inspection/test_true.text"
    false_file_path = "test_output/honeypot_inspection/test_false.text"
    output_path = f"test_output/honeypot_inspection/test_capsule_{timestamp()}.hpot"

    # ファイル読み込み
    try:
        with open(true_file_path, 'rb') as f:
            true_data = f.read()
        with open(false_file_path, 'rb') as f:
            false_data = f.read()

        print(f"正規ファイル '{true_file_path}' を読み込みました（{len(true_data)} バイト）")
        print(f"非正規ファイル '{false_file_path}' を読み込みました（{len(false_data)} バイト）")
    except Exception as e:
        print(f"ファイル読み込みエラー: {e}")
        return

    # マスター鍵とトラップドアパラメータの生成
    master_key = create_master_key()
    trapdoor_params = create_trapdoor_parameters(master_key)

    # 鍵ペアの導出
    keys, salt = derive_keys_from_trapdoor(trapdoor_params)
    true_key = keys[KEY_TYPE_TRUE]
    false_key = keys[KEY_TYPE_FALSE]

    print("\n--- 鍵情報 ---\n")
    print_bytes_info("マスター鍵", master_key)
    print_bytes_info("正規鍵", true_key)
    print_bytes_info("非正規鍵", false_key)

    # ハニーポットファイル作成
    try:
        # ファクトリーを直接使用
        factory = HoneypotCapsuleFactory(trapdoor_params)
        capsule = factory.create_capsule(true_data, false_data, {"test": "true_false_test"})

        # シリアライズしてファイルに保存
        serialized = capsule.serialize()
        with open(output_path, 'wb') as f:
            f.write(serialized)

        print(f"\nハニーポットカプセルをファイルに保存しました: {output_path} ({len(serialized)} バイト)")
    except Exception as e:
        print(f"カプセル作成エラー: {e}")
        return

    # 復号テスト
    try:
        # 正規鍵でのテスト
        restored_true_data, metadata = read_data_from_honeypot_file(serialized, KEY_TYPE_TRUE)
        print("\n--- 正規鍵での復号結果 ---\n")
        print(f"メタデータ: {metadata}")
        print_bytes_info("復号されたデータ", restored_true_data)

        if restored_true_data == true_data:
            print("正規データの復号に成功しました（データが一致）")
        else:
            print("正規データの復号に失敗しました（データが一致しません）")

        # 非正規鍵でのテスト
        restored_false_data, _ = read_data_from_honeypot_file(serialized, KEY_TYPE_FALSE)
        print("\n--- 非正規鍵での復号結果 ---\n")
        print_bytes_info("復号されたデータ", restored_false_data)

        if restored_false_data == false_data:
            print("非正規データの復号に成功しました（データが一致）")
        else:
            print("非正規データの復号に失敗しました（データが一致しません）")
    except Exception as e:
        print(f"復号エラー: {e}")
        return

def test_bind_token_to_data():
    """トークン結合機能のテスト"""
    print("\n=== トークン結合機能のテスト ===\n")

    # ダミーデータとトークンの作成
    data = b"This is sample data for testing token binding functionality."
    # 正確に32バイトのトークンを作成
    token = os.urandom(32)

    # マスター鍵とトラップドアパラメータの生成
    master_key = create_master_key()
    trapdoor_params = create_trapdoor_parameters(master_key)

    # ファクトリークラスのインスタンス化
    factory = HoneypotCapsuleFactory(trapdoor_params)

    # トークンとデータの結合
    bound_data = factory._bind_token_to_data(data, token)
    print_bytes_info("元のデータ", data)
    print_bytes_info("トークン", token)
    print_bytes_info("結合されたデータ", bound_data)

    # カプセルの作成と抽出テスト
    capsule = HoneypotCapsule()
    capsule.add_true_data(bound_data)

    # カプセルからのデータ抽出
    extracted_data = extract_data_from_capsule(capsule, KEY_TYPE_TRUE)
    print_bytes_info("抽出されたデータ", extracted_data)

    # 結果検証
    if extracted_data == data:
        print("結合・抽出テスト成功: データが正しく復元されました")
    else:
        print("結合・抽出テスト失敗: データが正しく復元されませんでした")

        # 詳細な比較
        if len(extracted_data) != len(data):
            print(f"データ長が異なります: 元={len(data)}バイト, 抽出={len(extracted_data)}バイト")
        else:
            # バイト単位での比較
            diff_count = sum(1 for a, b in zip(data, extracted_data) if a != b)
            print(f"異なるバイト数: {diff_count}/{len(data)}")

            # 最初の不一致を表示
            for i, (a, b) in enumerate(zip(data, extracted_data)):
                if a != b:
                    print(f"最初の不一致: インデックス {i}, 元={a:02x}, 抽出={b:02x}")
                    break

def test_large_file_handling():
    """大きなファイル処理のテスト"""
    print("\n=== 大きなファイル処理のテスト ===\n")

    # テスト用の大きなデータを生成
    true_data = os.urandom(5 * 1024 * 1024)  # 5MB
    false_data = os.urandom(5 * 1024 * 1024)  # 5MB

    print(f"テスト用の大きなデータを生成しました (各5MB)")

    # マスター鍵とトラップドアパラメータの生成
    master_key = create_master_key()
    trapdoor_params = create_trapdoor_parameters(master_key)

    # 小さなチャンクサイズを指定して分割処理をテスト
    chunk_size = 1 * 1024 * 1024  # 1MB
    start_time = time.time()
    large_file_data = create_large_honeypot_file(
        true_data, false_data, trapdoor_params,
        {"test": "large_file_test"}, chunk_size
    )
    elapsed = time.time() - start_time

    print(f"大きなファイルの処理に {elapsed:.2f} 秒かかりました")
    print(f"生成されたファイルサイズ: {len(large_file_data) / (1024 * 1024):.2f} MB")

    # データの読み込みをテスト
    start_time = time.time()
    read_true_data, metadata = read_data_from_honeypot_file(large_file_data, KEY_TYPE_TRUE)
    elapsed = time.time() - start_time

    print(f"正規データの読み込みに {elapsed:.2f} 秒かかりました")
    print(f"メタデータ: {metadata}")

    if len(read_true_data) == len(true_data) and read_true_data == true_data:
        print("正規データの読み込みテスト成功: データが正しく復元されました")
    else:
        print("正規データの読み込みテスト失敗: データが正しく復元されませんでした")

    # 非正規データの読み込みをテスト
    start_time = time.time()
    read_false_data, _ = read_data_from_honeypot_file(large_file_data, KEY_TYPE_FALSE)
    elapsed = time.time() - start_time

    print(f"非正規データの読み込みに {elapsed:.2f} 秒かかりました")

    if len(read_false_data) == len(false_data) and read_false_data == false_data:
        print("非正規データの読み込みテスト成功: データが正しく復元されました")
    else:
        print("非正規データの読み込みテスト失敗: データが正しく復元されませんでした")

def main():
    """メイン関数"""
    print("ハニーポットカプセル検査を開始します")
    print(f"実行時刻: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 各テストを実行
    test_with_true_false_text()
    test_bind_token_to_data()
    test_large_file_handling()

    print("\nハニーポットカプセル検査が完了しました")

if __name__ == "__main__":
    main()