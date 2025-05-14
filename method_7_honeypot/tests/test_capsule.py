#!/usr/bin/env python3
"""
ハニーポットカプセルの単体テスト

このテストは、ハニーポットカプセル機能が正しく動作し、
データのカプセル化と抽出が適切に行われることを確認します。
"""

import os
import sys
import unittest
import tempfile
import shutil
import binascii
import random
import json
from datetime import datetime
from pathlib import Path

# テスト対象のモジュールをインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    generate_honey_token, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.honeypot_capsule import (
    HoneypotCapsule, HoneypotCapsuleFactory,
    create_honeypot_file, read_data_from_honeypot_file,
    extract_data_from_capsule, create_large_honeypot_file,
    read_data_from_large_honeypot_file
)


class TestHoneypotCapsule(unittest.TestCase):
    """ハニーポットカプセルのテストケース"""

    def setUp(self):
        """テスト前の準備"""
        # 一時ディレクトリを作成
        self.test_dir = tempfile.mkdtemp()

        # トラップドアパラメータの生成
        self.master_key = create_master_key()
        self.params = create_trapdoor_parameters(self.master_key)

        # テストデータの作成
        self.true_data = b"This is the true data that should be revealed with the correct key."
        self.false_data = b"This is the false data that will be shown with an incorrect key."

        # メタデータの作成
        self.metadata = {
            "description": "Test honeypot capsule",
            "timestamp": int(datetime.now().timestamp()),
            "version": "1.0",
            "test_id": random.randint(1000, 9999)
        }

        # カプセルファクトリの作成
        self.factory = HoneypotCapsuleFactory(self.params)

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # 一時ディレクトリを削除
        shutil.rmtree(self.test_dir)

    def test_capsule_creation(self):
        """カプセル作成のテスト"""
        print("\n=== カプセル作成のテスト ===")

        # 空のカプセルを作成
        capsule = HoneypotCapsule()

        # 基本パラメータの確認
        self.assertEqual(capsule.version, 1)
        self.assertEqual(capsule.magic, b"HPOT01")
        self.assertEqual(len(capsule.seed), 16)
        self.assertEqual(len(capsule.blocks), 0)
        self.assertEqual(capsule.metadata, {})

        # データブロックの追加
        capsule.add_true_data(self.true_data)
        capsule.add_false_data(self.false_data)
        capsule.set_metadata(self.metadata)

        # ブロック数の確認
        # 注: ダミーブロックが確率的に追加されるため、少なくとも2つ（true, false）は存在する
        self.assertGreaterEqual(len(capsule.blocks), 2)

        # シリアライズ
        serialized = capsule.serialize()
        print(f"シリアライズされたカプセルのサイズ: {len(serialized)} バイト")

        # ブロック取得関数のテスト
        true_block = capsule.get_block_by_type(1)  # DATA_TYPE_TRUE
        false_block = capsule.get_block_by_type(2)  # DATA_TYPE_FALSE

        self.assertIsNotNone(true_block)
        self.assertIsNotNone(false_block)

        print("カプセル作成とブロック追加: 成功")

    def test_capsule_serialization(self):
        """カプセルのシリアライズとデシリアライズのテスト"""
        print("\n=== カプセルのシリアライズとデシリアライズのテスト ===")

        # カプセルの作成
        capsule = self.factory.create_capsule(self.true_data, self.false_data, self.metadata)

        # シリアライズ
        serialized = capsule.serialize()
        print(f"シリアライズされたカプセルのサイズ: {len(serialized)} バイト")

        # デシリアライズ
        restored_capsule = HoneypotCapsule.deserialize(serialized)

        # メタデータが正しく復元されたか確認
        self.assertEqual(restored_capsule.metadata, self.metadata)
        print(f"復元されたメタデータ: {json.dumps(restored_capsule.metadata, indent=2)}")

        # ブロック数が正しいか確認
        true_block = restored_capsule.get_block_by_type(1)  # DATA_TYPE_TRUE
        false_block = restored_capsule.get_block_by_type(2)  # DATA_TYPE_FALSE

        self.assertIsNotNone(true_block)
        self.assertIsNotNone(false_block)

        print("カプセルのシリアライズとデシリアライズ: 成功")

    def test_data_extraction(self):
        """カプセルからのデータ抽出テスト"""
        print("\n=== カプセルからのデータ抽出テスト ===")

        # カプセルの作成
        capsule = self.factory.create_capsule(self.true_data, self.false_data, self.metadata)

        # シリアライズ
        serialized = capsule.serialize()

        # デシリアライズ
        restored_capsule = HoneypotCapsule.deserialize(serialized)

        # データの抽出
        extracted_true_data = extract_data_from_capsule(restored_capsule, KEY_TYPE_TRUE)
        extracted_false_data = extract_data_from_capsule(restored_capsule, KEY_TYPE_FALSE)

        # 抽出データの検証
        self.assertEqual(extracted_true_data, self.true_data)
        self.assertEqual(extracted_false_data, self.false_data)

        print(f"正規データ抽出: {extracted_true_data.decode('utf-8')}")
        print(f"非正規データ抽出: {extracted_false_data.decode('utf-8')}")
        print("データ抽出テスト: 成功")

    def test_honeypot_file_functions(self):
        """ハニーポットファイル作成・読み取り関数のテスト"""
        print("\n=== ハニーポットファイル関数のテスト ===")

        # ハニーポットファイルの作成
        file_data = create_honeypot_file(
            self.true_data,
            self.false_data,
            self.params,
            self.metadata
        )

        print(f"ハニーポットファイルのサイズ: {len(file_data)} バイト")

        # ファイルからのデータ読み込み
        true_data, metadata = read_data_from_honeypot_file(file_data, KEY_TYPE_TRUE)
        false_data, _ = read_data_from_honeypot_file(file_data, KEY_TYPE_FALSE)

        # データの検証
        self.assertEqual(true_data, self.true_data)
        self.assertEqual(false_data, self.false_data)
        self.assertEqual(metadata, self.metadata)

        print("ハニーポットファイル作成・読み取り: 成功")

    def test_large_data_handling(self):
        """大きなデータの処理テスト"""
        print("\n=== 大きなデータの処理テスト ===")

        # テスト用に小さいサイズのデータを使用
        large_true_data = os.urandom(64 * 1024)  # 64KB
        large_false_data = os.urandom(64 * 1024)  # 64KB

        # 大きなデータ用のハニーポットファイル作成
        file_data = create_honeypot_file(
            large_true_data,
            large_false_data,
            self.params,
            self.metadata
        )

        print(f"ハニーポットファイルのサイズ: {len(file_data) // 1024} KB")

        # ファイルからのデータ読み込み
        true_data, metadata = read_data_from_honeypot_file(file_data, KEY_TYPE_TRUE)
        false_data, _ = read_data_from_honeypot_file(file_data, KEY_TYPE_FALSE)

        # データの検証
        self.assertEqual(len(true_data), len(large_true_data))
        self.assertEqual(len(false_data), len(large_false_data))
        self.assertEqual(true_data, large_true_data)
        self.assertEqual(false_data, large_false_data)

        print(f"大きなデータのサイズ比較 - 元:{len(large_true_data) // 1024}KB, 抽出:{len(true_data) // 1024}KB")
        print("大きなデータの処理: 成功")

    def test_error_handling(self):
        """エラー処理のテスト"""
        print("\n=== エラー処理のテスト ===")

        # カプセルの作成
        capsule = self.factory.create_capsule(self.true_data, self.false_data, self.metadata)

        # シリアライズ
        serialized = capsule.serialize()

        # データ破損のシミュレーション
        corrupted_data = bytearray(serialized)
        # ヘッダーを破損させる
        corrupted_data[10] = (corrupted_data[10] + 1) % 256

        # 破損データの検証
        with self.assertRaises(ValueError):
            HoneypotCapsule.deserialize(bytes(corrupted_data))

        # 空のカプセルを作成（何もデータを追加しない）
        empty_capsule = HoneypotCapsule()
        # カプセルをシリアライズ
        empty_serialized = empty_capsule.serialize()
        # デシリアライズ
        restored_empty_capsule = HoneypotCapsule.deserialize(empty_serialized)

        # 存在しないブロックタイプのデータ抽出（Noneが返るはず）
        missing_data_true = extract_data_from_capsule(restored_empty_capsule, KEY_TYPE_TRUE)
        self.assertIsNone(missing_data_true)

        missing_data_false = extract_data_from_capsule(restored_empty_capsule, KEY_TYPE_FALSE)
        self.assertIsNone(missing_data_false)

        # 不正なファイルデータでの読み取り
        invalid_file_data = b"This is not a valid honeypot file data"
        with self.assertRaises(ValueError):
            read_data_from_honeypot_file(invalid_file_data, KEY_TYPE_TRUE)

        print("エラー処理: 成功")


# テスト出力ディレクトリの作成
os.makedirs('test_output', exist_ok=True)


def run_tests():
    """テスト実行関数"""
    # 現在の時刻を取得
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ログファイルを設定
    log_file = os.path.join('test_output', f'capsule_test_{timestamp}.log')

    # 標準出力を記録
    with open(log_file, 'w') as f:
        # 元の標準出力を保存
        original_stdout = sys.stdout

        try:
            # 標準出力をファイルにリダイレクト
            sys.stdout = f

            print(f"=== ハニーポットカプセルのテスト ===")
            print(f"実行日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Python バージョン: {sys.version}")
            print(f"テスト開始...\n")

            # テストの実行
            unittest.main(argv=['first-arg-is-ignored'], exit=False)

            print(f"\nテスト完了。")

        finally:
            # 標準出力を元に戻す
            sys.stdout = original_stdout

    print(f"テスト結果がログファイルに保存されました: {log_file}")
    return log_file


if __name__ == '__main__':
    log_file = run_tests()

    # テスト結果の概要を表示
    with open(log_file, 'r') as f:
        for line in f:
            if 'Ran' in line or 'OK' in line or 'FAILED' in line:
                print(line.strip())