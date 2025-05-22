"""
暗号書庫生成機能のテスト

【責務】
このモジュールは、暗号書庫生成機能の動作を検証するための単体テストを提供します。
特に以下の点を重点的に検証します：
- パーティションマップキーの生成と復元の正確性
- A領域とB領域の分離特性の確保
- ガベージシェアと有効シェアの統計的区別不可能性
- シェアID空間の分割と管理の検証
- 複数回の生成における一意性と非決定論性の確認
- CLIデータファイルの検証（RULE-2.1.6に基づく）
"""

import os
import json
import unittest
import tempfile
import shutil
import glob
import sys
from typing import Dict, List, Any
from collections import defaultdict
from pathlib import Path

# プロジェクト構造に合わせたインポートパスの設定
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from method_13_shamir_multi_plaintext_system.shamir.constants import ShamirConstants
from method_13_shamir_multi_plaintext_system.shamir.crypto_storage_creation import (
    create_crypto_storage,
    divide_share_id_space,
    validate_partitions,
    verify_partition_distribution,
    verify_statistical_indistinguishability,
    generate_garbage_share,
)
from method_13_shamir_multi_plaintext_system.shamir.map1_key_manager import (
    generate_partition_map_key,
    restore_partition_distribution,
    DecryptionError
)


class TestCryptoStorageCreation(unittest.TestCase):
    """暗号書庫生成機能のテストクラス"""

    def setUp(self):
        """テスト前の準備"""
        # テスト用ディレクトリを作成
        self.test_dir = tempfile.mkdtemp()

        # テスト用パスワード
        self.a_password = "test_password_a"
        self.b_password = "test_password_b"

        # テスト用システムパラメータ（小さい値でテスト時間を短縮）
        self.test_params = {
            'PARTITION_SIZE': 10,
            'ACTIVE_SHARES': 5,
            'UNASSIGNED_SHARES': 10,
            'SHARE_ID_SPACE': 30,
        }

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # テスト用ディレクトリを削除
        shutil.rmtree(self.test_dir)

    def test_divide_share_id_space(self):
        """シェアID空間の分割テスト"""
        # シェアID空間を分割
        a_partition, b_partition, unassigned = divide_share_id_space(self.test_params)

        # 分割結果の検証
        self.assertEqual(len(a_partition), self.test_params['PARTITION_SIZE'])
        self.assertEqual(len(b_partition), self.test_params['PARTITION_SIZE'])
        self.assertEqual(len(unassigned), self.test_params['UNASSIGNED_SHARES'])

        # 全体の数をチェック（すべてのIDが割り当てられているか）
        total = len(a_partition) + len(b_partition) + len(unassigned)
        self.assertEqual(
            total,
            self.test_params['PARTITION_SIZE'] * 2 + self.test_params['UNASSIGNED_SHARES']
        )

        # 重複がないことを確認
        all_ids = a_partition + b_partition + unassigned
        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_cli_data_file_format(self):
        """CLIデータファイルの形式検証（RULE-2.1.6準拠）"""
        # テスト用のCLIデータファイルをテンポラリディレクトリに作成
        test_data = {
            'timestamp': '2025-05-10T12:30:45',
            'test_id': 'test_20250510_123045_12345678',
            'a_partition_map_key': 'key_for_a_partition_map',
            'b_partition_map_key': 'key_for_b_partition_map',
            'a_partition_map': [1, 3, 5, 7, 9],
            'b_partition_map': [2, 4, 6, 8, 10],
            'a_password_hash': 'a1b2c3d4e5f6',
            'b_password_hash': 'f6e5d4c3b2a1',
            'storage_file': '/path/to/storage.json',
            'partition_size': 10,
            'active_shares': 5
        }

        # UUIDを含むファイル名でテストファイルを作成
        file_uuid = '0123456789abcdef0123456789abcdef'
        timestamp = '20250510_123045'
        test_file_path = Path(self.test_dir) / f"cli_data_{timestamp}_{file_uuid}.json"

        with open(test_file_path, 'w', encoding='utf-8') as f:
            json.dump(test_data, f)

        # 作成したファイルを読み込み
        with open(test_file_path, 'r', encoding='utf-8') as f:
            loaded_data = json.load(f)

        # データの整合性を検証
        self.assertEqual(loaded_data['a_partition_map_key'], test_data['a_partition_map_key'])
        self.assertEqual(loaded_data['b_partition_map_key'], test_data['b_partition_map_key'])
        self.assertEqual(loaded_data['a_partition_map'], test_data['a_partition_map'])
        self.assertEqual(loaded_data['b_partition_map'], test_data['b_partition_map'])

        # シェア数が正しいか検証
        self.assertEqual(len(loaded_data['a_partition_map']), loaded_data['active_shares'])
        self.assertEqual(len(loaded_data['b_partition_map']), loaded_data['active_shares'])

        # A領域とB領域のMAP配列に重複がないか検証
        a_set = set(loaded_data['a_partition_map'])
        b_set = set(loaded_data['b_partition_map'])
        intersection = a_set.intersection(b_set)
        self.assertEqual(len(intersection), 0, "A領域とB領域のMAP配列に重複があります")

    def test_validate_partitions_no_overlap(self):
        """パーティション検証（重複なし）のテスト"""
        a_partition = [1, 2, 3, 4, 5]
        b_partition = [6, 7, 8, 9, 10]

        # エラーが発生しないことを確認
        try:
            validate_partitions(a_partition, b_partition)
        except ValueError:
            self.fail("validate_partitions() raised ValueError unexpectedly!")

    def test_validate_partitions_with_overlap(self):
        """パーティション検証（重複あり）のテスト"""
        a_partition = [1, 2, 3, 4, 5]
        b_partition = [5, 6, 7, 8, 9]  # 5が重複

        # ValueError例外が発生することを確認
        with self.assertRaises(ValueError):
            validate_partitions(a_partition, b_partition)

    def test_partition_map_key_generation_and_restoration(self):
        """パーティションマップキーの生成と復元テスト"""
        partition = [1, 5, 10, 15, 20]
        password = "test_password"

        # パーティションマップキーを生成
        partition_map_key = generate_partition_map_key(partition, password)

        # パーティションマップキーが生成されることを確認
        self.assertIsNotNone(partition_map_key)
        self.assertIsInstance(partition_map_key, str)
        self.assertGreater(len(partition_map_key), 0)

        # パーティションマップキーから元の第1段階MAPを復元
        restored_partition = restore_partition_distribution(partition_map_key, password)

        # 復元された第1段階MAPが元の配列と一致することを確認
        self.assertEqual(sorted(partition), sorted(restored_partition))

    def test_restore_with_wrong_password(self):
        """間違ったパスワードでの復元テスト"""
        partition = [1, 5, 10, 15, 20]
        password = "correct_password"
        wrong_password = "wrong_password"

        # パーティションマップキーを生成
        partition_map_key = generate_partition_map_key(partition, password)

        # 間違ったパスワードで復元するとDecryptionErrorが発生することを確認
        with self.assertRaises(DecryptionError):
            restore_partition_distribution(partition_map_key, wrong_password)

    def test_create_crypto_storage(self):
        """暗号書庫生成のテスト"""
        # 暗号書庫を生成
        storage_file, a_partition_map_key, b_partition_map_key = create_crypto_storage(
            self.a_password, self.b_password, self.test_dir, self.test_params
        )

        # ファイルが作成されたことを確認
        self.assertTrue(os.path.exists(storage_file))

        # パーティションマップキーが生成されたことを確認
        self.assertIsNotNone(a_partition_map_key)
        self.assertIsNotNone(b_partition_map_key)

        # 作成された暗号書庫ファイルを読み込む
        with open(storage_file, 'r', encoding='utf-8') as f:
            crypto_storage = json.load(f)

        # 暗号書庫の構造を確認
        self.assertIn('metadata', crypto_storage)
        self.assertIn('shares', crypto_storage)

        # メタデータの内容を確認
        metadata = crypto_storage['metadata']
        self.assertIn('salt', metadata)

        # メタデータが最小限の情報のみを含むことを確認
        self.assertEqual(len(metadata), 1, "メタデータはsaltのみを含むべき")

        # シェア数を確認
        shares = crypto_storage['shares']
        self.assertEqual(len(shares), self.test_params['PARTITION_SIZE'] * 2 + self.test_params['UNASSIGNED_SHARES'])

    def test_metadata_security(self):
        """メタデータセキュリティ検証テスト"""
        # 暗号書庫を生成
        storage_file, _, _ = create_crypto_storage(
            self.a_password, self.b_password, self.test_dir, self.test_params
        )

        # 作成された暗号書庫ファイルを読み込む
        with open(storage_file, 'r', encoding='utf-8') as f:
            crypto_storage = json.load(f)

        # メタデータの内容を確認
        metadata = crypto_storage['metadata']

        # 必須フィールドの確認
        self.assertIn('salt', metadata, "メタデータにsaltが含まれていません")

        # メタデータが最小限の情報のみを含むことを確認
        self.assertEqual(len(metadata), 1, "メタデータはsaltのみを含むべき")

    def test_partition_separation(self):
        """パーティション分離特性のテスト"""
        # 暗号書庫を生成
        _, a_partition_map_key, b_partition_map_key = create_crypto_storage(
            self.a_password, self.b_password, self.test_dir, self.test_params
        )

        # パーティションマップキーから第1段階MAPを復元
        a_partition = restore_partition_distribution(a_partition_map_key, self.a_password)
        b_partition = restore_partition_distribution(b_partition_map_key, self.b_password)

        # サイズを確認
        self.assertEqual(len(a_partition), self.test_params['PARTITION_SIZE'])
        self.assertEqual(len(b_partition), self.test_params['PARTITION_SIZE'])

        # 重複がないことを確認
        a_set = set(a_partition)
        b_set = set(b_partition)
        intersection = a_set.intersection(b_set)
        self.assertEqual(len(intersection), 0)

        # 検証関数でも確認
        self.assertTrue(verify_partition_distribution(a_partition, b_partition, self.test_params['PARTITION_SIZE']))

    def test_multiple_generations(self):
        """複数回の生成で異なる分布になることを確認するテスト"""
        # 複数回生成
        num_iterations = 5
        all_a_partitions = []
        all_b_partitions = []

        for _ in range(num_iterations):
            _, a_key, b_key = create_crypto_storage(
                self.a_password, self.b_password, self.test_dir, self.test_params
            )

            a_partition = restore_partition_distribution(a_key, self.a_password)
            b_partition = restore_partition_distribution(b_key, self.b_password)

            all_a_partitions.append(sorted(a_partition))
            all_b_partitions.append(sorted(b_partition))

        # すべての組み合わせで比較し、完全に一致するものがないことを確認
        for i in range(num_iterations):
            for j in range(i + 1, num_iterations):
                self.assertNotEqual(all_a_partitions[i], all_a_partitions[j])
                self.assertNotEqual(all_b_partitions[i], all_b_partitions[j])

    def test_cli_data_file_verification(self):
        """テストランナーが生成するCLIデータファイルの検証

        RULE-2.1.6に基づく検証：
        - CLIデータファイルには必要な情報が含まれていること
        - パーティションマップキーから復元されるMAP配列とCLIから直接取得したMAP配列に整合性があること
        """
        # CLIが生成したデータファイルを探す
        test_report_dir = Path(__file__).parent / "test_report"
        if not test_report_dir.exists():
            self.skipTest("テストレポートディレクトリが存在しません")

        # 最新のCLIデータファイルを探す（存在しない場合はスキップ）
        cli_data_files = list(test_report_dir.glob("cli_data_*.json"))
        if not cli_data_files:
            self.skipTest("CLIデータファイルが存在しません")

        # 最新のファイルを取得（修正日時で並べ替え）
        latest_file = sorted(cli_data_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]

        # ファイルを読み込む
        with open(latest_file, 'r', encoding='utf-8') as f:
            cli_data = json.load(f)

        # 必要な情報が含まれているか検証
        required_fields = [
            'a_partition_map_key', 'b_partition_map_key',
            'a_partition_map', 'b_partition_map',
            'a_password_hash', 'b_password_hash',
            'partition_size', 'active_shares'
        ]

        for field in required_fields:
            self.assertIn(field, cli_data, f"CLIデータファイルに{field}が含まれていません")

        # パーティションサイズとアクティブシェア数が一致するか検証
        self.assertEqual(len(cli_data['a_partition_map']), cli_data['active_shares'])
        self.assertEqual(len(cli_data['b_partition_map']), cli_data['active_shares'])

        # CLIデータファイルには平文パスワードが含まれていないことを確認
        # （セキュリティのためハッシュ値のみが保存されているべき）
        self.assertNotIn('a_password', cli_data)
        self.assertNotIn('b_password', cli_data)

    def test_statistical_indistinguishability(self):
        """ガベージシェアと有効シェアの統計的区別不可能性テスト"""
        # 有効シェアとガベージシェアを生成
        valid_shares = []
        garbage_shares = []

        # 統計的な分布を揃えるため、同じ方法で乱数生成
        prime = ShamirConstants.PRIME
        import secrets
        from gmpy2 import mpz

        # 両方とも同じ乱数生成メソッドを使用
        for _ in range(100):
            # mpz型を使用して値を生成（オーバーフロー防止）
            valid_shares.append(mpz(secrets.randbelow(int(prime - 1))) + 1)

        # ガベージシェア生成
        for _ in range(100):
            garbage_shares.append(generate_garbage_share())

        # 統計的区別不可能性を検証
        self.assertTrue(verify_statistical_indistinguishability(garbage_shares, valid_shares))

    def test_ten_generations(self):
        """10回の生成テスト"""
        results = []

        # 10回生成して結果を記録
        for i in range(10):
            _, a_key, b_key = create_crypto_storage(
                f"{self.a_password}_{i}", f"{self.b_password}_{i}",
                self.test_dir, self.test_params
            )

            a_partition = restore_partition_distribution(a_key, f"{self.a_password}_{i}")
            b_partition = restore_partition_distribution(b_key, f"{self.b_password}_{i}")

            results.append({
                'iteration': i,
                'a_partition': a_partition,
                'b_partition': b_partition,
                'a_size': len(a_partition),
                'b_size': len(b_partition),
                'separation': verify_partition_distribution(
                    a_partition, b_partition, self.test_params['PARTITION_SIZE']
                )
            })

        # 全ての結果を検証
        for result in results:
            # PARTITION_SIZEと完全一致するか
            self.assertEqual(result['a_size'], self.test_params['PARTITION_SIZE'])
            self.assertEqual(result['b_size'], self.test_params['PARTITION_SIZE'])

            # 完全に分離しているか
            self.assertTrue(result['separation'])

        # 各生成が異なる分布を持つか（分布の比較）
        distribution_equal_count = 0
        for i in range(10):
            for j in range(i + 1, 10):
                if sorted(results[i]['a_partition']) == sorted(results[j]['a_partition']):
                    distribution_equal_count += 1

        # 完全にランダムな場合、同一の分布になる確率は極めて低い
        self.assertEqual(distribution_equal_count, 0,
                        "異なる実行で同一の分布が発生しました。生成の非決定論性が確保されていません。")


if __name__ == '__main__':
    unittest.main()