"""
基本的なテスト

【責務】
このモジュールは、シャミア秘密分散法システムの基本機能を検証するための単体テストを提供します。
以下の機能を検証します：
- パーティションマップキーの生成と検証
- 多項式評価アルゴリズムの正確性
- シェア生成と復元の動作確認
- 暗号化・復号化機能の検証
- 複数文書の管理と独立した復号化の確認
"""

import unittest
import json
import os
import tempfile
from pathlib import Path

from shamir.constants import ShamirConstants
from method_13_shamir_multi_plaintext_system.shamir._trash.partition import generate_partition_map_key, PartitionManager, initialize_system
from method_13_shamir_multi_plaintext_system.shamir._trash.core import generate_polynomial, evaluate_polynomial, generate_shares, lagrange_interpolation
from shamir.crypto import encrypt_json_document, decrypt_json_document, load_encrypted_file, save_encrypted_file
from shamir.update import update_encrypted_document
from shamir.tests import security_self_diagnostic


class TestBasicFunctionality(unittest.TestCase):
    """基本的な機能テスト"""

    def setUp(self):
        """テスト前の準備"""
        # テスト用の一時ディレクトリを作成
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # システム初期化
        self.system_info = initialize_system()
        self.partition_a_key = self.system_info['partition_a_key']
        self.partition_b_key = self.system_info['partition_b_key']

        # パーティションマネージャーを初期化
        self.partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # テスト用のJSON文書
        self.test_doc_a = {
            "document_type": "A",
            "title": "Document for User A",
            "content": "This is a secret document for user A.",
            "metadata": {
                "created_at": "2023-06-01T12:00:00Z",
                "version": 1,
                "author": "Test Author A"
            }
        }

        self.test_doc_b = {
            "document_type": "B",
            "title": "Document for User B",
            "content": "This is a secret document for user B.",
            "metadata": {
                "created_at": "2023-06-02T14:30:00Z",
                "version": 1,
                "author": "Test Author B"
            }
        }

        # テスト用のパスワード
        self.password_a = "password_for_user_a"
        self.password_b = "password_for_user_b"

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # 一時ディレクトリを削除
        self.temp_dir.cleanup()

    def test_partition_map_key_generation(self):
        """パーティションマップキー生成のテスト"""
        key1 = generate_partition_map_key()
        key2 = generate_partition_map_key()

        # キーが生成されていることを確認
        self.assertIsNotNone(key1)
        self.assertIsNotNone(key2)

        # キーが一意であることを確認
        self.assertNotEqual(key1, key2)

        # キーの長さが適切であることを確認
        self.assertGreater(len(key1), 32)
        self.assertGreater(len(key2), 32)

    def test_polynomial_evaluation(self):
        """多項式評価のテスト"""
        from gmpy2 import mpz

        # テスト用の多項式: 3x^2 + 2x + 1
        coef = [mpz(1), mpz(2), mpz(3)]

        # 素数
        prime = ShamirConstants.PRIME

        # x=0での評価（秘密値）
        y0 = evaluate_polynomial(coef, mpz(0), prime)
        self.assertEqual(y0, 1)

        # x=1での評価
        y1 = evaluate_polynomial(coef, mpz(1), prime)
        self.assertEqual(y1, 6)

        # x=2での評価
        y2 = evaluate_polynomial(coef, mpz(2), prime)
        self.assertEqual(y2, 17)

    def test_share_generation_and_reconstruction(self):
        """シェア生成と復元のテスト"""
        from gmpy2 import mpz

        # テスト用の秘密値
        secret = mpz(12345)

        # テスト用の閾値とシェアID
        threshold = 3
        share_ids = [1, 2, 3, 4, 5]

        # 素数
        prime = ShamirConstants.PRIME

        # シェアを生成
        shares = generate_shares(secret, threshold, share_ids, prime)

        # 各閾値サイズのサブセットで秘密を復元できることを確認
        for i in range(len(shares) - threshold + 1):
            subset = shares[i:i+threshold]
            recovered = lagrange_interpolation([s for s in subset], prime)
            self.assertEqual(recovered, secret)

        # 閾値未満のサブセットでは復元できないことを確認
        with self.assertRaises(ValueError):
            lagrange_interpolation([shares[0]], prime)

    def test_encryption_and_decryption(self):
        """暗号化と復号のテスト"""
        # 暗号化ファイルのパス
        encrypted_file_path = self.temp_path / "encrypted.json"

        # Aのドキュメントを暗号化
        encrypted_file = encrypt_json_document(
            self.test_doc_a,
            self.password_a,
            self.partition_a_key,
            self.partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        save_encrypted_file(encrypted_file, str(encrypted_file_path))

        # ファイルが作成されていることを確認
        self.assertTrue(encrypted_file_path.exists())

        # 暗号化ファイルを読み込み
        loaded_file = load_encrypted_file(str(encrypted_file_path))

        # Aのパスワードとパーティションキーで復号
        decrypted_a = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password_a
        )

        # 復号に成功していることを確認
        self.assertEqual(decrypted_a, self.test_doc_a)

        # Bのパスワードとパーティションキーで復号（失敗するはず）
        decrypted_b = decrypt_json_document(
            loaded_file,
            self.partition_b_key,
            self.password_b
        )

        # 復号に失敗していることを確認
        self.assertNotEqual(decrypted_b, self.test_doc_a)
        self.assertIn('error', decrypted_b)

    def test_multiple_documents(self):
        """複数文書の暗号化と復号のテスト"""
        # 暗号化ファイルのパス
        encrypted_file_path = self.temp_path / "multi_encrypted.json"

        # Aのドキュメントを暗号化
        encrypted_file_a = encrypt_json_document(
            self.test_doc_a,
            self.password_a,
            self.partition_a_key,
            self.partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        save_encrypted_file(encrypted_file_a, str(encrypted_file_path))

        # Bのドキュメントを追加（更新処理として）
        success, updated_file = update_encrypted_document(
            str(encrypted_file_path),
            self.test_doc_b,
            self.password_b,
            self.partition_b_key
        )

        # 更新が成功していることを確認
        self.assertTrue(success)

        # 更新ファイルを保存
        save_encrypted_file(updated_file, str(encrypted_file_path))

        # 更新されたファイルを読み込み
        loaded_file = load_encrypted_file(str(encrypted_file_path))

        # Aのパスワードとパーティションキーで復号
        decrypted_a = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password_a
        )

        # Bのパスワードとパーティションキーで復号
        decrypted_b = decrypt_json_document(
            loaded_file,
            self.partition_b_key,
            self.password_b
        )

        # 両方とも正しく復号できることを確認
        self.assertEqual(decrypted_a, self.test_doc_a)
        self.assertEqual(decrypted_b, self.test_doc_b)

        # 異なるパーティションやパスワードでは元の文書が取得できないことを確認
        wrong_decrypted = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password_b
        )
        self.assertIn('error', wrong_decrypted)


if __name__ == '__main__':
    unittest.main()