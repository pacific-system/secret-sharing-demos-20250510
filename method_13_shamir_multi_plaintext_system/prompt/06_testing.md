## テストとバリデーション

システム全体のテストでは、各コンポーネントの機能テスト、統計的検証テスト、セキュリティテストを行います。特に暗号システムとして重要な安全性の検証に重点を置きます。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `05_security.md`: セキュリティ要件と攻撃モデル
- `06_performance.md`: 性能評価とパフォーマンステスト
- `07_guidelines.md`: 7.3 節「条件分岐の禁止と定数時間処理の実装パターン」、7.5 節「統計的区別不可能性の実装」

### 1. 機能テスト

## システムのテスト

システムのテスト部分では、ユニットテスト、統合テスト、および性能テストを実装し、システムの正確性、堅牢性、セキュリティを検証します。

### 1. ユニットテスト

```python
import unittest
import json
import os
import tempfile
import shutil
from gmpy2 import mpz
import time

class ShamirSecretSharingTest(unittest.TestCase):
    """シャミア秘密分散法の基本機能テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.prime = ShamirConstants.PRIME
        self.threshold = 3
        self.share_ids = [1, 2, 3, 4, 5]

    def test_polynomial_creation(self):
        """多項式生成のテスト"""
        secret = mpz(42)
        degree = self.threshold - 1

        coef = generate_polynomial(secret, degree, self.prime)

        # 係数のチェック
        self.assertEqual(len(coef), self.threshold)
        self.assertEqual(coef[0], secret)  # 最初の係数は秘密値

        # 各係数が適切な範囲内にあることを確認
        for c in coef[1:]:
            self.assertGreater(c, 0)
            self.assertLess(c, self.prime)

    def test_polynomial_evaluation(self):
        """多項式評価のテスト"""
        coef = [mpz(42), mpz(11), mpz(7)]  # f(x) = 42 + 11x + 7x^2
        x = mpz(3)

        expected = (42 + 11*3 + 7*3*3) % self.prime
        result = evaluate_polynomial(coef, x, self.prime)

        self.assertEqual(result, expected)

    def test_share_generation_and_reconstruction(self):
        """シェア生成と復元のテスト"""
        secret = mpz(12345)

        # シェア生成
        shares = generate_shares(secret, self.threshold, self.share_ids, self.prime)

        # 必要最小限のシェアで復元
        min_shares = shares[:self.threshold]
        reconstructed = lagrange_interpolation(min_shares, self.prime)
        self.assertEqual(reconstructed, secret)

        # 別の組み合わせでも復元できることを確認
        other_shares = [shares[0], shares[2], shares[4]]
        reconstructed = lagrange_interpolation(other_shares, self.prime)
        self.assertEqual(reconstructed, secret)

        # 閾値未満のシェアでは復元できないことを確認
        insufficient_shares = shares[:self.threshold-1]
        reconstructed = lagrange_interpolation(insufficient_shares, self.prime)
        self.assertNotEqual(reconstructed, secret)


class JsonProcessingTest(unittest.TestCase):
    """JSON処理のテスト"""

    def test_json_preprocessing_and_postprocessing(self):
        """JSONの前処理と後処理のテスト"""
        original_doc = {
            "name": "テスト文書",
            "data": [1, 2, 3, 4, 5],
            "nested": {"key": "value", "日本語": "テスト"}
        }

        # 前処理
        processed_data = preprocess_json_document(original_doc)

        # チャンクに分割
        chunks = split_into_chunks(processed_data)

        # 後処理でJSONに戻す
        restored_doc = postprocess_json_document(chunks)

        # 元のJSONと一致することを確認
        self.assertEqual(restored_doc, original_doc)


class MapGenerationTest(unittest.TestCase):
    """MAP生成のテスト"""

    def test_stage1_map(self):
        """第1段階MAPの生成テスト"""
        partition_key = "test_partition_key"
        all_share_ids = list(range(1, 101))

        selected_ids = stage1_map(partition_key, all_share_ids)

        # 同じキーで実行すると同じIDが選択されることを確認
        selected_ids2 = stage1_map(partition_key, all_share_ids)
        self.assertEqual(selected_ids, selected_ids2)

        # 異なるキーでは異なるIDが選択されることを確認
        different_ids = stage1_map("different_key", all_share_ids)
        self.assertNotEqual(selected_ids, different_ids)

    def test_stage2_map(self):
        """第2段階MAPの生成テスト"""
        password = "test_password"
        candidate_ids = [1, 2, 3, 4, 5]
        salt = b"test_salt"

        mapping = stage2_map(password, candidate_ids, salt)

        # 各IDがマッピングされていることを確認
        for id in candidate_ids:
            self.assertIn(id, mapping)

        # 同じパスワードで実行すると同じマッピングが生成されることを確認
        mapping2 = stage2_map(password, candidate_ids, salt)
        self.assertEqual(mapping, mapping2)

        # 異なるパスワードでは異なるマッピングが生成されることを確認
        different_mapping = stage2_map("different_password", candidate_ids, salt)
        self.assertNotEqual(mapping, different_mapping)


class ConstantTimeOperationsTest(unittest.TestCase):
    """定数時間操作のテスト"""

    def test_constant_time_select(self):
        """条件分岐なしの選択処理テスト"""
        # 数値型のテスト
        self.assertEqual(constant_time_select(True, 10, 20), 10)
        self.assertEqual(constant_time_select(False, 10, 20), 20)

        # リスト型のテスト
        self.assertEqual(constant_time_select(True, [1, 2], [3, 4]), [1, 2])
        self.assertEqual(constant_time_select(False, [1, 2], [3, 4]), [3, 4])

        # 辞書型のテスト
        self.assertEqual(constant_time_select(True, {"a": 1}, {"b": 2}), {"a": 1})
        self.assertEqual(constant_time_select(False, {"a": 1}, {"b": 2}), {"b": 2})
```

### 2. 統合テスト

```python
class ShamirIntegrationTest(unittest.TestCase):
    """シャミア秘密分散システムの統合テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.test_dir = tempfile.mkdtemp()
        self.encrypted_file_path = os.path.join(self.test_dir, "test_encrypted.json")
        self.encrypted_file_path_b = os.path.join(self.test_dir, "test_encrypted_b.json")

        # テスト用データ
        self.json_doc_a = {
            "name": "文書A",
            "data": [1, 2, 3, 4, 5],
            "meta": {"creator": "ユーザーA", "created_at": "2023-01-01"}
        }

        self.json_doc_b = {
            "name": "文書B",
            "data": [6, 7, 8, 9, 10],
            "meta": {"creator": "ユーザーB", "created_at": "2023-01-02"}
        }

        # パスワードとマップキー
        self.password_a = "password_a"
        self.password_b = "password_b"
        self.system_info = initialize_system()
        self.partition_a_key = self.system_info["partition_a_key"]
        self.partition_b_key = self.system_info["partition_b_key"]

    def tearDown(self):
        """テスト後のクリーンアップ"""
        shutil.rmtree(self.test_dir)

    def test_encrypt_decrypt_single_document(self):
        """単一文書の暗号化と復号のテスト"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        # 暗号化ファイルを読み込み
        loaded_file = load_encrypted_file(self.encrypted_file_path)

        # 文書Aを復号
        decrypted_doc = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password_a
        )

        # 元の文書と一致することを確認
        self.assertEqual(decrypted_doc, self.json_doc_a)

        # 誤ったパスワードで復号を試みる
        wrong_decrypted = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            "wrong_password"
        )

        # エラーオブジェクトが返されることを確認
        self.assertIn('error', wrong_decrypted)

        # 誤ったパーティションキーで復号を試みる
        wrong_partition = decrypt_json_document(
            loaded_file,
            self.partition_b_key,
            self.password_a
        )

        # エラーオブジェクトが返されることを確認
        self.assertIn('error', wrong_partition)

    def test_encrypt_decrypt_separate_documents(self):
        """別々のパーティションキーを使用した2つの文書の暗号化と復号のテスト"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file_a = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        # 文書Bを暗号化
        encrypted_file_b = encrypt_json_document(
            self.json_doc_b,
            self.password_b,
            self.partition_b_key,
            partition_manager.b_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file_a, f)

        with open(self.encrypted_file_path_b, 'w') as f:
            json.dump(encrypted_file_b, f)

        # 暗号化ファイルを読み込み
        loaded_file_a = load_encrypted_file(self.encrypted_file_path)
        loaded_file_b = load_encrypted_file(self.encrypted_file_path_b)

        # 文書Aを復号
        decrypted_a = decrypt_json_document(
            loaded_file_a,
            self.partition_a_key,
            self.password_a
        )

        # 文書Bを復号
        decrypted_b = decrypt_json_document(
            loaded_file_b,
            self.partition_b_key,
            self.password_b
        )

        # 元の文書と一致することを確認
        self.assertEqual(decrypted_a, self.json_doc_a)
        self.assertEqual(decrypted_b, self.json_doc_b)

        # 誤ったパスワードとパーティションキーの組み合わせ
        wrong_combo = decrypt_json_document(
            loaded_file_a,
            self.partition_a_key,
            self.password_b
        )

        # エラーオブジェクトが返されることを確認
        self.assertIn('error', wrong_combo)

    def test_update_document(self):
        """文書の更新テスト"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        # 更新用の文書
        updated_doc_a = self.json_doc_a.copy()
        updated_doc_a["name"] = "更新された文書A"
        updated_doc_a["data"].append(6)

        # 文書Aを更新
        success, result = update_encrypted_document(
            self.encrypted_file_path,
            updated_doc_a,
            self.password_a,
            self.partition_a_key
        )

        # 更新が成功したことを確認
        self.assertTrue(success)

        # 更新後のファイルを読み込み
        loaded_file = load_encrypted_file(self.encrypted_file_path)

        # 文書Aを復号
        decrypted_a = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password_a
        )

        # 文書Aが更新されていることを確認
        self.assertEqual(decrypted_a, updated_doc_a)

        # 誤ったパスワードで更新を試みる
        wrong_success, wrong_result = update_encrypted_document(
            self.encrypted_file_path,
            {"new": "data"},
            "wrong_password",
            self.partition_a_key
        )

        # 更新が失敗したことを確認
        self.assertFalse(wrong_success)
```

### 3. 性能テスト

```python
class ShamirPerformanceTest(unittest.TestCase):
    """シャミア秘密分散システムの性能テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.test_dir = tempfile.mkdtemp()
        self.encrypted_file_path = os.path.join(self.test_dir, "perf_test.json")

        # システム初期化
        self.system_info = initialize_system()
        self.partition_a_key = self.system_info["partition_a_key"]
        self.password = "test_password"

        # テスト用データ生成
        self.small_doc = {"data": "x" * 100}  # 約100バイト
        self.medium_doc = {"data": "x" * 10000}  # 約10KB
        self.large_doc = {"data": "x" * 100000}  # 約100KB

    def tearDown(self):
        """テスト後のクリーンアップ"""
        shutil.rmtree(self.test_dir)

    def _measure_encryption_time(self, doc):
        """暗号化時間を計測"""
        # パーティションマネージャーの初期化
        partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.system_info["partition_b_key"]
        )

        start_time = time.time()

        encrypted_file = encrypt_json_document(
            doc,
            self.password,
            self.partition_a_key,
            partition_manager.a_share_ids
        )

        end_time = time.time()

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        return end_time - start_time, len(json.dumps(encrypted_file))

    def _measure_decryption_time(self):
        """復号時間を計測"""
        # 暗号化ファイルを読み込み
        loaded_file = load_encrypted_file(self.encrypted_file_path)

        start_time = time.time()

        decrypted_doc = decrypt_json_document(
            loaded_file,
            self.partition_a_key,
            self.password
        )

        end_time = time.time()

        return end_time - start_time

    def test_encryption_performance(self):
        """暗号化性能テスト"""
        # 小サイズデータ
        small_time, small_size = self._measure_encryption_time(self.small_doc)
        print(f"\n小サイズ暗号化: {small_time:.4f}秒, サイズ: {small_size}バイト")

        # 中サイズデータ
        medium_time, medium_size = self._measure_encryption_time(self.medium_doc)
        print(f"中サイズ暗号化: {medium_time:.4f}秒, サイズ: {medium_size}バイト")

        # 大サイズデータ
        large_time, large_size = self._measure_encryption_time(self.large_doc)
        print(f"大サイズ暗号化: {large_time:.4f}秒, サイズ: {large_size}バイト")

        # 性能スケーリングの確認
        # 一般的に、データサイズが10倍になると処理時間もほぼ10倍になることを期待
        # ただし、オーバーヘッドのため正確に10倍にはならない
        scaling_factor_medium = medium_time / small_time
        scaling_factor_large = large_time / medium_time

        print(f"中/小 スケーリング比: {scaling_factor_medium:.2f}")
        print(f"大/中 スケーリング比: {scaling_factor_large:.2f}")

        # サイズ比の確認
        size_ratio_medium = medium_size / small_size
        size_ratio_large = large_size / medium_size

        print(f"中/小 サイズ比: {size_ratio_medium:.2f}")
        print(f"大/中 サイズ比: {size_ratio_large:.2f}")

        # 基本的なアサーション
        self.assertLess(small_time, medium_time)
        self.assertLess(medium_time, large_time)

    def test_decryption_performance(self):
        """復号性能テスト"""
        # 各サイズで暗号化してから復号時間を計測

        # 小サイズデータ
        self._measure_encryption_time(self.small_doc)
        small_time = self._measure_decryption_time()
        print(f"\n小サイズ復号: {small_time:.4f}秒")

        # 中サイズデータ
        self._measure_encryption_time(self.medium_doc)
        medium_time = self._measure_decryption_time()
        print(f"中サイズ復号: {medium_time:.4f}秒")

        # 大サイズデータ
        self._measure_encryption_time(self.large_doc)
        large_time = self._measure_decryption_time()
        print(f"大サイズ復号: {large_time:.4f}秒")

        # 基本的なアサーション
        self.assertLess(small_time, medium_time)
        self.assertLess(medium_time, large_time)
```

### 4. セキュリティテスト

```python
class ShamirSecurityTest(unittest.TestCase):
    """シャミア秘密分散システムのセキュリティテスト"""

    def setUp(self):
        """テスト前の準備"""
        self.test_dir = tempfile.mkdtemp()
        self.encrypted_file_path = os.path.join(self.test_dir, "security_test.json")

        # テスト用データ
        self.json_doc_a = {"name": "文書A", "sensitive": "機密情報A"}
        self.json_doc_b = {"name": "文書B", "sensitive": "機密情報B"}

        # パスワードとマップキー
        self.password_a = "password_a"
        self.password_b = "password_b"
        self.system_info = initialize_system()
        self.partition_a_key = self.system_info["partition_a_key"]
        self.partition_b_key = self.system_info["partition_b_key"]

        # パーティションマネージャーの初期化
        self.partition_manager = PartitionManager(
            partition_a_key=self.partition_a_key,
            partition_b_key=self.partition_b_key
        )

        # 文書Aを暗号化
        encrypted_file = encrypt_json_document(
            self.json_doc_a,
            self.password_a,
            self.partition_a_key,
            self.partition_manager.a_share_ids
        )

        # 暗号化ファイルを保存
        with open(self.encrypted_file_path, 'w') as f:
            json.dump(encrypted_file, f)

    def tearDown(self):
        """テスト後のクリーンアップ"""
        shutil.rmtree(self.test_dir)

    def test_statistical_indistinguishability(self):
        """統計的区別不可能性テスト"""
        # ファイルを読み込み
        with open(self.encrypted_file_path, 'r') as f:
            encrypted_file = json.load(f)

        # シェア値を分析
        all_shares = encrypted_file['shares']
        all_values = [int(share['value']) for share in all_shares]

        # シェア値の統計分析
        # 基本的な統計値を計算
        min_value = min(all_values)
        max_value = max(all_values)
        avg_value = sum(all_values) / len(all_values)

        # 値の分布を確認するために値域を10分割してヒストグラムを計算
        range_size = (max_value - min_value) // 10
        if range_size == 0:
            range_size = 1

        histogram = [0] * 10
        for value in all_values:
            bin_idx = min(9, (value - min_value) // range_size)
            histogram[bin_idx] += 1

        # ヒストグラムの各ビンの期待値（均一分布の場合）
        expected = len(all_values) / 10

        # カイ二乗値の計算（分布の均一性を評価）
        chi_squared = sum((obs - expected) ** 2 / expected for obs in histogram)

        # カイ二乗分布の臨界値（自由度9、有意水準0.05）は16.92
        # この値を下回れば均一分布と見なせる
        print(f"\nシェア値のカイ二乗値: {chi_squared}")
        print(f"ヒストグラム: {histogram}")

        # 安全のため厳しい基準を設定
        self.assertLess(chi_squared, 20.0, "シェア値の分布が均一でない可能性があります")

    def test_side_channel_resistance(self):
        """サイドチャネル攻撃耐性テスト"""
        # タイミング攻撃耐性テスト
        # 正しいパスワードと誤ったパスワードで処理時間に大きな差がないか確認

        # ファイルを読み込み
        with open(self.encrypted_file_path, 'r') as f:
            encrypted_file = json.load(f)

        # 正しいパスワードでの復号時間を計測
        start_time = time.time()
        decrypt_json_document(encrypted_file, self.partition_a_key, self.password_a)
        correct_time = time.time() - start_time

        # 誤ったパスワードでの復号時間を計測
        start_time = time.time()
        decrypt_json_document(encrypted_file, self.partition_a_key, "wrong_password")
        wrong_time = time.time() - start_time

        # 処理時間の差を計算（絶対値）
        time_diff = abs(correct_time - wrong_time)

        print(f"\n正しいパスワードでの復号時間: {correct_time:.4f}秒")
        print(f"誤ったパスワードでの復号時間: {wrong_time:.4f}秒")
        print(f"時間差: {time_diff:.4f}秒")

        # 時間差が小さいことを確認
        # 通常、0.1秒以内の差は許容範囲と考えられる
        # ただし、この値はシステムやハードウェアに依存する
        self.assertLess(time_diff, 0.1, "タイミング攻撃に対して脆弱な可能性があります")
```

### 5. 総合テストプログラム

```python
def run_all_tests():
    """すべてのテストを実行"""
    # テストスイートを作成
    test_suite = unittest.TestSuite()

    # 基本ユニットテスト
    test_suite.addTest(unittest.makeSuite(ShamirSecretSharingTest))
    test_suite.addTest(unittest.makeSuite(JsonProcessingTest))
    test_suite.addTest(unittest.makeSuite(MapGenerationTest))
    test_suite.addTest(unittest.makeSuite(ConstantTimeOperationsTest))

    # 統合テスト
    test_suite.addTest(unittest.makeSuite(ShamirIntegrationTest))

    # 性能テスト
    test_suite.addTest(unittest.makeSuite(ShamirPerformanceTest))

    # セキュリティテスト
    test_suite.addTest(unittest.makeSuite(ShamirSecurityTest))

    # テスト実行
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(test_suite)


if __name__ == "__main__":
    run_all_tests()
```

### 6. セキュリティ自己診断ツール

```python
def security_self_diagnostic():
    """
    システムのセキュリティ自己診断ツール
    統計的区別不可能性やサイドチャネル攻撃耐性などを検証
    """
    print("=== シャミア秘密分散法 セキュリティ自己診断 ===\n")

    # システム初期化
    print("システム初期化中...")
    system_info = initialize_system()
    partition_a_key = system_info["partition_a_key"]
    partition_b_key = system_info["partition_b_key"]

    # パーティション空間の検証
    print("\n1. パーティション空間の検証")
    partition_manager = PartitionManager(
        partition_a_key=partition_a_key,
        partition_b_key=partition_b_key
    )

    is_indistinguishable = verify_statistical_indistinguishability(
        partition_manager.a_share_ids,
        partition_manager.b_share_ids,
        partition_manager.unassigned_ids
    )

    if is_indistinguishable:
        print("✓ パーティション空間は統計的に区別不可能です")
    else:
        print("✗ パーティション空間に統計的な偏りがあります")

    # シェア値の均一性検証
    print("\n2. シェア値の均一性検証")
    test_secrets = [mpz(1), mpz(1000), mpz(1000000)]
    threshold = 3
    test_share_ids = list(range(1, 10))

    # 各秘密値に対してシェアを生成し、値の分布を確認
    all_share_values = []
    for secret in test_secrets:
        shares = generate_shares(secret, threshold, test_share_ids, ShamirConstants.PRIME)
        share_values = [int(value) % 1000000 for _, value in shares]  # 下位6桁のみ使用
        all_share_values.extend(share_values)

    # シェア値の最小値、最大値、平均値を計算
    min_value = min(all_share_values)
    max_value = max(all_share_values)
    avg_value = sum(all_share_values) / len(all_share_values)

    # 値の分布を確認するために値域を10分割してヒストグラムを計算
    range_size = (max_value - min_value) // 10 or 1
    histogram = [0] * 10
    for value in all_share_values:
        bin_idx = min(9, (value - min_value) // range_size)
        histogram[bin_idx] += 1

    # ヒストグラムの各ビンの期待値（均一分布の場合）
    expected = len(all_share_values) / 10

    # カイ二乗値の計算（分布の均一性を評価）
    chi_squared = sum((obs - expected) ** 2 / expected for obs in histogram)

    print(f"シェア値の統計: 最小={min_value}, 最大={max_value}, 平均={avg_value:.2f}")
    print(f"ヒストグラム: {histogram}")
    print(f"カイ二乗値: {chi_squared:.2f}")

    if chi_squared < 16.92:  # 自由度9、有意水準0.05の臨界値
        print("✓ シェア値は統計的に均一に分布しています")
    else:
        print("✗ シェア値の分布に偏りがある可能性があります")

    # タイミング攻撃耐性検証
    print("\n3. タイミング攻撃耐性検証")
    password = "test_password"
    wrong_password = "wrong_password"

    # テスト用データと暗号化
    test_data = {"test": "data"}

    # プレウォーミング（JITコンパイラの最適化のため）
    for _ in range(3):
        encrypted = encrypt_json_document(
            test_data, password, partition_a_key, partition_manager.a_share_ids
        )
        decrypt_json_document(encrypted, partition_a_key, password)
        decrypt_json_document(encrypted, partition_a_key, wrong_password)

    # 本測定
    encrypted = encrypt_json_document(
        test_data, password, partition_a_key, partition_manager.a_share_ids
    )

    # 正しいパスワードでの復号時間を計測（複数回測定して平均）
    correct_times = []
    for _ in range(5):
        start_time = time.time()
        decrypt_json_document(encrypted, partition_a_key, password)
        correct_times.append(time.time() - start_time)

    avg_correct_time = sum(correct_times) / len(correct_times)

    # 誤ったパスワードでの復号時間を計測（複数回測定して平均）
    wrong_times = []
    for _ in range(5):
        start_time = time.time()
        decrypt_json_document(encrypted, partition_a_key, wrong_password)
        wrong_times.append(time.time() - start_time)

    avg_wrong_time = sum(wrong_times) / len(wrong_times)

    # 処理時間の差を計算（絶対値）
    time_diff = abs(avg_correct_time - avg_wrong_time)

    print(f"正しいパスワードでの平均復号時間: {avg_correct_time:.4f}秒")
    print(f"誤ったパスワードでの平均復号時間: {avg_wrong_time:.4f}秒")
    print(f"平均時間差: {time_diff:.4f}秒")

    if time_diff < 0.05:  # 50ミリ秒以内の差は許容
        print("✓ タイミング攻撃に対して良好な耐性があります")
    elif time_diff < 0.1:  # 100ミリ秒以内
        print("△ タイミング攻撃に対して妥当な耐性がありますが、改善の余地があります")
    else:
        print("✗ タイミング攻撃に対して脆弱である可能性があります")

    # 総合評価
    print("\n=== 総合セキュリティ評価 ===")
    if is_indistinguishable and chi_squared < 16.92 and time_diff < 0.1:
        print("✓ セキュリティ要件を満たしています")
    else:
        print("✗ セキュリティに懸念があります。詳細な分析を確認してください")


if __name__ == "__main__":
    security_self_diagnostic()
```
