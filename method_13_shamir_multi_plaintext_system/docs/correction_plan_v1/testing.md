# シャミア秘密分散法による複数平文復号システム：テスト計画

## はじめに

このドキュメントでは、シャミア秘密分散法による複数平文復号システムの包括的なテスト計画と検証手順を提案します。問題点の詳細については`problems.md`を、解決策については`solutions.md`を参照してください。

## テスト計画

### 1. ユニットテスト

#### 1.1 基本機能テスト

| テスト名                     | 説明                     | 期待される結果                                         |
| ---------------------------- | ------------------------ | ------------------------------------------------------ |
| `test_polynomial`            | 多項式生成と評価をテスト | 指定された多項式が正しく生成され、評価結果が一致する   |
| `test_share_generation`      | シェア生成をテスト       | 指定された秘密値からシェアが正しく生成される           |
| `test_secret_reconstruction` | 秘密復元をテスト         | 生成されたシェアから元の秘密が正確に復元される         |
| `test_stage1_map`            | 第 1 段階 MAP をテスト   | 同じパーティションキーで常に同じシェア ID が選択される |
| `test_stage2_map`            | 第 2 段階 MAP をテスト   | 同じパスワードで常に同じマッピングが生成される         |

```python
def test_stage1_map_consistency():
    """stage1_map関数の一貫性テスト"""
    partition_key = "test_partition_key"
    all_share_ids = list(range(1, 1001))

    # 10回実行して結果を比較
    results = []
    for _ in range(10):
        selected_ids = stage1_map(partition_key, all_share_ids)
        results.append(selected_ids)

    # 全ての結果が一致することを確認
    for i in range(1, len(results)):
        assert results[0] == results[i], f"Run {i} differs from first run"

    print("✓ stage1_map passed consistency test")
```

#### 1.2 暗号化/復号テスト

| テスト名                  | 説明                             | 期待される結果                                               |
| ------------------------- | -------------------------------- | ------------------------------------------------------------ |
| `test_encrypt_decrypt`    | 基本的な暗号化と復号をテスト     | 暗号化されたファイルが同じキーとパスワードで正しく復号される |
| `test_wrong_password`     | 誤ったパスワードでの復号をテスト | 復号に失敗し、エラーメッセージが返される                     |
| `test_metadata_integrity` | メタデータの整合性をテスト       | 暗号化ファイルのメタデータが正しく保持される                 |

```python
def test_encrypt_decrypt_cycle():
    """暗号化と復号の完全なサイクルテスト"""
    # テストデータ
    doc = {"test": "value", "nested": {"data": [1, 2, 3]}}
    password = "test_password"
    partition_key = "test_partition_key"

    # 暗号化
    encrypted = encrypt_json_document(doc, password, partition_key)

    # 復号
    decrypted = decrypt_json_document(encrypted, partition_key, password)

    # 元のデータと一致するか確認
    assert decrypted == doc, "Decrypted document does not match original"

    print("✓ Encrypt/decrypt cycle test passed")
```

#### 1.3 更新処理テスト

| テスト名                        | 説明                               | 期待される結果                                               |
| ------------------------------- | ---------------------------------- | ------------------------------------------------------------ |
| `test_update_document`          | 暗号化ファイルの更新をテスト       | 更新が成功し、新しいデータが正しく復号される                 |
| `test_update_preserves_data`    | 更新が他のデータを保持するかテスト | 更新後も他のパーティションのデータが保持される               |
| `test_update_with_invalid_data` | 無効なデータでの更新をテスト       | 適切なエラーメッセージが返され、元のファイルは影響を受けない |

```python
def test_update_preserves_other_partition():
    """更新が他のパーティションデータを保持することをテスト"""
    # テストデータ
    doc_a = {"user": "A", "data": "A's secret"}
    doc_b = {"user": "B", "data": "B's secret"}

    password_a = "password_a"
    password_b = "password_b"

    partition_key_a = "partition_key_a"
    partition_key_b = "partition_key_b"

    # Aのデータで暗号化
    encrypted = encrypt_json_document(doc_a, password_a, partition_key_a)

    # 暗号化ファイルをBのデータで更新
    updated = update_document(encrypted, doc_b, password_b, partition_key_b)

    # 両方のデータが復号できることを確認
    decrypted_a = decrypt_json_document(updated, partition_key_a, password_a)
    decrypted_b = decrypt_json_document(updated, partition_key_b, password_b)

    assert decrypted_a == doc_a, "A's data was lost during update"
    assert decrypted_b == doc_b, "B's data was not properly stored"

    print("✓ Update preserves other partition data")
```

### 2. 統合テスト

#### 2.1 CLI テスト

| テスト名                  | 説明                   | 期待される結果                           |
| ------------------------- | ---------------------- | ---------------------------------------- |
| `test_cli_encrypt`        | 暗号化コマンドをテスト | ファイルが正しく暗号化される             |
| `test_cli_decrypt`        | 復号コマンドをテスト   | ファイルが正しく復号される               |
| `test_cli_update`         | 更新コマンドをテスト   | ファイルが正しく更新される               |
| `test_cli_error_handling` | エラー処理をテスト     | エラー状況で適切なメッセージが表示される |

```bash
#!/bin/bash

# CLIテストスクリプト

set -e  # エラー時に停止

echo "Running CLI tests..."

# テスト用ファイル
echo '{"test": "data A"}' > test_a.json
echo '{"test": "data B"}' > test_b.json

# テスト用キー
PARTITION_KEY_A="test_partition_key_a"
PARTITION_KEY_B="test_partition_key_b"
PASSWORD_A="password_for_a"
PASSWORD_B="password_for_b"

# 1. 暗号化テスト
python -m shamir encrypt \
  --input test_a.json \
  --output test_encrypted.json \
  --password "$PASSWORD_A" \
  --partition-key "$PARTITION_KEY_A"

echo "✓ Encryption test passed"

# 2. 復号テスト
python -m shamir decrypt \
  --input test_encrypted.json \
  --output test_decrypted.json \
  --password "$PASSWORD_A" \
  --partition-key "$PARTITION_KEY_A"

# 内容を比較
if diff -q test_a.json test_decrypted.json > /dev/null; then
  echo "✓ Decryption test passed"
else
  echo "✗ Decryption test failed: files differ"
  exit 1
fi

# 3. 更新テスト
python -m shamir update \
  --encrypted-input test_encrypted.json \
  --json-input test_b.json \
  --output test_updated.json \
  --password "$PASSWORD_B" \
  --partition-key "$PARTITION_KEY_B"

echo "✓ Update test passed"

# 4. 更新後のBデータ復号テスト
python -m shamir decrypt \
  --input test_updated.json \
  --output test_decrypted_b.json \
  --password "$PASSWORD_B" \
  --partition-key "$PARTITION_KEY_B"

if diff -q test_b.json test_decrypted_b.json > /dev/null; then
  echo "✓ B data decryption test passed"
else
  echo "✗ B data decryption test failed: files differ"
  exit 1
fi

# 5. 更新後のAデータ復号テスト
python -m shamir decrypt \
  --input test_updated.json \
  --output test_decrypted_a_after.json \
  --password "$PASSWORD_A" \
  --partition-key "$PARTITION_KEY_A"

if diff -q test_a.json test_decrypted_a_after.json > /dev/null; then
  echo "✓ A data preservation test passed"
else
  echo "✗ A data preservation test failed: A's data was lost"
  exit 1
fi

echo "All CLI tests passed!"
```

#### 2.2 パフォーマンステスト

| テスト名                | 説明                         | 期待される結果                   |
| ----------------------- | ---------------------------- | -------------------------------- |
| `test_large_file`       | 大きなファイルの処理をテスト | 適切な時間内に処理が完了する     |
| `test_memory_usage`     | メモリ使用量をテスト         | メモリ使用量が許容範囲内に収まる |
| `test_multiple_updates` | 複数回の更新をテスト         | 複数回の更新後も正しく動作する   |

```python
def test_memory_usage():
    """メモリ使用量テスト"""
    import resource
    import gc

    # 初期メモリ使用量を記録
    gc.collect()
    start_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # テスト用大規模データ生成
    large_data = {"data": ["x" * 1000] * 1000}  # 約1MBのJSON

    # 暗号化と復号
    encrypted = encrypt_json_document(large_data, "test", "test_key")
    decrypted = decrypt_json_document(encrypted, "test_key", "test")

    # 終了時メモリ使用量を記録
    gc.collect()
    end_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # メモリ増加量（KB）
    mem_increase = end_mem - start_mem

    print(f"Memory usage increase: {mem_increase} KB")
    assert mem_increase < 100000, "Memory usage too high"  # 100MB以内に制限
```

### 3. セキュリティテスト

#### 3.1 統計的区別不可能性テスト

| テスト名                      | 説明                       | 期待される結果                               |
| ----------------------------- | -------------------------- | -------------------------------------------- |
| `test_indistinguishability`   | シェア分布の統計的検証     | 異なるユーザーのシェアが統計的に区別できない |
| `test_partition_distribution` | パーティション分布のテスト | 各パーティションのシェアが均等に分布している |

```python
def test_statistical_indistinguishability():
    """シェアの統計的区別不可能性をテスト"""
    # Aユーザー用の文書を暗号化
    doc_a = {"user": "A", "data": "A data"}
    encrypted_a = encrypt_json_document(doc_a, "password_a", "key_a")

    # Bユーザー用の文書を暗号化
    doc_b = {"user": "B", "data": "B data"}
    encrypted_b = encrypt_json_document(doc_b, "password_b", "key_b")

    # シェアIDの分布を比較
    a_share_ids = [s['share_id'] for s in encrypted_a['shares']]
    b_share_ids = [s['share_id'] for s in encrypted_b['shares']]

    # 基本統計量の計算
    a_mean = sum(a_share_ids) / len(a_share_ids)
    b_mean = sum(b_share_ids) / len(b_share_ids)

    # 平均値の差が小さいことを確認
    diff = abs(a_mean - b_mean) / max(a_mean, b_mean)
    assert diff < 0.2, f"Share distributions differ too much: {diff:.2f}"

    print("✓ Statistical indistinguishability test passed")
```

#### 3.2 タイミング攻撃耐性テスト

| テスト名             | 説明                 | 期待される結果                                             |
| -------------------- | -------------------- | ---------------------------------------------------------- |
| `test_timing_attack` | 処理時間の分析       | 正しいパスワードと誤ったパスワードの処理時間に有意差がない |
| `test_constant_time` | 定数時間処理のテスト | データサイズに関わらず処理時間が一定                       |

```python
def test_timing_attack_resistance():
    """タイミング攻撃耐性をテスト"""
    import time

    # テストデータ
    doc = {"test": "data"}
    correct_password = "correct_password"
    wrong_password = "wrong_password"
    partition_key = "test_key"

    # 暗号化
    encrypted = encrypt_json_document(doc, correct_password, partition_key)

    # 正しいパスワードでの復号時間を測定（10回平均）
    correct_times = []
    for _ in range(10):
        start = time.time()
        decrypt_json_document(encrypted, partition_key, correct_password)
        correct_times.append(time.time() - start)

    # 誤ったパスワードでの復号時間を測定（10回平均）
    wrong_times = []
    for _ in range(10):
        start = time.time()
        decrypt_json_document(encrypted, partition_key, wrong_password)
        wrong_times.append(time.time() - start)

    # 平均時間を計算
    avg_correct = sum(correct_times) / len(correct_times)
    avg_wrong = sum(wrong_times) / len(wrong_times)

    # 時間差の比率
    time_ratio = max(avg_correct, avg_wrong) / min(avg_correct, avg_wrong)

    print(f"Correct password avg time: {avg_correct:.6f}s")
    print(f"Wrong password avg time: {avg_wrong:.6f}s")
    print(f"Time ratio: {time_ratio:.2f}")

    # 時間差が20%以内であることを確認
    assert time_ratio < 1.2, f"Timing difference too large: {time_ratio:.2f}"
```

### 4. 継続的インテグレーションテスト

以下の CI 設定を実装して自動テストを行うことを推奨します：

```yaml
# .github/workflows/ci.yml
name: Shamir Multi-Plaintext System CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.7, 3.8, 3.9, '3.10']

    steps:
      - uses: actions/checkout@v2
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v2
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
          pip install pytest pytest-cov mypy
      - name: Lint with mypy
        run: |
          mypy shamir/
      - name: Test with pytest
        run: |
          pytest --cov=shamir tests/
      - name: Upload coverage
        uses: codecov/codecov-action@v1
```

## テスト環境設定

### 1. 仮想環境のセットアップ

```bash
# Python仮想環境の作成
python -m venv venv

# 仮想環境の有効化
# Windows:
# venv\Scripts\activate
# Unix/MacOS:
source venv/bin/activate

# 依存関係のインストール
pip install -r requirements.txt

# テスト用依存関係のインストール
pip install pytest pytest-cov mypy
```

### 2. テストの実行

```bash
# ユニットテストの実行
pytest tests/

# カバレッジレポートの生成
pytest --cov=shamir tests/ --cov-report=html

# 特定のテストの実行
pytest tests/test_crypto.py::test_encrypt_decrypt_cycle

# 全テストスイートの実行（時間がかかる可能性があります）
pytest tests/ -v
```

## テスト結果の分析

### 1. テストカバレッジ

- コード行カバレッジ: 90%以上を目標とする
- 分岐カバレッジ: 85%以上を目標とする
- すべての公開関数がテスト対象であること

### 2. パフォーマンス分析

- 暗号化/復号処理: 1MB 未満のファイルで 1 秒以内
- メモリ使用量: プロセスあたり 100MB 以下
- 同時実行時の安定性: クラッシュなし

### 3. CI 結果の評価

- すべてのテストが成功すること
- 静的コード解析でエラーがないこと
- 依存関係の脆弱性がないこと

## 結論

包括的なテスト計画を実施することで、シャミア秘密分散法による複数平文復号システムの信頼性と堅牢性を向上させることができます。特に重要なのは：

1. MAP ロジックの決定論的な一貫性を確保するテスト
2. 暗号化 → 更新 → 復号の完全なワークフローテスト
3. メモリ使用量と処理時間の効率性テスト
4. 統計的区別不可能性を検証するセキュリティテスト

これらのテストを自動化して継続的に実行することで、システムの品質を長期的に維持することが可能になります。
