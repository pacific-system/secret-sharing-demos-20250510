# 問題 6: テスト計画（全体計画の一部）

## テストの重要性

シャミア秘密分散法による複数平文復号システムの修正では、各機能の正確性を検証するための包括的なテストが不可欠です。本テスト計画では、修正された機能が正しく動作することを確認するためのテスト戦略を概説します。

## テスト戦略

テストは以下の 4 つのレベルで行います：

1. **ユニットテスト**: 個々の関数やクラスの動作を検証
2. **統合テスト**: 複数のコンポーネントの相互作用を検証
3. **システムテスト**: システム全体の動作を検証
4. **パフォーマンステスト**: システムの性能を検証

## テスト実装ガイドライン

### 1. テスト環境のセットアップ

以下のようなテスト環境を構築します：

```python
# tests/conftest.py

import pytest
import os
import json
import tempfile
import shutil
from typing import Dict, Any, List

@pytest.fixture
def temp_dir():
    """テスト用の一時ディレクトリを提供"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir

@pytest.fixture
def test_json_data():
    """テスト用のJSONデータを提供"""
    return {
        "user": "test",
        "data": {
            "field1": "value1",
            "field2": 123,
            "field3": [1, 2, 3],
            "field4": {"nested": "object"}
        }
    }

@pytest.fixture
def large_test_json_data():
    """大きなテスト用JSONデータを提供"""
    # 約1MBのデータを生成
    data = {
        "large_array": ["item" * 100 for _ in range(1000)],
        "nested": {
            "objects": [{"id": i, "data": "x" * 100} for i in range(100)]
        }
    }
    return data

@pytest.fixture
def test_keys():
    """テスト用のキーセットを提供"""
    return {
        "partitionA": "test_partition_key_A",
        "partitionB": "test_partition_key_B",
        "partitionC": "test_partition_key_C",
        "passwordA": "test_password_A",
        "passwordB": "test_password_B",
        "passwordC": "test_password_C",
    }
```

### 2. 各問題に対応するユニットテスト

各修正問題に対して、専用のテストモジュールを作成します。

#### パーティションキー機能テスト

```python
# tests/test_partition_key.py

import pytest
import os
from shamir.partition import generate_partition_map
from shamir.key_management import PartitionKeyManager
from shamir.crypto import encrypt_json_document, decrypt_json_document

def test_partition_map_determinism():
    """パーティションキーからの確定的なマップ生成をテスト"""
    # 同じパーティションキーで複数回生成
    key = os.urandom(32)
    map1 = generate_partition_map(key, 10000, 30)
    map2 = generate_partition_map(key, 10000, 30)

    # 同じ結果が得られるか確認
    assert map1 == map2, "同じキーから異なる結果が生成されました"

    # 異なるキーでは異なる結果が得られるか確認
    key2 = os.urandom(32)
    map3 = generate_partition_map(key2, 10000, 30)
    assert map1 != map3, "異なるキーから同じ結果が生成されました"

def test_partition_key_separation():
    """パーティション間の適切な分離をテスト"""
    # テストデータ
    keyA = os.urandom(32)
    keyB = os.urandom(32)

    # 両方のキーから領域を生成
    mapA = set(generate_partition_map(keyA, 10000, 30))
    mapB = set(generate_partition_map(keyB, 10000, 30))

    # 重複の数を計算
    intersection = mapA.intersection(mapB)

    # 重複は限定的であるべき（完全に重複なしは確率的に難しい）
    assert len(intersection) / len(mapA) < 0.1, "パーティション間の重複が多すぎます"

def test_encryption_decryption_with_partition_keys(test_json_data, test_keys):
    """異なるパーティションキーでの暗号化と復号をテスト"""
    # キーマネージャを初期化
    key_manager = PartitionKeyManager()

    # パーティションキーを登録
    key_bytes_A = test_keys["partitionA"].encode('utf-8')
    key_bytes_B = test_keys["partitionB"].encode('utf-8')
    key_manager.add_key("userA", key_bytes_A)
    key_manager.add_key("userB", key_bytes_B)

    # ユーザーAのデータを暗号化
    dataA = test_json_data
    encrypted = encrypt_json_document(dataA, test_keys["passwordA"], "userA")

    # ユーザーBのデータを追加
    dataB = {"user": "B", "data": "B's secret data"}
    updated = update_document(encrypted, dataB, test_keys["passwordB"], "userB")

    # それぞれのユーザーでデータを復号
    decrypted_A = decrypt_json_document(updated, "userA", test_keys["passwordA"])
    decrypted_B = decrypt_json_document(updated, "userB", test_keys["passwordB"])

    # 正しく復号されたか確認
    assert decrypted_A == dataA, "ユーザーAのデータが正しく復号されませんでした"
    assert decrypted_B == dataB, "ユーザーBのデータが正しく復号されませんでした"
```

#### MAP 生成テスト

```python
# tests/test_map_generation.py

import pytest
import os
import random
from shamir.core import stage1_map, stage2_map
from shamir.crypto import encrypt_json_document, decrypt_json_document
from shamir.constants import ShamirConstants

def test_stage1_map_determinism():
    """stage1_map関数の決定論的な動作をテスト"""
    # テストキー
    key = os.urandom(32)

    # 同じ条件で2回呼び出し
    map1 = stage1_map(key, ShamirConstants.SHARE_ID_SPACE, 10)
    map2 = stage1_map(key, ShamirConstants.SHARE_ID_SPACE, 10)

    # 結果が同じことを確認
    assert map1 == map2, "同じキーから異なるシェアIDが生成されました"

def test_stage2_map_determinism():
    """stage2_map関数の決定論的な動作をテスト"""
    # テストパラメータ
    password = "test_password"
    salt = os.urandom(16)
    share_ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    # 同じ条件で2回呼び出し
    scores1 = stage2_map(password, salt, share_ids)
    scores2 = stage2_map(password, salt, share_ids)

    # 結果が同じことを確認
    assert scores1 == scores2, "同じパスワードとソルトで異なるスコアが生成されました"

def test_encrypt_decrypt_cycle_consistency():
    """暗号化と復号の一貫性をテスト"""
    # テストデータ
    doc = {"test": "data"}
    password = "test_password"
    partition_key = "test_key"

    # 同じデータを複数回暗号化
    results = []
    for _ in range(5):
        encrypted = encrypt_json_document(doc, password, partition_key)
        decrypted = decrypt_json_document(encrypted, partition_key, password)
        results.append(decrypted)

    # すべての復号結果が一致するか確認
    assert all(r == doc for r in results), "異なる暗号化結果になりました"
```

#### 更新処理テスト

```python
# tests/test_update_process.py

import pytest
import os
import json
import tempfile
from shamir.crypto import encrypt_json_document, decrypt_json_document
from shamir.update import update_document, WALManager
from shamir.constants import ShamirConstants

def test_update_preserves_original_data(test_json_data, test_keys):
    """更新処理が元のデータを保持することをテスト"""
    # ユーザーAのデータを暗号化
    dataA = test_json_data
    encrypted = encrypt_json_document(
        dataA,
        test_keys["passwordA"],
        test_keys["partitionA"]
    )

    # ユーザーBのデータで更新
    dataB = {"user": "B", "data": "B's data"}
    updated = update_document(
        encrypted,
        dataB,
        test_keys["passwordB"],
        test_keys["partitionB"]
    )

    # ユーザーAのデータを復号して確認
    decrypted_A = decrypt_json_document(
        updated,
        test_keys["partitionA"],
        test_keys["passwordA"]
    )

    # 元のデータと一致するか確認
    assert decrypted_A == dataA, "更新後にユーザーAのデータが変更されました"

def test_multiple_updates(test_json_data, test_keys):
    """複数回の更新処理をテスト"""
    # ユーザーAのデータを暗号化
    dataA = test_json_data
    encrypted = encrypt_json_document(
        dataA,
        test_keys["passwordA"],
        test_keys["partitionA"]
    )

    # ユーザーB, Cのデータで順番に更新
    dataB = {"user": "B", "data": "B's data"}
    updated1 = update_document(
        encrypted,
        dataB,
        test_keys["passwordB"],
        test_keys["partitionB"]
    )

    dataC = {"user": "C", "data": "C's data"}
    updated2 = update_document(
        updated1,
        dataC,
        test_keys["passwordC"],
        test_keys["partitionC"]
    )

    # すべてのユーザーデータを復号して確認
    decrypted_A = decrypt_json_document(updated2, test_keys["partitionA"], test_keys["passwordA"])
    decrypted_B = decrypt_json_document(updated2, test_keys["partitionB"], test_keys["passwordB"])
    decrypted_C = decrypt_json_document(updated2, test_keys["partitionC"], test_keys["passwordC"])

    # すべてのデータが正しいか確認
    assert decrypted_A == dataA, "更新後にユーザーAのデータが変更されました"
    assert decrypted_B == dataB, "更新後にユーザーBのデータが変更されました"
    assert decrypted_C == dataC, "ユーザーCのデータが正しくありません"

def test_wal_recovery(temp_dir, test_json_data, test_keys):
    """WALによる回復機能をテスト"""
    # WALマネージャを初期化
    wal_manager = WALManager(os.path.join(temp_dir, "wal"))

    # テストファイルパス
    test_file = os.path.join(temp_dir, "test.json")
    wal_file = wal_manager.create_wal_file(test_file)

    # ユーザーAのデータを暗号化
    dataA = test_json_data
    encrypted = encrypt_json_document(
        dataA,
        test_keys["passwordA"],
        test_keys["partitionA"]
    )

    # 初期状態をファイルとWALに保存
    with open(test_file, 'w') as f:
        json.dump(encrypted, f)

    wal_manager.write_initial_state(wal_file, encrypted)

    # 更新をシミュレート（故意にエラーを発生させる前に）
    dataB = {"user": "B", "data": "B's data"}
    updated = update_document(
        encrypted,
        dataB,
        test_keys["passwordB"],
        test_keys["partitionB"]
    )

    # 故意にファイルを破損（WALからの回復をテスト）
    with open(test_file, 'w') as f:
        f.write("corrupted data")

    # WALから復元
    recovered = wal_manager.rollback_from_wal(wal_file)

    # 復元データを保存
    with open(test_file, 'w') as f:
        json.dump(recovered, f)

    # 復元データから正しく復号できるか確認
    with open(test_file, 'r') as f:
        loaded = json.load(f)

    decrypted = decrypt_json_document(
        loaded,
        test_keys["partitionA"],
        test_keys["passwordA"]
    )

    # 元のデータと一致するか確認
    assert decrypted == dataA, "WALからの復元後のデータが元のデータと一致しません"
```

#### シェア ID 空間サイズテスト

```python
# tests/test_share_id_space.py

import pytest
import os
import time
import random
from shamir.share_id import generate_share_ids, determine_share_id_space_size
from shamir.performance import PerformanceMonitor
from shamir.crypto import encrypt_json_document
from shamir.constants import ShamirConstants

def test_share_id_space_performance(large_test_json_data):
    """異なるシェアID空間サイズでのパフォーマンスをテスト"""
    # テストパラメータ
    password = "test_password"
    partition_key = "test_key"
    doc = {"test": "data"}  # 小さいデータを使用（時間短縮のため）

    # 小さいシェアID空間での暗号化
    ShamirConstants.SHARE_ID_SPACE = 1000
    result_small, perf_small = PerformanceMonitor.measure_performance(
        encrypt_json_document, doc, password, partition_key
    )

    # 標準サイズのシェアID空間での暗号化
    ShamirConstants.SHARE_ID_SPACE = 10000
    result_medium, perf_medium = PerformanceMonitor.measure_performance(
        encrypt_json_document, doc, password, partition_key
    )

    # 大きいシェアID空間での暗号化
    ShamirConstants.SHARE_ID_SPACE = 100000
    result_large, perf_large = PerformanceMonitor.measure_performance(
        encrypt_json_document, doc, password, partition_key
    )

    # 結果の出力
    print(f"小さいシェアID空間（1000）: {perf_small['execution_time_sec']:.4f}秒, {perf_small['final_rss_mb']:.2f}MB")
    print(f"標準シェアID空間（10000）: {perf_medium['execution_time_sec']:.4f}秒, {perf_medium['final_rss_mb']:.2f}MB")
    print(f"大きいシェアID空間（100000）: {perf_large['execution_time_sec']:.4f}秒, {perf_large['final_rss_mb']:.2f}MB")

    # シェアID空間が大きいほどメモリ使用量と実行時間が増加するはず
    assert perf_small['final_rss_mb'] <= perf_medium['final_rss_mb'] <= perf_large['final_rss_mb']

    # 実行時間の厳密な比較は環境によって異なる可能性があるため注意
    # しかし、大きな差があるはず
    assert perf_small['execution_time_sec'] <= perf_large['execution_time_sec'] * 0.8

def test_generate_share_ids_efficiency():
    """シェアID生成の効率性をテスト"""
    # テストパラメータ
    seed = os.urandom(32)
    count = 1000
    max_id = 10000

    # メモリ使用量と実行時間を測定
    result, performance = PerformanceMonitor.measure_performance(
        generate_share_ids, seed, count, max_id
    )

    # 結果の確認（数値は環境によって異なる）
    print(f"実行時間: {performance['execution_time_sec']:.4f}秒")
    print(f"メモリ増加量: {performance['memory_increase_rss_mb']:.2f}MB")

    # メモリ使用量が適切であることを確認（多すぎないこと）
    assert performance['memory_increase_rss_mb'] < 10, "シェアID生成のメモリ使用量が多すぎます"

    # 実行時間が適切であることを確認（遅すぎないこと）
    assert performance['execution_time_sec'] < 0.5, "シェアID生成の実行時間が長すぎます"
```

#### ファイル形式テスト

```python
# tests/test_file_format.py

import pytest
import os
import json
from shamir.crypto import encrypt_json_document, decrypt_json_document
from shamir.utils import convert_file_format
from shamir.formats import FileFormat

def test_file_format_size_reduction(test_json_data, test_keys):
    """ファイル形式の最適化によるサイズ削減をテスト"""
    # ユーザーAのデータを暗号化（古い形式）
    dataA = test_json_data
    encrypted_old = encrypt_json_document(
        dataA,
        test_keys["passwordA"],
        test_keys["partitionA"]
    )

    # 新しい形式に変換
    encrypted_new = convert_file_format(encrypted_old)

    # ファイルサイズを比較
    old_json = json.dumps(encrypted_old)
    new_json = json.dumps(encrypted_new)

    old_size = len(old_json)
    new_size = len(new_json)

    # 削減率を計算
    reduction = (old_size - new_size) / old_size * 100

    print(f"旧形式サイズ: {old_size} バイト")
    print(f"新形式サイズ: {new_size} バイト")
    print(f"削減率: {reduction:.2f}%")

    # 10%以上の削減を期待
    assert reduction >= 10, "ファイルサイズの削減が期待より少ない"

def test_backward_compatibility(test_json_data, test_keys):
    """後方互換性をテスト（古い形式のファイルを新しいコードで復号）"""
    # ユーザーAのデータを暗号化（古い形式）
    dataA = test_json_data
    encrypted_old = encrypt_json_document(
        dataA,
        test_keys["passwordA"],
        test_keys["partitionA"]
    )

    # 新しい形式に変換
    encrypted_new = convert_file_format(encrypted_old)

    # 元のデータを旧形式と新形式から復号
    decrypted_old = decrypt_json_document(
        encrypted_old,
        test_keys["partitionA"],
        test_keys["passwordA"]
    )

    decrypted_new = decrypt_json_document(
        encrypted_new,
        test_keys["partitionA"],
        test_keys["passwordA"]
    )

    # 結果が同じことを確認
    assert decrypted_old == decrypted_new == dataA, "形式変換後にデータが変化しました"

def test_file_format_extraction():
    """FileFormatクラスの抽出機能をテスト"""
    # テストデータ（新形式）
    shares_map = {
        "0:1": "123",
        "0:2": "456",
        "1:1": "789",
        "1:2": "012"
    }

    metadata = {
        "salt": "test_salt",
        "threshold": 2,
        "total_chunks": 2
    }

    new_format = {
        "metadata": metadata,
        "shares_map": shares_map
    }

    # シェアデータの抽出
    shares_data, extracted_metadata = FileFormat.extract_share_data(new_format)

    # メタデータが正しく抽出されたか確認
    assert extracted_metadata == metadata

    # シェアデータが正しく抽出されたか確認
    assert len(shares_data) == 4

    # チャンク0のシェアが含まれているか確認
    chunk0_shares = [s for s in shares_data if s["chunk_index"] == 0]
    assert len(chunk0_shares) == 2

    # シェアIDが正しく変換されたか確認
    share_ids = [s["share_id"] for s in shares_data]
    assert sorted(share_ids) == [1, 1, 2, 2]
```

### 3. 統合テスト

CLI コマンドと全体的なワークフローをテストします。

```python
# tests/test_cli_integration.py

import pytest
import os
import json
import subprocess
from shamir.cli import main

def test_encrypt_decrypt_cli(temp_dir, test_json_data):
    """暗号化と復号のCLIコマンドをテスト"""
    # テストファイルを作成
    input_json = os.path.join(temp_dir, "input.json")
    encrypted_json = os.path.join(temp_dir, "encrypted.json")
    decrypted_json = os.path.join(temp_dir, "decrypted.json")

    # 入力ファイルを作成
    with open(input_json, 'w') as f:
        json.dump(test_json_data, f)

    # 暗号化コマンド
    encrypt_args = [
        "encrypt",
        "--input", input_json,
        "--output", encrypted_json,
        "--password", "test_password",
        "--partition-key", "test_key"
    ]

    # CLIを実行
    result = subprocess.run(
        ["python", "-m", "shamir"] + encrypt_args,
        capture_output=True,
        text=True
    )

    # 成功したか確認
    assert result.returncode == 0, f"暗号化に失敗: {result.stderr}"
    assert os.path.exists(encrypted_json), "暗号化ファイルが作成されていない"

    # 復号コマンド
    decrypt_args = [
        "decrypt",
        "--input", encrypted_json,
        "--output", decrypted_json,
        "--password", "test_password",
        "--partition-key", "test_key"
    ]

    # CLIを実行
    result = subprocess.run(
        ["python", "-m", "shamir"] + decrypt_args,
        capture_output=True,
        text=True
    )

    # 成功したか確認
    assert result.returncode == 0, f"復号に失敗: {result.stderr}"
    assert os.path.exists(decrypted_json), "復号ファイルが作成されていない"

    # 復号されたデータが元のデータと一致するか確認
    with open(decrypted_json, 'r') as f:
        decrypted_data = json.load(f)

    assert decrypted_data == test_json_data, "復号されたデータが元のデータと一致しない"

def test_update_cli(temp_dir):
    """更新のCLIコマンドをテスト"""
    # テストファイルを作成
    input_a = os.path.join(temp_dir, "input_a.json")
    input_b = os.path.join(temp_dir, "input_b.json")
    encrypted = os.path.join(temp_dir, "encrypted.json")
    updated = os.path.join(temp_dir, "updated.json")
    decrypted_a = os.path.join(temp_dir, "decrypted_a.json")
    decrypted_b = os.path.join(temp_dir, "decrypted_b.json")

    # 入力ファイルを作成
    data_a = {"user": "A", "data": "A's data"}
    data_b = {"user": "B", "data": "B's data"}

    with open(input_a, 'w') as f:
        json.dump(data_a, f)

    with open(input_b, 'w') as f:
        json.dump(data_b, f)

    # 暗号化コマンド（ユーザーA）
    encrypt_args = [
        "encrypt",
        "--input", input_a,
        "--output", encrypted,
        "--password", "passwordA",
        "--partition-key", "keyA"
    ]

    subprocess.run(
        ["python", "-m", "shamir"] + encrypt_args,
        capture_output=True,
        check=True
    )

    # 更新コマンド（ユーザーB）
    update_args = [
        "update",
        "--encrypted-input", encrypted,
        "--json-input", input_b,
        "--output", updated,
        "--password", "passwordB",
        "--partition-key", "keyB"
    ]

    subprocess.run(
        ["python", "-m", "shamir"] + update_args,
        capture_output=True,
        check=True
    )

    # 復号コマンド（ユーザーA）
    decrypt_a_args = [
        "decrypt",
        "--input", updated,
        "--output", decrypted_a,
        "--password", "passwordA",
        "--partition-key", "keyA"
    ]

    subprocess.run(
        ["python", "-m", "shamir"] + decrypt_a_args,
        capture_output=True,
        check=True
    )

    # 復号コマンド（ユーザーB）
    decrypt_b_args = [
        "decrypt",
        "--input", updated,
        "--output", decrypted_b,
        "--password", "passwordB",
        "--partition-key", "keyB"
    ]

    subprocess.run(
        ["python", "-m", "shamir"] + decrypt_b_args,
        capture_output=True,
        check=True
    )

    # 復号されたデータが元のデータと一致するか確認
    with open(decrypted_a, 'r') as f:
        decrypted_data_a = json.load(f)

    with open(decrypted_b, 'r') as f:
        decrypted_data_b = json.load(f)

    assert decrypted_data_a == data_a, "ユーザーAのデータが正しく復元されていない"
    assert decrypted_data_b == data_b, "ユーザーBのデータが正しく復元されていない"
```

### 4. パフォーマンステスト

大規模データや多数のパーティションでのパフォーマンスをテストします。

```python
# tests/test_performance.py

import pytest
import os
import json
import time
from shamir.performance import PerformanceMonitor
from shamir.crypto import encrypt_json_document, decrypt_json_document
from shamir.update import update_document

def test_large_file_performance(large_test_json_data, test_keys):
    """大きなファイルでのパフォーマンスをテスト"""
    # テストパラメータ
    data = large_test_json_data
    password = test_keys["passwordA"]
    partition_key = test_keys["partitionA"]

    # 暗号化パフォーマンスを測定
    print("\n暗号化パフォーマンス:")
    result_encrypt, perf_encrypt = PerformanceMonitor.measure_performance(
        encrypt_json_document, data, password, partition_key
    )

    print(f"実行時間: {perf_encrypt['execution_time_sec']:.4f}秒")
    print(f"メモリ使用量: {perf_encrypt['final_rss_mb']:.2f}MB")

    # 復号パフォーマンスを測定
    print("\n復号パフォーマンス:")
    result_decrypt, perf_decrypt = PerformanceMonitor.measure_performance(
        decrypt_json_document, result_encrypt, partition_key, password
    )

    print(f"実行時間: {perf_decrypt['execution_time_sec']:.4f}秒")
    print(f"メモリ使用量: {perf_decrypt['final_rss_mb']:.2f}MB")

    # 結果が一致するか確認
    assert result_decrypt == data, "大きなファイルの復号に失敗しました"

def test_multiple_partition_performance(test_json_data):
    """多数のパーティションでのパフォーマンスをテスト"""
    # 基本データ
    base_data = test_json_data

    # パーティション数
    num_partitions = 10

    # 初期暗号化
    encrypted = encrypt_json_document(
        base_data,
        f"password0",
        f"partition_key0"
    )

    update_times = []

    # 複数のパーティションで更新
    for i in range(1, num_partitions):
        data = {"user": f"User{i}", "data": f"Data for user {i}"}

        start_time = time.time()
        encrypted = update_document(
            encrypted,
            data,
            f"password{i}",
            f"partition_key{i}"
        )
        end_time = time.time()

        update_times.append(end_time - start_time)

    # パーティション数増加に伴う平均更新時間を計算
    avg_time = sum(update_times) / len(update_times)
    print(f"\n平均更新時間（{num_partitions}パーティション）: {avg_time:.4f}秒")

    # 各パーティションからの復号をテスト
    decrypt_times = []

    for i in range(num_partitions):
        start_time = time.time()
        decrypted = decrypt_json_document(
            encrypted,
            f"partition_key{i}",
            f"password{i}"
        )
        end_time = time.time()

        decrypt_times.append(end_time - start_time)

    # 平均復号時間を計算
    avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)
    print(f"平均復号時間（{num_partitions}パーティション）: {avg_decrypt_time:.4f}秒")

    # パフォーマンスの制約を確認
    assert avg_time < 1.0, "更新処理が遅すぎます"
    assert avg_decrypt_time < 0.5, "復号処理が遅すぎます"
```

## 自動テストの実行

以下のような Makefile を作成して、テストの実行を自動化します。

```makefile
# tests/Makefile

.PHONY: test test-unit test-integration test-performance test-coverage

# 基本的なテスト
test:
	pytest -v

# ユニットテストのみ
test-unit:
	pytest -v tests/test_partition_key.py tests/test_map_generation.py tests/test_update_process.py tests/test_share_id_space.py tests/test_file_format.py

# 統合テストのみ
test-integration:
	pytest -v tests/test_cli_integration.py

# パフォーマンステストのみ
test-performance:
	pytest -v tests/test_performance.py

# カバレッジレポート付きテスト
test-coverage:
	pytest --cov=shamir --cov-report=html
```

## テスト計画の実行順序

テストを実行する推奨順序は以下の通りです：

1. ユニットテスト（各モジュールが単独で正しく動作するか）
2. 統合テスト（モジュール間の相互作用が正しいか）
3. パフォーマンステスト（性能要件を満たしているか）

テストが失敗した場合は、修正を行い、再度テストを実行してください。すべてのテストが成功するまで修正を繰り返してください。

## テスト結果の評価

テスト結果は以下の基準で評価します：

1. **機能性**: すべてのテストケースが成功すること
2. **パフォーマンス**: 指定された時間内に処理が完了すること
3. **メモリ使用量**: 指定されたメモリ使用量以内に収まること
4. **互換性**: 古いデータ形式とも互換性があること

## まとめ

この包括的なテスト計画を実施することで、シャミア秘密分散法による複数平文復号システムの修正が正しく機能することを確認できます。テストはシステムの信頼性と安定性を確保する重要な要素であり、今後の拡張や変更に対しても堅牢性を提供します。
