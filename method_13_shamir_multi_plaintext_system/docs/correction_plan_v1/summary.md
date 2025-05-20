# シャミア秘密分散法による複数平文復号システム：実装上の問題点

## 背景

シャミア秘密分散法による複数平文復号システムは、単一の暗号化ファイルから異なるパスワードを使用して異なる平文（JSON 文書）を復号可能にする技術です。このシステムは「パーティションマップキーによる MAP 生成とパスワードによるマップ生成」という多段 MAP 方式を核心としています。

最近の実装改善として、CLI インターフェースを簡素化し、`--user`フラグの削除と`--partition-key-a/b`を単一の`--partition-key`に統合しました。しかし、実装テスト中にいくつかの重要な問題が発見されました。

## 発見された問題点

### 1. 過大なシェア ID 空間サイズ

**問題**：
元の実装では`SHARE_ID_SPACE = 2**32 - 1`（約 43 億）という大きなシェア ID 空間を使用していました。これにより、実行時にメモリ消費が過大になり、プログラムが Kill される結果となっていました。

**確認方法**：
デバッグ出力を追加し、シェア ID 空間サイズを 1000 に縮小したところ、プログラムが正常に動作するようになりました。

**影響**：

- プログラムの実行が不可能
- メモリ使用量の急激な増加
- システムによるプロセスの強制終了

**修正案**：
シェア ID 空間のサイズを適切な値（例：10,000 程度）に設定し、シェア数とセキュリティのバランスを取るべきです。

### 2. MAP の生成ロジックの不整合

**問題**：
`stage1_map`関数がパーティションキーに基づいてシェア ID を選択しますが、選択パターンが一貫していません。そのため、同じパーティションキーとパスワードであっても、暗号化したファイルが後で復号できない場合があります。

**確認方法**：

- `stage1_map`関数が各実行で異なる選択を行うことをデバッグログで確認
- 同じファイルに対して繰り返し暗号化/復号を行うと、成功率が低い

**影響**：

- 信頼性の低下：同じキーとパスワードでも復号できない場合がある
- 複数平文共存時の整合性問題：一方の文書の更新が他方の文書のアクセス不能を引き起こす

**修正案**：

- `stage1_map`関数の乱数生成と選択アルゴリズムの見直し
- シード値から ID 生成までの決定論的プロセスを厳密に固定
- テストケースを追加し、繰り返し暗号化/復号操作での一貫性を確保

### 3. 更新処理の問題

**問題**：
ファイル更新処理が正しく動作せず、特に複数のユーザー文書が共存する場合に問題が生じます。具体的には、更新後のファイルでは一部のユーザー文書しか復号できなくなります。

**確認方法**：

- A 用文書で暗号化し、B 用文書で更新後
- B 用パスワードとキーでは開けるが、A 用では開けない

**影響**：

- 複数ユーザー文書の共存が実質的に不可能
- データ喪失リスク：更新操作が既存データを破壊する可能性

**修正案**：

- 他のシェアを維持する処理ロジックの見直し
- 特に stage1_map の結果に基づく「他のシェアの選択処理」の修正
- 更新処理の原子性強化（全ユーザーデータの一貫性確保）

### 4. 依存関係の管理不備

**問題**：
`update.py`モジュールで必要な`base64`モジュールがインポートされていませんでした。

**確認方法**：
更新処理実行時に "name 'base64' is not defined" エラーが発生

**影響**：

- 更新機能が完全に動作しない
- エラーメッセージが不明確でデバッグが困難

**修正案**：

- 各モジュールの依存関係の包括的レビュー
- 自動テスト導入による未使用/不足インポートのチェック

## 修正優先度

1. **高優先度**：MAI 生成ロジックの不整合修正（システムの信頼性に直結）
2. **高優先度**：更新処理の問題修正（データ損失防止のため）
3. **中優先度**：シェア ID 空間サイズの最適化（パフォーマンス向上）
4. **低優先度**：依存関係の管理改善（すでに修正済み）

## 今後のアクション

1. ユニットテストの拡充：特に暗号化 → 更新 → 復号のフローを検証するテスト
2. シェア ID 選択アルゴリズムの再設計：一貫性とセキュリティのバランスを考慮
3. メモリ使用量の最適化：大規模ファイル処理でもメモリ効率を確保
4. エラーハンドリングの強化：例外処理とエラーメッセージの明確化

## 結論

シャミア秘密分散法による複数平文復号システムは理論的には優れたアプローチですが、現在の実装にはいくつかの重要な問題があります。特に MAP 生成の一貫性と更新処理における複数文書の保全に課題があります。これらの問題を解決することで、システムの信頼性と使いやすさが大幅に向上するでしょう。
# シャミア秘密分散法による複数平文復号システム：解決策

## はじめに

このドキュメントでは、シャミア秘密分散法による複数平文復号システムで発見された問題点に対する具体的な解決策を提案します。問題点の詳細については`problems.md`を参照してください。

## 1. シェア ID 空間サイズの最適化

### 問題の概要

元の実装では`SHARE_ID_SPACE = 2**32 - 1`（約 43 億）の巨大なシェア ID 空間を使用していたため、メモリ消費が過大になりプログラムが強制終了する問題が発生していました。

### 解決策

#### 短期的解決策

```python
# constants.py
SHARE_ID_SPACE = 10000  # 適切なサイズに縮小
```

#### 中長期的解決策

1. **動的シェア ID 範囲の実装**:

   ```python
   def generate_share_id_space(security_level='standard'):
       if security_level == 'low':
           return 1000  # 開発/テスト用
       elif security_level == 'standard':
           return 10000  # 一般使用
       elif security_level == 'high':
           return 100000  # 高セキュリティ向け
       else:
           return 10000  # デフォルト
   ```

2. **メモリ効率の良い ID セット管理**:

   ```python
   def get_share_ids(partition_key, count, max_id):
       """メモリ効率の良いID生成（全IDを保持せずに計算）"""
       seed = int.from_bytes(hashlib.sha256(partition_key.encode()).digest(), 'big')
       rng = random.Random(seed)

       # ビットマップでIDの使用/未使用を管理
       used_ids = set()
       result = []

       while len(result) < count:
           # 範囲内でランダムIDを生成
           id = rng.randint(1, max_id)
           if id not in used_ids:
               used_ids.add(id)
               result.append(id)

       return result
   ```

3. **段階的ロード機構**:
   - 全 ID を一度にメモリにロードせず、必要に応じて計算する仕組み
   - 複数のシェア ID 空間を小さなブロックに分割し、必要なブロックのみをロード

## 2. MAP 生成ロジックの改善

### 問題の概要

`stage1_map`関数がパーティションキーに基づいてシェア ID を選択する際に一貫性がなく、同じキーでも異なる選択結果になることがあります。

### 解決策

#### 厳密な決定論的アルゴリズムの実装

```python
def stage1_map(partition_key: str, all_share_ids: List[int]) -> List[int]:
    """決定論的なシェアID選択（改良版）"""
    # ハッシュ生成（既存コード）
    key_bytes = partition_key.encode('ascii')
    seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')

    # シードから直接IDを選択する決定論的アルゴリズム
    selected_ids = []

    # 一時的なマッピングテーブルを作成
    id_mapping = {}
    for share_id in all_share_ids:
        # 各IDに対して決定論的なスコアを計算
        # シード値とIDを組み合わせてハッシュ化
        id_hash = hashlib.sha256(f"{seed}:{share_id}".encode()).digest()
        score = int.from_bytes(id_hash, 'big')
        id_mapping[share_id] = score

    # スコアでソートして上位のIDを選択
    sorted_ids = sorted(all_share_ids, key=lambda id: id_mapping[id])
    selected_count = int(len(all_share_ids) * ShamirConstants.RATIO_A)

    return sorted_ids[:selected_count]
```

#### ID 選択の安定性検証関数

```python
def verify_id_selection_stability(partition_key, runs=10):
    """ID選択の安定性を検証するテスト関数"""
    all_share_ids = list(range(1, ShamirConstants.SHARE_ID_SPACE + 1))
    previous_ids = None

    for i in range(runs):
        selected_ids = stage1_map(partition_key, all_share_ids)

        if previous_ids is not None:
            if set(selected_ids) != set(previous_ids):
                print(f"Error: Run {i} produced different IDs!")
                return False

        previous_ids = selected_ids

    print("All runs produced identical ID selections")
    return True
```

## 3. 更新処理の修正

### 問題の概要

更新処理が正しく機能せず、特に複数のユーザー文書が共存する場合に問題が発生します。

### 解決策

#### `_atomic_update`関数の修正

```python
def _atomic_update(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str,
    wal_manager: WALManager
) -> Tuple[bool, Dict[str, Any]]:
    """改良版更新処理"""
    # WALログを作成
    wal_path = wal_manager.create_wal_file(file_path)

    try:
        # 暗号化ファイルを読み込む
        with open(file_path, 'r') as f:
            encrypted_file = json.load(f)

        # ファイルの状態をWALに記録
        wal_manager.write_initial_state(wal_path, encrypted_file)

        # メタデータを取得
        metadata = encrypted_file['metadata']
        salt = base64.urlsafe_b64decode(metadata['salt'])
        threshold = metadata['threshold']

        # 全シェアを取得
        all_shares = encrypted_file['shares']
        all_share_ids = sorted(list(set(share['share_id'] for share in all_shares)))

        # ステップ1: 更新対象のシェアを特定
        # パーティションキーに対応するシェアIDを特定
        target_share_ids = stage1_map(partition_key, all_share_ids)

        # ステップ2: 対象シェアを新しい内容で置き換え
        # 更新対象でないシェアを保持
        preserved_shares = [s for s in all_shares if s['share_id'] not in target_share_ids]

        # 新しい文書を暗号化
        preprocessed_data = preprocess_json_document(json_doc)
        chunks = split_into_chunks(preprocessed_data)

        # 更新対象のシェアIDで新しいシェアを生成
        new_shares = []
        for chunk_idx, chunk in enumerate(chunks):
            secret = mpz(int.from_bytes(chunk, 'big'))
            # 閾値分のシェアを生成
            chunk_shares = generate_shares(
                secret, threshold, target_share_ids[:threshold], ShamirConstants.PRIME
            )
            for share_id, value in chunk_shares:
                new_shares.append({
                    'chunk_index': chunk_idx,
                    'share_id': share_id,
                    'value': str(value)
                })

        # メタデータを更新（両方の文書のチャンク数を個別に保持）
        updated_metadata = metadata.copy()

        # チャンク数の記録方法を改善
        if partition_key.endswith('_a_user'):
            updated_metadata['chunks_a'] = len(chunks)
        elif partition_key.endswith('_b_user'):
            updated_metadata['chunks_b'] = len(chunks)
        else:
            # 汎用的な更新
            updated_metadata['chunks_' + hashlib.md5(partition_key.encode()).hexdigest()[:8]] = len(chunks)

        # 共通のchunks数も更新
        updated_metadata['total_chunks'] = max(len(chunks), metadata.get('total_chunks', 0))

        # 更新後のファイルを作成
        updated_file = {
            'metadata': updated_metadata,
            'shares': preserved_shares + new_shares
        }

        # 更新結果をWALに記録
        wal_manager.write_updated_state(wal_path, updated_file)

        # WALをコミット
        wal_manager.commit_wal(wal_path, file_path)

        return (True, updated_file)
    except Exception as e:
        # エラー発生時はロールバック
        wal_manager.rollback_from_wal(wal_path)
        return (False, {"error": str(e)})
    finally:
        # WALをクリーンアップ
        wal_manager.cleanup_wal(wal_path)
```

#### チャンク追跡システムの改善

複数ユーザーのチャンク数を個別に管理するメタデータ構造：

```python
# 改良版メタデータ形式
metadata = {
    'salt': base64_encoded_salt,
    'threshold': threshold,
    'total_chunks': max_chunks,  # 最大チャンク数（互換性のため）
    'chunks_by_key': {
        'hash_of_partition_key_a': chunks_a,
        'hash_of_partition_key_b': chunks_b,
        # 必要に応じて拡張可能
    }
}
```

## 4. 依存関係管理の強化

### 問題の概要

`update.py`モジュールで必要な`base64`モジュールがインポートされていませんでした。

### 解決策

#### 包括的なインポートチェック

各モジュールの先頭に標準的なインポートセットを定義：

```python
# 共通のインポート
import os
import sys
import json
import time
import base64
import hashlib
import secrets
import random
from typing import Dict, List, Tuple, Set, Any, Optional, Union
```

#### インポート検証テスト

```python
def test_imports():
    """各モジュールのインポート動作を検証"""
    modules = [
        'shamir.core',
        'shamir.crypto',
        'shamir.partition',
        'shamir.update',
        'shamir.tests',
        'shamir.app'
    ]

    for module_name in modules:
        try:
            module = __import__(module_name, fromlist=['*'])
            print(f"✓ {module_name} imported successfully")
        except ImportError as e:
            print(f"✗ {module_name}: Import error - {e}")
        except Exception as e:
            print(f"✗ {module_name}: Unexpected error - {e}")
```

## 5. テスト強化およびデバッグ機能

### 包括的なテストケース

```python
def test_full_workflow():
    """完全な暗号化→更新→復号ワークフローのテスト"""
    # テスト用データ
    doc_a = {"user": "A", "message": "Secret A"}
    doc_b = {"user": "B", "message": "Secret B"}

    partition_key_a = "test_partition_key_a"
    partition_key_b = "test_partition_key_b"

    password_a = "password_for_a"
    password_b = "password_for_b"

    # ステップ1: A文書を暗号化
    encrypted_file = encrypt_json_document(doc_a, password_a, partition_key_a)

    # ステップ2: 復号テスト（A）
    decrypted_a = decrypt_json_document(encrypted_file, partition_key_a, password_a)
    assert decrypted_a == doc_a, "A文書の復号に失敗"

    # ステップ3: B文書を追加更新
    updated_file = update_document(encrypted_file, doc_b, password_b, partition_key_b)

    # ステップ4: 更新後のファイルから両方の文書が復号できることを確認
    decrypted_a_after = decrypt_json_document(updated_file, partition_key_a, password_a)
    assert decrypted_a_after == doc_a, "更新後のA文書の復号に失敗"

    decrypted_b = decrypt_json_document(updated_file, partition_key_b, password_b)
    assert decrypted_b == doc_b, "B文書の復号に失敗"

    print("完全なワークフローテストに成功しました")
```

### デバッグモード

システム全体の動作を可視化するデバッグモードを実装：

```python
class ShamirDebug:
    """デバッグユーティリティクラス"""
    ENABLED = False
    LEVEL = 1  # 1=基本, 2=詳細, 3=全て

    @staticmethod
    def log(message, level=1):
        """レベルに応じたログ出力"""
        if ShamirDebug.ENABLED and level <= ShamirDebug.LEVEL:
            print(f"[DEBUG] {message}")

    @staticmethod
    def dump_share_ids(title, ids, max_display=10):
        """シェアIDを出力（最大表示数を制限）"""
        if ShamirDebug.ENABLED and ShamirDebug.LEVEL >= 2:
            if len(ids) <= max_display:
                id_str = ", ".join(str(id) for id in ids)
            else:
                start = ", ".join(str(id) for id in ids[:max_display//2])
                end = ", ".join(str(id) for id in ids[-max_display//2:])
                id_str = f"{start}, ... ({len(ids) - max_display} more) ..., {end}"
            print(f"[DEBUG] {title}: {id_str}")
```

## 結論

上記の解決策を実装することで、シャミア秘密分散法による複数平文復号システムの主要な問題点を解決できます。特に重要なのは：

1. メモリ使用量の大幅な削減
2. MAP 生成ロジックの一貫性向上
3. 複数ユーザー文書の更新操作の安定性確保

これらの改善により、システムはより安定して動作し、実際の環境での利用に適したものになります。実装の際には、各修正が他のコンポーネントに与える影響も考慮し、包括的なテストを行うことが重要です。
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
