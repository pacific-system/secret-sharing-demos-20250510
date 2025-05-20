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

## 5. パーティションキーの本来機能の実装

### 問題の概要

パーティションキーは割り当てられた最大領域を復元するためのキーであり、互いの最大領域に対して不可侵な MAP を常に同じように生成できる機能が必要ですが、現状では正しく実装されていません。

### 解決策

#### 1. 決定論的パーティション空間分割

```python
def generate_partition_space(partition_key: str, share_id_space: int) -> List[int]:
    """
    パーティションキーから決定論的に固定された領域を生成

    Args:
        partition_key: パーティションキー
        share_id_space: 全シェアID空間サイズ

    Returns:
        パーティションに割り当てられたシェアIDのリスト
    """
    # パーティションキーからシード値を決定論的に生成
    key_bytes = partition_key.encode('ascii')
    seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')

    # シェアID空間全体を生成（メモリ効率のため範囲オブジェクトを使用）
    all_ids = range(1, share_id_space + 1)

    # パーティションの割合に応じた選択数を計算
    # ※各パーティションキーは固有の比率を持つことも可能
    if 'a_key' in partition_key:
        ratio = ShamirConstants.RATIO_A
    elif 'b_key' in partition_key:
        ratio = ShamirConstants.RATIO_B
    else:
        # デフォルトは均等割り当て
        ratio = 0.3

    selection_count = int(share_id_space * ratio)

    # シード値を使って決定論的にIDをシャッフルし選択
    # ハッシュベースの選択で常に同じ結果を保証
    selected_ids = []
    for id in all_ids:
        # 各IDに対して決定論的なハッシュを計算
        # パーティションキーとIDを組み合わせて一意性を確保
        hash_input = f"{partition_key}:{id}".encode()
        hash_value = hashlib.sha256(hash_input).digest()
        score = int.from_bytes(hash_value, 'big')
        selected_ids.append((id, score))

    # スコアでソートし、上位のIDを選択
    selected_ids.sort(key=lambda x: x[1])
    return [id for id, _ in selected_ids[:selection_count]]
```

#### 2. パーティション重複回避システム

複数のパーティションキーが同じシェア ID を選択しないようにする機構：

```python
def create_non_overlapping_partitions(partition_keys: List[str], share_id_space: int) -> Dict[str, List[int]]:
    """
    互いに重複しないパーティション空間を生成

    Args:
        partition_keys: パーティションキーのリスト
        share_id_space: 全シェアID空間サイズ

    Returns:
        {パーティションキー: 割り当てられたシェアIDのリスト}
    """
    # 全シェアIDのリスト
    all_ids = set(range(1, share_id_space + 1))

    # 各パーティションキーごとに一意のハッシュ値を計算
    key_hashes = []
    for key in partition_keys:
        key_bytes = key.encode()
        hash_value = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')
        key_hashes.append((key, hash_value))

    # ハッシュ値でソート（決定論的な順序を確保）
    key_hashes.sort(key=lambda x: x[1])

    # 各パーティションの割り当て範囲を計算
    result = {}
    remaining_ids = all_ids

    for i, (key, _) in enumerate(key_hashes):
        # 最後のパーティションは残りすべてを取得
        if i == len(key_hashes) - 1:
            result[key] = list(remaining_ids)
            break

        # パーティションの割合を計算（均等または指定された比率）
        if len(key_hashes) > 1:
            # 先に処理されたパーティションの方が優先度が高い
            ratio = 1.0 / (len(key_hashes) - i)
        else:
            ratio = 1.0

        # 割り当てるID数を計算
        count = int(len(remaining_ids) * ratio)

        # IDをソートして決定論的に選択
        sorted_ids = sorted(remaining_ids)
        selected = sorted_ids[:count]

        result[key] = selected
        remaining_ids -= set(selected)

    return result
```

#### 3. パーティションキー管理システム

```python
class PartitionKeyManager:
    """パーティションキー管理クラス"""

    def __init__(self, share_id_space: int = ShamirConstants.SHARE_ID_SPACE):
        self.share_id_space = share_id_space
        self.partition_cache = {}  # キャッシュによるパフォーマンス向上

    def get_partition_ids(self, partition_key: str) -> List[int]:
        """
        パーティションキーに対応するシェアIDを取得

        Args:
            partition_key: パーティションキー

        Returns:
            シェアIDのリスト
        """
        # キャッシュがあれば利用
        if partition_key in self.partition_cache:
            return self.partition_cache[partition_key]

        # 新たに計算
        partition_ids = generate_partition_space(partition_key, self.share_id_space)

        # キャッシュに保存
        self.partition_cache[partition_key] = partition_ids

        return partition_ids

    def verify_non_overlapping(self, key1: str, key2: str) -> bool:
        """
        2つのパーティションキーが重複しないことを検証

        Args:
            key1: 1つ目のパーティションキー
            key2: 2つ目のパーティションキー

        Returns:
            重複がなければTrue、あればFalse
        """
        ids1 = self.get_partition_ids(key1)
        ids2 = self.get_partition_ids(key2)

        # 共通要素がないか確認
        return len(set(ids1).intersection(set(ids2))) == 0
```

## 6. 暗号化ファイル形式の最適化

### 問題の概要

暗号化ファイル構造に冗長なメタデータ（chunk_index、share_id など）が含まれており、効率的ではありません。

### 解決策

#### 1. 位置ベースの暗号化ファイル形式

```python
def optimize_encrypted_file_format(encrypted_file: Dict[str, Any]) -> Dict[str, Any]:
    """
    暗号化ファイル形式を最適化

    Args:
        encrypted_file: 現在の暗号化ファイル

    Returns:
        最適化された暗号化ファイル
    """
    # 必要なメタデータのみを保持
    optimized_metadata = {
        'salt': encrypted_file['metadata']['salt'],
        'threshold': encrypted_file['metadata']['threshold'],
        'chunk_count': encrypted_file['metadata']['total_chunks'],
    }

    # シェアを位置ベースのマップに変換
    # 各シェアは対応する位置だけで特定され、metadata不要
    shares_map = {}

    for share in encrypted_file['shares']:
        # シェアIDをMAP位置に変換
        # パーティションキーとパスワードで復号時に同じ位置が計算される
        share_id = share['share_id']
        chunk_idx = share['chunk_index']
        value = share['value']

        position_key = f"{chunk_idx}_{share_id}"
        shares_map[position_key] = value

    # 最適化されたファイル形式
    optimized_file = {
        'metadata': optimized_metadata,
        'shares_map': shares_map
    }

    return optimized_file
```

#### 2. 位置ベースの復号機構

```python
def decrypt_from_optimized_format(
    optimized_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> Any:
    """
    最適化形式から復号

    Args:
        optimized_file: 最適化された暗号化ファイル
        partition_key: パーティションキー
        password: パスワード

    Returns:
        復号されたJSONドキュメント
    """
    # メタデータを取得
    metadata = optimized_file['metadata']
    salt = base64.urlsafe_b64decode(metadata['salt'])
    threshold = metadata['threshold']
    chunk_count = metadata['chunk_count']

    # パーティションキーから対象のシェアIDを取得
    partition_manager = PartitionKeyManager()
    share_ids = partition_manager.get_partition_ids(partition_key)

    # パスワードから第2段階MAPを生成
    stage2_map = generate_password_map(password, salt, share_ids)

    # 各チャンクに対して閾値分のシェアを選択
    reconstructed_chunks = []

    for chunk_idx in range(chunk_count):
        # マッピング値でソートして上位threshold個を選択
        sorted_ids = sorted(share_ids, key=lambda id: stage2_map.get(id, float('inf')))
        selected_ids = sorted_ids[:threshold]

        # 選択されたシェアを収集
        shares = []
        for share_id in selected_ids:
            position_key = f"{chunk_idx}_{share_id}"
            if position_key in optimized_file['shares_map']:
                value = optimized_file['shares_map'][position_key]
                shares.append((share_id, mpz(value)))

        # 閾値分のシェアがあれば秘密を復元
        if len(shares) >= threshold:
            secret = lagrange_interpolation(shares, ShamirConstants.PRIME)
            # 秘密から元のチャンクバイトに変換
            chunk_bytes = int_to_bytes(secret, ShamirConstants.CHUNK_SIZE)
            reconstructed_chunks.append(chunk_bytes)

    # 全チャンクからドキュメントを復元
    return postprocess_chunks_to_json(reconstructed_chunks)
```

#### 3. ファイルサイズの比較検証関数

```python
def compare_file_formats(json_doc: Any, partition_key: str, password: str) -> Dict[str, int]:
    """
    標準形式と最適化形式のファイルサイズを比較

    Args:
        json_doc: 暗号化するJSONドキュメント
        partition_key: パーティションキー
        password: パスワード

    Returns:
        サイズ比較結果
    """
    # 標準形式で暗号化
    standard_file = encrypt_json_document(json_doc, password, partition_key)
    standard_json = json.dumps(standard_file)

    # 最適化形式に変換
    optimized_file = optimize_encrypted_file_format(standard_file)
    optimized_json = json.dumps(optimized_file)

    # サイズを比較
    standard_size = len(standard_json.encode('utf-8'))
    optimized_size = len(optimized_json.encode('utf-8'))
    size_reduction = standard_size - optimized_size
    reduction_percent = (size_reduction / standard_size) * 100

    return {
        'standard_size_bytes': standard_size,
        'optimized_size_bytes': optimized_size,
        'size_reduction_bytes': size_reduction,
        'reduction_percent': reduction_percent
    }
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

1. パーティションキーの本来機能の実装による領域分離の確立
2. メモリ使用量の大幅な削減
3. MAP 生成ロジックの一貫性向上
4. 複数ユーザー文書の更新操作の安定性確保
5. 暗号化ファイル形式の最適化による効率向上

これらの改善により、システムはより安定して動作し、理論設計に忠実な実装となり、実際の環境での利用に適したものになります。実装の際には、各修正が他のコンポーネントに与える影響も考慮し、包括的なテストを行うことが重要です。
