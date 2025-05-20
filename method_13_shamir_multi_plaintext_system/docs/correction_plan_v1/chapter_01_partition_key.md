# 問題 1: パーティションキーの本来機能の実装（最高優先度）

## 問題の詳細

パーティションキーは各ユーザーに割り当てられた最大領域を復元するためのキーであり、互いの最大領域に対して不可侵な MAP を毎回同じように生成できるためのキーです。現在の実装では：

1. 同じパーティションキーを使用しても、異なる実行時に異なる MAP 領域が生成される
2. `keys.json`のパーティションキー定義が適切に機能していない
3. 複数ユーザー間でのシェア領域の分離が不完全
4. セキュリティモデルの根幹部分が機能していない

## 修正手順

### 1. 決定論的パーティション分割アルゴリズムの実装

`shamir/partition.py`モジュールを新規作成し、パーティションキーから決定論的なシェア ID 分配を行う機能を実装してください。

```python
# shamir/partition.py

import hashlib
import random
from typing import Set, List, Dict

from .constants import ShamirConstants

def generate_partition_map(partition_key: bytes, share_id_space_size: int, required_shares: int) -> List[int]:
    """
    パーティションキーから決定論的に割り当てられたシェアID空間を生成する

    Args:
        partition_key: パーティションキー（バイト列）
        share_id_space_size: シェアID空間の合計サイズ
        required_shares: 必要なシェア数

    Returns:
        allocated_share_ids: このパーティションに割り当てられたシェアIDのリスト
    """
    # パーティションキーからハッシュ値を生成
    key_hash = hashlib.sha256(partition_key).digest()

    # ハッシュ値を整数に変換し、乱数生成器のシードとして使用
    seed = int.from_bytes(key_hash, byteorder='big')
    rng = random.Random(seed)  # 決定論的な乱数生成器

    # パーティションに割り当てられる最大シェア数を計算
    # （全空間の約30%をこのパーティションに割り当て）
    allocation_ratio = 0.3
    max_allocation = int(share_id_space_size * allocation_ratio)

    if required_shares > max_allocation:
        raise ValueError(
            f"必要なシェア数({required_shares})が割り当て可能なシェア数({max_allocation})を超えています"
        )

    # パーティションが使用可能なシェアID群を生成
    # シェアIDは1から始まる（0は使用しない）
    available_ids = set()

    while len(available_ids) < required_shares:
        # 決定論的に次のIDを選択
        next_id = rng.randint(1, share_id_space_size)
        available_ids.add(next_id)

    # IDのリストを決定論的な順序で返す（毎回同じ順序になるようソート）
    return sorted(list(available_ids))

def analyze_partition_overlap(
    partition_keys: List[bytes],
    share_id_space_size: int = None,
    sample_size: int = 100
) -> Dict[str, float]:
    """
    異なるパーティションキー間のシェア領域の重複を分析する

    Args:
        partition_keys: 分析するパーティションキーのリスト
        share_id_space_size: シェアID空間のサイズ（デフォルトはShamirConstantsから取得）
        sample_size: 各パーティションから生成するシェア数

    Returns:
        結果の辞書。キーはパーティションキーペアのハッシュ、値は重複率（0-1）
    """
    if share_id_space_size is None:
        share_id_space_size = ShamirConstants.SHARE_ID_SPACE

    # 各パーティションキーに対応するシェアIDを生成
    partition_shares = {}

    for key in partition_keys:
        # キーを16進数文字列として表現（ログ出力用）
        key_hex = key.hex()[:8] + "..."

        # このパーティションに割り当てられるシェアIDを生成
        try:
            shares = set(generate_partition_map(key, share_id_space_size, sample_size))
            partition_shares[key_hex] = shares
        except ValueError as e:
            print(f"キー {key_hex} でのシェア生成エラー: {e}")

    # 重複分析
    results = {}

    for i, (key1_hex, shares1) in enumerate(partition_shares.items()):
        for key2_hex, shares2 in list(partition_shares.items())[i+1:]:
            # 重複するシェアIDを計算
            overlap = shares1.intersection(shares2)
            overlap_count = len(overlap)

            # 重複率を計算（0-1の範囲）
            overlap_ratio = overlap_count / sample_size

            # 結果を保存
            pair_key = f"{key1_hex}-{key2_hex}"
            results[pair_key] = overlap_ratio

    return results
```

### 2. `stage1_map`関数の修正

既存の`shamir/core.py`ファイル内の`stage1_map`関数を以下のように修正してください。

```python
# shamir/core.py の修正部分

from .partition import generate_partition_map

def stage1_map(partition_key: str, share_id_space_size: int, required_shares: int) -> List[int]:
    """
    パーティションキーに基づいて、シャミア秘密分散法で使用するシェアIDを決定論的に選択する

    Args:
        partition_key: パーティションキー（文字列）
        share_id_space_size: シェアID空間の合計サイズ
        required_shares: 必要なシェア数（例：閾値など）

    Returns:
        selected_share_ids: 選択されたシェアIDのリスト
    """
    # 文字列キーをバイト列に変換
    key_bytes = partition_key.encode('utf-8') if isinstance(partition_key, str) else partition_key

    # パーティションキーに基づいて利用可能なシェアID空間を取得
    available_ids = generate_partition_map(key_bytes, share_id_space_size)

    # シード値を固定して決定論的選択を保証
    seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), byteorder='big')
    random.seed(seed)

    # 利用可能なIDから必要数を決定論的に選択
    if len(available_ids) < required_shares:
        raise ValueError(f"利用可能なシェアIDが不足しています: {len(available_ids)} < {required_shares}")

    # リストに変換してソートすることで、選択の順序を固定
    available_ids_list = sorted(list(available_ids))
    selected_indices = random.sample(range(len(available_ids_list)), required_shares)
    selected_share_ids = [available_ids_list[i] for i in selected_indices]

    return selected_share_ids
```

### 3. パーティションキー管理クラスの実装

パーティションキーを適切に管理するためのクラスを`shamir/key_management.py`に実装してください。

```python
# shamir/key_management.py

import base64
import json
import hashlib
from typing import Dict, Any, List, Set
import os

class PartitionKeyManager:
    """パーティションキー管理クラス"""

    def __init__(self, keys_file: str = "keys.json"):
        self.keys_file = keys_file
        self.partition_keys = {}
        self.partition_cache = {}  # キャッシュによるパフォーマンス向上

        if os.path.exists(keys_file):
            self.load_keys()

    def load_keys(self) -> Dict[str, bytes]:
        """
        キーファイルからパーティションキーを読み込む

        Returns:
            パーティションキー辞書 {user_id: partition_key_bytes, ...}
        """
        try:
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)

            for user_id, key_data in keys_data.items():
                # Base64エンコードされたキーをバイト列に変換
                if isinstance(key_data, dict) and "partition_key" in key_data:
                    self.partition_keys[user_id] = base64.b64decode(key_data["partition_key"])
                elif isinstance(key_data, str):
                    # 直接文字列が格納されているケースも処理
                    self.partition_keys[user_id] = base64.b64decode(key_data)

            return self.partition_keys
        except Exception as e:
            print(f"キーファイルの読み込み中にエラーが発生しました: {e}")
            return {}

    def save_keys(self) -> bool:
        """
        パーティションキーをファイルに保存

        Returns:
            保存が成功したかどうか
        """
        try:
            keys_data = {}
            for user_id, key_bytes in self.partition_keys.items():
                # バイト列をBase64エンコード
                keys_data[user_id] = {
                    "partition_key": base64.b64encode(key_bytes).decode('utf-8')
                }

            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=2)

            return True
        except Exception as e:
            print(f"キーファイルの保存中にエラーが発生しました: {e}")
            return False

    def generate_key(self, user_id: str, key_size: int = 32) -> bytes:
        """
        新しいパーティションキーを生成

        Args:
            user_id: ユーザーID
            key_size: キーサイズ（バイト単位、デフォルトは32バイト/256ビット）

        Returns:
            生成されたパーティションキー
        """
        # 安全な乱数でキー生成
        key_bytes = os.urandom(key_size)
        self.partition_keys[user_id] = key_bytes
        self.save_keys()
        return key_bytes

    def get_key(self, user_id: str) -> bytes:
        """
        ユーザーIDからパーティションキーを取得

        Args:
            user_id: ユーザーID

        Returns:
            パーティションキー（バイト列）
        """
        if user_id not in self.partition_keys:
            raise KeyError(f"パーティションキーが見つかりません: {user_id}")

        return self.partition_keys[user_id]
```

### 4. 既存のコードを修正して新機能を統合

以下のファイルを修正して、新しいパーティションキー機能を統合します。

#### crypto.py の修正

```python
# shamir/crypto.py の修正部分

from .partition import generate_partition_map
from .key_management import PartitionKeyManager

# パーティションキーマネージャのインスタンス
key_manager = PartitionKeyManager()

def encrypt_json_document(json_doc, password, partition_key):
    """
    JSONドキュメントを暗号化

    修正: パーティションキーの処理部分
    """
    # パーティションキーをバイト列に変換
    if isinstance(partition_key, str):
        # 管理されたキーを取得するか、文字列をそのままバイト列に変換
        try:
            # ユーザーIDとしてキーを検索
            key_bytes = key_manager.get_key(partition_key)
        except KeyError:
            # 直接文字列をバイト列に変換
            key_bytes = partition_key.encode('utf-8')
    else:
        key_bytes = partition_key  # すでにバイト列

    # 決定論的に対象シェアIDを選択
    target_share_ids = stage1_map(key_bytes, ShamirConstants.SHARE_ID_SPACE, threshold)

    # 以下は既存のコードを継続...
```

#### update.py の修正

```python
# shamir/update.py の修正部分

from .partition import generate_partition_map
from .key_management import PartitionKeyManager

# パーティションキーマネージャのインスタンス
key_manager = PartitionKeyManager()

def update_document(encrypted_file, json_doc, password, partition_key):
    """
    暗号化ファイルにJSONドキュメントを追加更新

    修正: パーティションキーの処理部分
    """
    # パーティションキーをバイト列に変換 (crypto.pyと同様の処理)
    if isinstance(partition_key, str):
        try:
            key_bytes = key_manager.get_key(partition_key)
        except KeyError:
            key_bytes = partition_key.encode('utf-8')
    else:
        key_bytes = partition_key

    # メタデータを取得
    metadata = encrypted_file['metadata']

    # 全シェアを取得
    all_shares = encrypted_file['shares']
    all_share_ids = set(share['share_id'] for share in all_shares)

    # ステップ1: 更新対象のシェアを決定論的に特定
    target_share_ids = stage1_map(key_bytes, ShamirConstants.SHARE_ID_SPACE, metadata['threshold'])

    # ステップ2: 対象シェアを新しい内容で置き換え (既存シェアは保持)
    preserved_shares = [s for s in all_shares if s['share_id'] not in target_share_ids]

    # 以下は既存のコードを継続...
```

### 5. CLI インターフェースの更新

`shamir/cli.py`を修正し、パーティションキーを適切に処理できるようにします。

```python
# shamir/cli.py の修正部分

from .key_management import PartitionKeyManager

# パーティションキーマネージャのインスタンス
key_manager = PartitionKeyManager()

def encrypt_command(args):
    """
    暗号化コマンド

    修正: パーティションキーの処理
    """
    # ファイルからJSONを読み込み
    with open(args.input, 'r') as f:
        json_doc = json.load(f)

    # パーティションキーの処理
    partition_key = args.partition_key

    # ユーザーIDが指定された場合はキーマネージャから取得
    if args.user_id:
        try:
            partition_key = key_manager.get_key(args.user_id)
        except KeyError:
            # ユーザーIDが存在しない場合は新規キーを生成
            print(f"新しいパーティションキーを生成: {args.user_id}")
            partition_key = key_manager.generate_key(args.user_id)

    # 暗号化を実行
    encrypted = encrypt_json_document(json_doc, args.password, partition_key)

    # 暗号化ファイルを保存
    with open(args.output, 'w') as f:
        json.dump(encrypted, f, indent=2)

    print(f"暗号化完了: {args.output}")

# 他のコマンドも同様に修正
```

### 6. 設定ファイルでの定数定義

`shamir/constants.py`を修正または作成し、必要な定数を定義します。

```python
# shamir/constants.py

class ShamirConstants:
    """シャミア秘密分散システムの定数"""

    # シェアID空間サイズ (修正: 適切なサイズに縮小)
    SHARE_ID_SPACE = 10000

    # 大きな素数 (2^256 - 189)
    PRIME = 2**256 - 189

    # 各チャンクのバイトサイズ
    CHUNK_SIZE = 32

    # パーティション割り当て率
    # 各パーティションには全空間の何%を割り当てるか
    PARTITION_ALLOCATION_RATIO = 0.3

    # 閾値のデフォルト値
    DEFAULT_THRESHOLD = 3
```

## 検証方法

この修正が正しく実装されていることを確認するため、以下のテストを実施してください。

### パーティションキー機能のテスト

```python
# tests/test_partition.py

import pytest
from shamir.partition import generate_partition_map
from shamir.core import stage1_map
from shamir.constants import ShamirConstants

def test_partition_map_deterministic():
    """同じパーティションキーで常に同じ領域が生成されることをテスト"""
    partition_key = b"test_partition_key"

    # 同じキーで2回実行
    ids1 = generate_partition_map(partition_key, ShamirConstants.SHARE_ID_SPACE)
    ids2 = generate_partition_map(partition_key, ShamirConstants.SHARE_ID_SPACE)

    # 結果が同一であることを確認
    assert ids1 == ids2, "同じパーティションキーなのに異なる領域が生成されました"

def test_stage1_map_deterministic():
    """stage1_map関数の決定論的な動作をテスト"""
    partition_key = b"test_partition_key"
    required_shares = 5

    # 同じキーで複数回実行
    result1 = stage1_map(partition_key, ShamirConstants.SHARE_ID_SPACE, required_shares)
    result2 = stage1_map(partition_key, ShamirConstants.SHARE_ID_SPACE, required_shares)

    # 結果が同一であることを確認
    assert result1 == result2, "stage1_mapが非決定論的です"

    # 必要な数のシェアが返されていることを確認
    assert len(result1) == required_shares, "要求されたシェア数と異なります"

def test_different_partition_keys():
    """異なるパーティションキーは異なる領域を生成することをテスト"""
    key1 = b"partition_key_1"
    key2 = b"partition_key_2"

    ids1 = generate_partition_map(key1, ShamirConstants.SHARE_ID_SPACE)
    ids2 = generate_partition_map(key2, ShamirConstants.SHARE_ID_SPACE)

    # 完全に一致しないことを確認
    assert ids1 != ids2, "異なるパーティションキーなのに同じ領域が生成されました"

    # ある程度の重複は許容されるが、大部分は異なるべき
    overlap = len(ids1.intersection(ids2))
    overlap_ratio = overlap / len(ids1)

    # 重複率が50%未満であることを確認（理論的には約30%程度の重複が期待される）
    assert overlap_ratio < 0.5, f"重複率が高すぎます: {overlap_ratio:.2f}"
```

## 期待される成果

この修正により、以下の成果が期待されます：

1. 同じパーティションキーを使用すれば、異なる実行時でも常に同じシェア ID が選択される
2. 異なるパーティション間でのデータ分離が適切に維持される
3. 複数ユーザーが同じファイルで暗号化/更新操作を行っても、相互のデータが保護される
4. キー管理が容易になり、ユーザー ID からパーティションキーへのマッピングが明確になる

これらの修正はシステムの信頼性と安全性の基盤を形成します。
