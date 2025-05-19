## システムの初期化

システムの初期化部分では、パーティション空間の設定、パーティションマップキーの生成、そしてシステム全体のセットアップを行います。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `02_architecture.md`: パーティション空間の基本設計原則
- `03_detailed_design.md`: パーティション空間の詳細設計
- `04_implementation.md`: 実装詳細とシステムの初期化方法
- `07_guidelines.md`: 安全なパーティション空間管理の実装ガイドライン

### 1. 必要なライブラリとパッケージ

```python
# 暗号関連の基本ライブラリ
import os
import secrets
import hashlib
import hmac
import json
import base64
import zlib
from typing import Dict, List, Tuple, Set, Union, Any, Optional
import uuid
import time
import fcntl
import shutil
from pathlib import Path

# 大きな整数演算のためのライブラリ
import gmpy2
from gmpy2 import mpz

# 暗号ライブラリ
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
```

### 2. システム定数の定義

```python
class ShamirConstants:
    """システム全体で使用する定数"""
    # 有限体の素数 (2^521 - 1)
    PRIME = mpz(2**521 - 1)

    # 閾値（最小復元シェア数）
    DEFAULT_THRESHOLD = 3

    # チャンクサイズ（バイト単位）
    CHUNK_SIZE = 64

    # KDF設定
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_TIME_COST = 3
    ARGON2_PARALLELISM = 4
    ARGON2_OUTPUT_LENGTH = 32

    # パーティション比率
    RATIO_A = 0.35  # Aユーザー用（35%）
    RATIO_B = 0.35  # Bユーザー用（35%）
    RATIO_UNASSIGNED = 0.30  # 未割当（30%）

    # シェアID空間サイズ
    SHARE_ID_SPACE = 2**32 - 1

    # WALログのタイムアウト（秒）
    WAL_TIMEOUT = 3600  # 1時間

    # テンポラリファイルのプレフィックス
    TEMP_FILE_PREFIX = "shamir_temp_"
```

### 3. パーティションマップキーの生成

```python
def generate_partition_map_key(length: int = 32) -> str:
    """
    パーティションマップキーを生成する

    Args:
        length: 生成するキーの長さ（バイト）

    Returns:
        base64エンコードされたパーティションマップキー
    """
    # 暗号論的に安全な乱数を生成
    random_bytes = secrets.token_bytes(length)

    # 読みやすいBase64文字列に変換（URL安全版）
    map_key = base64.urlsafe_b64encode(random_bytes).decode('ascii')

    return map_key
```

### 4. パーティション空間の管理

```python
class PartitionManager:
    """パーティション空間を管理するクラス"""

    def __init__(self,
                 partition_a_key: str,
                 partition_b_key: str,
                 total_shares: int = 1000):
        """
        パーティションマネージャーを初期化

        Args:
            partition_a_key: Aユーザー用パーティションマップキー
            partition_b_key: Bユーザー用パーティションマップキー
            total_shares: 生成する総シェア数
        """
        self.partition_a_key = partition_a_key
        self.partition_b_key = partition_b_key
        self.total_shares = total_shares

        # 各パーティションのシェア数を計算
        self.a_shares_count = int(total_shares * ShamirConstants.RATIO_A)
        self.b_shares_count = int(total_shares * ShamirConstants.RATIO_B)
        self.unassigned_count = total_shares - self.a_shares_count - self.b_shares_count

        # シェアIDを生成
        self.all_share_ids = self._generate_all_share_ids()
        self.a_share_ids = self._map_partition_ids(partition_a_key, self.a_shares_count)
        self.b_share_ids = self._map_partition_ids(partition_b_key, self.b_shares_count)

        # 未割当IDを計算（AとBに割り当てられていないID）
        self.unassigned_ids = self._calculate_unassigned_ids()

    def _generate_all_share_ids(self) -> List[int]:
        """全シェアIDを生成（1からSHARE_ID_SPACE間の一意な値）"""
        ids = set()
        while len(ids) < self.total_shares:
            new_id = secrets.randbelow(ShamirConstants.SHARE_ID_SPACE - 1) + 1
            ids.add(new_id)
        return sorted(list(ids))

    def _map_partition_ids(self, partition_key: str, count: int) -> List[int]:
        """
        パーティションマップキーからシェアIDを決定論的に生成

        Args:
            partition_key: パーティションマップキー
            count: 生成するID数

        Returns:
            シェアIDのリスト
        """
        # パーティションマップキーから決定論的にシード値を生成
        key_bytes = partition_key.encode('ascii')
        seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')

        # シードから擬似乱数を生成（暗号論的に安全でなくてもよい）
        import random
        rng = random.Random(seed)

        # 全シェアIDからランダムにcount個選択
        selected_ids = sorted(rng.sample(self.all_share_ids, count))
        return selected_ids

    def _calculate_unassigned_ids(self) -> List[int]:
        """未割当IDを計算（AともBとも異なるID）"""
        a_set = set(self.a_share_ids)
        b_set = set(self.b_share_ids)
        all_set = set(self.all_share_ids)

        # 差集合で計算
        unassigned = all_set - a_set - b_set
        return sorted(list(unassigned))

    def get_partition_ids(self, partition_key: str) -> List[int]:
        """
        パーティションマップキーに対応するシェアIDを取得

        Args:
            partition_key: パーティションマップキー

        Returns:
            シェアIDのリスト
        """
        if partition_key == self.partition_a_key:
            return self.a_share_ids
        elif partition_key == self.partition_b_key:
            return self.b_share_ids
        else:
            # 対応するIDが見つからない場合は空リストを返す
            return []
```

### 5. 統計的区別不可能性の検証

```python
def verify_statistical_indistinguishability(
    a_ids: List[int],
    b_ids: List[int],
    unassigned_ids: List[int]
) -> bool:
    """
    パーティション空間の統計的区別不可能性を検証

    Args:
        a_ids: Aユーザー用IDリスト
        b_ids: Bユーザー用IDリスト
        unassigned_ids: 未割当IDリスト

    Returns:
        検証結果（True: 問題なし、False: 偏りあり）
    """
    # 全IDを結合してソート
    all_ids = sorted(a_ids + b_ids + unassigned_ids)
    total_count = len(all_ids)

    # ブロックサイズの決定（全体の約5%）
    block_size = max(10, total_count // 20)

    # 各ブロック内でのA, B, 未割当の比率を検証
    for start in range(0, total_count, block_size):
        end = min(start + block_size, total_count)
        block = all_ids[start:end]

        # ブロック内の各タイプのカウント
        a_count = sum(1 for id in block if id in a_ids)
        b_count = sum(1 for id in block if id in b_ids)
        u_count = sum(1 for id in block if id in unassigned_ids)

        # 各タイプの比率を計算
        block_total = len(block)
        a_ratio = a_count / block_total
        b_ratio = b_count / block_total
        u_ratio = u_count / block_total

        # 比率の許容範囲（±10%ポイント）
        if (abs(a_ratio - ShamirConstants.RATIO_A) > 0.1 or
            abs(b_ratio - ShamirConstants.RATIO_B) > 0.1 or
            abs(u_ratio - ShamirConstants.RATIO_UNASSIGNED) > 0.1):
            return False

    return True
```

### 6. システム初期化関数

```python
def initialize_system() -> Dict[str, Any]:
    """
    シャミア秘密分散システムを初期化し、必要なキーと設定を返す

    Returns:
        システム初期化情報を含む辞書
    """
    # パーティションマップキーを生成
    partition_a_key = generate_partition_map_key()
    partition_b_key = generate_partition_map_key()

    # パーティションマネージャーを初期化
    partition_manager = PartitionManager(
        partition_a_key=partition_a_key,
        partition_b_key=partition_b_key,
        total_shares=1000  # 総シェア数
    )

    # 統計的区別不可能性を検証
    is_indistinguishable = verify_statistical_indistinguishability(
        partition_manager.a_share_ids,
        partition_manager.b_share_ids,
        partition_manager.unassigned_ids
    )

    # 検証に失敗した場合は再初期化
    retry_count = 0
    while not is_indistinguishable and retry_count < 5:
        partition_manager = PartitionManager(
            partition_a_key=partition_a_key,
            partition_b_key=partition_b_key,
            total_shares=1000
        )
        is_indistinguishable = verify_statistical_indistinguishability(
            partition_manager.a_share_ids,
            partition_manager.b_share_ids,
            partition_manager.unassigned_ids
        )
        retry_count += 1

    if not is_indistinguishable:
        raise ValueError("統計的区別不可能性の検証に失敗しました。システム初期化をやり直してください。")

    # システム設定を辞書にまとめて返す
    return {
        "partition_a_key": partition_a_key,
        "partition_b_key": partition_b_key,
        "threshold": ShamirConstants.DEFAULT_THRESHOLD,
        "total_shares": partition_manager.total_shares,
        "a_share_count": partition_manager.a_shares_count,
        "b_share_count": partition_manager.b_shares_count,
        "unassigned_count": partition_manager.unassigned_count,
        "initialized_at": int(time.time())
    }
```
