# 問題 4: シェア ID 空間サイズの最適化（中優先度）

## 問題の詳細

元の実装では`SHARE_ID_SPACE = 2**32 - 1`（約 43 億）という大きなシェア ID 空間を使用していました。これにより、実行時にメモリ消費が過大になり、プログラムが強制終了する問題が発生していました。現在の問題は：

1. メモリ使用量の急激な増加によるプロセスの強制終了
2. 大きすぎるシェア ID 空間によるパフォーマンスの低下
3. 実際のセキュリティニーズと必要なシェア数のミスマッチ

## 修正手順

### 1. 適切なシェア ID 空間サイズの定義

`shamir/constants.py`を修正し、適切なサイズを定義します。

```python
# shamir/constants.py の修正部分

class ShamirConstants:
    """シャミア秘密分散システムの定数"""

    # シェアID空間サイズの定義（修正）
    # 43億（2^32-1）から1万に縮小
    SHARE_ID_SPACE = 10000

    # セキュリティレベルに応じたシェアID空間サイズ
    SHARE_ID_SPACE_LOW = 1000       # 開発/テスト用
    SHARE_ID_SPACE_STANDARD = 10000 # 一般用途
    SHARE_ID_SPACE_HIGH = 100000    # 高セキュリティ用

    # 閾値のデフォルト値
    DEFAULT_THRESHOLD = 3

    # 大きな素数（2^256 - 189）
    PRIME = 2**256 - 189

    # チャンクサイズ（バイト）
    CHUNK_SIZE = 32
```

### 2. メモリ効率の良い ID 生成機能の実装

全 ID をメモリに保持せず、効率的に生成する関数を実装します。

```python
# shamir/share_id.py を新規作成

import random
import hashlib
from typing import List, Set, Dict
from .constants import ShamirConstants

def generate_share_ids(seed: bytes, count: int, max_id: int = None) -> List[int]:
    """
    シード値から決定論的にシェアIDを生成する（メモリ効率の良い実装）

    Args:
        seed: シード値（バイト列）
        count: 生成するID数
        max_id: 最大ID値（デフォルトはSHARE_ID_SPACE）

    Returns:
        シェアIDのリスト
    """
    if max_id is None:
        max_id = ShamirConstants.SHARE_ID_SPACE

    if count > max_id:
        raise ValueError(f"要求されたID数({count})が最大ID({max_id})を超えています")

    # シード値からPRNGを初期化
    seed_int = int.from_bytes(seed, byteorder='big')
    rng = random.Random(seed_int)

    # 効率的なID生成（全空間を保持せず、必要な数だけ生成）
    share_ids = set()

    while len(share_ids) < count:
        new_id = rng.randint(1, max_id)  # 1から始める（0は使わない）
        share_ids.add(new_id)

    return sorted(list(share_ids))  # ソートして決定論的な順序を確保
```

### 3. 動的なシェア ID 空間サイズの実装

セキュリティレベルに応じてシェア ID 空間サイズを調整できる機能を実装します。

```python
# shamir/share_id.py に追加

def determine_share_id_space_size(security_level: str = 'standard') -> int:
    """
    セキュリティレベルに基づいて適切なシェアID空間サイズを決定

    Args:
        security_level: セキュリティレベル ('low', 'standard', 'high')

    Returns:
        シェアID空間サイズ
    """
    if security_level.lower() == 'low':
        return ShamirConstants.SHARE_ID_SPACE_LOW
    elif security_level.lower() == 'high':
        return ShamirConstants.SHARE_ID_SPACE_HIGH
    else:  # 'standard' または不明な値
        return ShamirConstants.SHARE_ID_SPACE_STANDARD

def check_share_id_collisions(partition_keys: List[bytes], share_id_space_size: int = None) -> Dict[tuple, float]:
    """
    複数のパーティションキー間のシェアID衝突を分析

    Args:
        partition_keys: パーティションキーのリスト
        share_id_space_size: シェアID空間サイズ

    Returns:
        {(key1, key2): collision_ratio, ...} 形式の衝突率辞書
    """
    if share_id_space_size is None:
        share_id_space_size = ShamirConstants.SHARE_ID_SPACE

    # 各パーティションキーのシェア領域を生成
    key_shares = {}
    for key in partition_keys:
        # パーティションキーから領域を生成（30%割り当て）
        allocation_size = int(share_id_space_size * 0.3)
        key_shares[key] = set(generate_share_ids(key, allocation_size, share_id_space_size))

    # パーティションキーのペアごとに衝突率を計算
    collisions = {}
    for i, key1 in enumerate(partition_keys):
        for key2 in partition_keys[i+1:]:
            # 重複するシェアIDの数
            intersection = key_shares[key1].intersection(key_shares[key2])
            # 衝突率 = 重複数 / 割り当て平均
            average_size = (len(key_shares[key1]) + len(key_shares[key2])) / 2
            collision_ratio = len(intersection) / average_size if average_size > 0 else 0

            collisions[(key1, key2)] = collision_ratio

    return collisions
```

### 4. 既存機能をメモリ効率の良い実装に修正

`core.py`のステージ 1 マップ生成関数を、メモリ効率の良い実装に置き換えます。

```python
# shamir/core.py の修正部分

from .share_id import generate_share_ids

def stage1_map(partition_key: bytes, share_id_space_size: int, required_shares: int) -> List[int]:
    """
    パーティションキーに基づいてシェアIDを選択する（メモリ効率の良い実装）

    Args:
        partition_key: パーティションキー
        share_id_space_size: シェアID空間のサイズ
        required_shares: 必要なシェア数

    Returns:
        選択されたシェアIDのリスト
    """
    # パーティションキーに基づいて割り当て可能なシェアID数を計算
    allocation_ratio = 0.3  # 30%割り当て
    allocation_size = int(share_id_space_size * allocation_ratio)

    # 必要なシェア数が割り当て数を超えていないか確認
    if required_shares > allocation_size:
        raise ValueError(f"必要なシェア数({required_shares})が割り当て可能なシェア数({allocation_size})を超えています")

    # 効率的なID生成（メモリを大量に使わない）
    return generate_share_ids(partition_key, required_shares, share_id_space_size)
```

### 5. パフォーマンス監視とデバッグ機能の追加

システムのメモリ使用量とパフォーマンスを監視する機能を実装します。

```python
# shamir/performance.py を新規作成

import time
import os
import psutil
import gc
from typing import Dict, Any, Callable, List, Tuple

class PerformanceMonitor:
    """パフォーマンスとメモリ使用量の監視クラス"""

    @staticmethod
    def get_memory_usage() -> Dict[str, float]:
        """
        現在のプロセスのメモリ使用量を取得

        Returns:
            メモリ使用量の情報（MB単位）
        """
        # 現在のプロセスの情報を取得
        process = psutil.Process(os.getpid())

        # メモリ使用量の取得
        memory_info = process.memory_info()

        return {
            'rss_mb': memory_info.rss / (1024 * 1024),  # 常駐セットサイズ（MB）
            'vms_mb': memory_info.vms / (1024 * 1024),  # 仮想メモリサイズ（MB）
        }

    @staticmethod
    def measure_performance(func: Callable, *args, **kwargs) -> Tuple[Any, Dict[str, float]]:
        """
        関数のパフォーマンスを測定

        Args:
            func: 測定する関数
            *args, **kwargs: 関数の引数

        Returns:
            (関数の戻り値, パフォーマンス指標)
        """
        # GCを実行してメモリ状態をクリーンに
        gc.collect()

        # 開始時のメモリと時間を記録
        start_memory = PerformanceMonitor.get_memory_usage()
        start_time = time.time()

        # 関数を実行
        result = func(*args, **kwargs)

        # 終了時のメモリと時間を記録
        end_time = time.time()
        gc.collect()  # 測定前にGCを実行
        end_memory = PerformanceMonitor.get_memory_usage()

        # パフォーマンス指標を計算
        performance = {
            'execution_time_sec': end_time - start_time,
            'memory_increase_rss_mb': end_memory['rss_mb'] - start_memory['rss_mb'],
            'memory_increase_vms_mb': end_memory['vms_mb'] - start_memory['vms_mb'],
            'final_rss_mb': end_memory['rss_mb'],
            'final_vms_mb': end_memory['vms_mb'],
        }

        return result, performance
```

### 6. コマンドラインインターフェイスの拡張

シェア ID 空間サイズを設定できるように CLI オプションを追加します。

```python
# shamir/cli.py の修正部分

from .share_id import determine_share_id_space_size

def setup_common_args(parser):
    """共通の引数設定"""
    # 既存の引数に加えて
    parser.add_argument('--security-level', choices=['low', 'standard', 'high'],
                        default='standard',
                        help='セキュリティレベル（シェアID空間のサイズに影響）')
    parser.add_argument('--share-id-space', type=int,
                        help='シェアID空間のサイズを直接指定（オプション）')

def encrypt_command(args):
    """暗号化コマンド（修正）"""
    # シェアID空間サイズの決定
    share_id_space = args.share_id_space
    if share_id_space is None:
        share_id_space = determine_share_id_space_size(args.security_level)

    # 以下既存の処理を継続...
    # ただし、各関数呼び出しにshare_id_space引数を追加
```

### 7. ユニットテストの追加

シェア ID 空間サイズの最適化に関するテストを追加します。

```python
# tests/test_share_id_optimization.py

import pytest
import os
import random
import time
from shamir.share_id import generate_share_ids, determine_share_id_space_size, check_share_id_collisions
from shamir.performance import PerformanceMonitor
from shamir.constants import ShamirConstants

def test_generate_share_ids():
    """シェアID生成のテスト"""
    # テスト用のシード値
    seed = os.urandom(32)

    # 異なる数のIDを生成
    ids_10 = generate_share_ids(seed, 10, 1000)
    ids_100 = generate_share_ids(seed, 100, 1000)

    # 正しい数のIDが生成されているか確認
    assert len(ids_10) == 10
    assert len(ids_100) == 100

    # 重複がないことを確認
    assert len(set(ids_10)) == 10
    assert len(set(ids_100)) == 100

    # 同じシードで生成すると同じIDになることを確認
    ids_10_repeat = generate_share_ids(seed, 10, 1000)
    assert ids_10 == ids_10_repeat

def test_determine_share_id_space_size():
    """セキュリティレベルに応じたシェアID空間サイズのテスト"""
    # 各レベルでサイズを確認
    assert determine_share_id_space_size('low') == ShamirConstants.SHARE_ID_SPACE_LOW
    assert determine_share_id_space_size('standard') == ShamirConstants.SHARE_ID_SPACE_STANDARD
    assert determine_share_id_space_size('high') == ShamirConstants.SHARE_ID_SPACE_HIGH

    # 不明な値はstandardとして扱われる
    assert determine_share_id_space_size('unknown') == ShamirConstants.SHARE_ID_SPACE_STANDARD

def test_performance_small_vs_large_space():
    """シェアID空間サイズによるパフォーマンスの違いをテスト"""
    # 小さい空間での生成
    seed = os.urandom(32)

    # 小さい空間での測定
    small_space_size = 10000
    result_small, perf_small = PerformanceMonitor.measure_performance(
        generate_share_ids, seed, 1000, small_space_size
    )

    # 大きい空間での測定
    large_space_size = 1000000
    result_large, perf_large = PerformanceMonitor.measure_performance(
        generate_share_ids, seed, 1000, large_space_size
    )

    # 結果を出力（テスト目的なので常に表示）
    print(f"小さい空間({small_space_size})での実行時間: {perf_small['execution_time_sec']:.6f}秒")
    print(f"大きい空間({large_space_size})での実行時間: {perf_large['execution_time_sec']:.6f}秒")
    print(f"小さい空間でのメモリ増加: {perf_small['memory_increase_rss_mb']:.2f}MB")
    print(f"大きい空間でのメモリ増加: {perf_large['memory_increase_rss_mb']:.2f}MB")

    # 実行時間の差を確認（大きい空間の方が遅いはず）
    # 注：環境によって差が大きくない場合もあるため、厳密なアサーションは避ける
    assert perf_small['execution_time_sec'] <= perf_large['execution_time_sec'] * 1.5

    # 生成結果が同じ数なことを確認
    assert len(result_small) == len(result_large) == 1000

def test_partition_collision_rate():
    """パーティション間の衝突率をテスト"""
    # 複数のランダムパーティションキーを生成
    partition_keys = [os.urandom(32) for _ in range(5)]

    # 異なるシェアID空間サイズでの衝突率をテスト
    small_space = 1000
    standard_space = 10000
    large_space = 100000

    collision_small = check_share_id_collisions(partition_keys, small_space)
    collision_standard = check_share_id_collisions(partition_keys, standard_space)
    collision_large = check_share_id_collisions(partition_keys, large_space)

    # 平均衝突率を計算
    avg_collision_small = sum(collision_small.values()) / len(collision_small)
    avg_collision_standard = sum(collision_standard.values()) / len(collision_standard)
    avg_collision_large = sum(collision_large.values()) / len(collision_large)

    # 結果を出力
    print(f"小さい空間での平均衝突率: {avg_collision_small:.4f}")
    print(f"標準空間での平均衝突率: {avg_collision_standard:.4f}")
    print(f"大きい空間での平均衝突率: {avg_collision_large:.4f}")

    # サイズが大きいほど衝突率が低くなることを確認
    assert avg_collision_small >= avg_collision_standard >= avg_collision_large
```

## 検証方法

この修正が正しく実装されていることを確認するため、以下の検証を行ってください：

1. **メモリ使用量のテスト**:

   ```python
   from shamir.performance import PerformanceMonitor
   from shamir.crypto import encrypt_json_document

   # テストデータ
   doc = {"test": "data" * 1000}  # 大きめのデータ

   # パフォーマンス測定
   result, performance = PerformanceMonitor.measure_performance(
       encrypt_json_document, doc, "password", "partition_key"
   )

   print(f"実行時間: {performance['execution_time_sec']:.2f}秒")
   print(f"メモリ使用量: {performance['final_rss_mb']:.2f}MB")
   ```

2. **異なるセキュリティレベルでの CLI テスト**:

   ```bash
   # 低セキュリティレベル（高速、小さいID空間）
   python -m shamir encrypt --input test.json --output encrypted_low.json \
     --password test123 --partition-key test_key --security-level low

   # 標準セキュリティレベル
   python -m shamir encrypt --input test.json --output encrypted_standard.json \
     --password test123 --partition-key test_key --security-level standard

   # 高セキュリティレベル
   python -m shamir encrypt --input test.json --output encrypted_high.json \
     --password test123 --partition-key test_key --security-level high
   ```

3. **パーティション衝突率の分析**:

   ```python
   from shamir.share_id import check_share_id_collisions
   import os

   # 10個のランダムパーティションキーを生成
   keys = [os.urandom(32) for _ in range(10)]

   # 衝突率を分析
   collisions = check_share_id_collisions(keys)

   # 結果の表示
   for (key1, key2), ratio in collisions.items():
       print(f"パーティション {key1.hex()[:8]}... と {key2.hex()[:8]}... の衝突率: {ratio:.4f}")

   # 平均衝突率
   avg_collision = sum(collisions.values()) / len(collisions)
   print(f"平均衝突率: {avg_collision:.4f}")
   ```

## 期待される成果

この修正により、以下の成果が期待されます：

1. **メモリ効率の改善**: メモリ消費が大幅に削減され、プログラムが強制終了しなくなる
2. **パフォーマンスの向上**: 処理速度が向上し、大きなファイルも効率的に扱える
3. **柔軟なセキュリティ設定**: 用途に応じて適切なセキュリティレベルを選択できる
4. **検証可能性**: パーティション間の衝突率を分析できるようになる

最適化されたシェア ID 空間サイズにより、システムのパフォーマンス、安定性、実用性が大幅に向上します。セキュリティを損なうことなく、より効率的な処理が可能になります。
