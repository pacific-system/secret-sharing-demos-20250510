"""
パーティション空間管理

このモジュールでは、シャミア秘密分散法のパーティション空間を管理します。
パーティションマップキーの生成、シェアIDの割り当て、統計的区別不可能性の
検証などの機能を提供します。
"""

import os
import secrets
import hashlib
import base64
import random
from typing import Dict, List, Tuple, Set, Any
from .constants import ShamirConstants


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


class PartitionManager:
    """パーティション空間を管理するクラス"""

    def __init__(self,
                 partition_a_key: str,
                 partition_b_key: str,
                 share_id_space: int = ShamirConstants.SHARE_ID_SPACE,
                 force_initialization: bool = False):
        """
        パーティションマネージャーの初期化

        Args:
            partition_a_key: Aユーザー用パーティションマップキー
            partition_b_key: Bユーザー用パーティションマップキー
            share_id_space: シェアID空間の大きさ
            force_initialization: 強制的に初期化するかどうか
        """
        self.partition_a_key = partition_a_key
        self.partition_b_key = partition_b_key
        self.share_id_space = share_id_space

        # シェアID空間の基本チェック
        if partition_a_key == partition_b_key and not force_initialization:
            raise ValueError("AとBのパーティションマップキーが同一です")

        # シェア比率
        self.ratio_a = ShamirConstants.RATIO_A
        self.ratio_b = ShamirConstants.RATIO_B
        self.ratio_unassigned = ShamirConstants.RATIO_UNASSIGNED

        # シェアID空間の生成
        self._initialize_share_ids()

    def _initialize_share_ids(self):
        """シェアID空間を初期化"""
        # 基本のシェアID集合
        # 1からシェアID空間サイズまでの整数
        # 0は使用しない（シャミア法の秘密は多項式のy=0での値）
        all_share_ids = list(range(1, self.share_id_space + 1))

        # パーティションマップキーを使って擬似乱数生成器を初期化
        # これによりパーティションマップキーが同じなら同じシェアID集合が生成される
        combined_key = self.partition_a_key + self.partition_b_key
        seed_value = int.from_bytes(
            hashlib.sha256(combined_key.encode('utf-8')).digest(),
            byteorder='big'
        )
        random.seed(seed_value)

        # シェアID全体をランダムに並べ替え
        random.shuffle(all_share_ids)

        # シェア数を計算
        total_shares = len(all_share_ids)
        a_shares_count = int(total_shares * self.ratio_a)
        b_shares_count = int(total_shares * self.ratio_b)
        unassigned_count = total_shares - a_shares_count - b_shares_count

        # 各パーティションに配分
        self.a_share_ids = all_share_ids[:a_shares_count]
        self.b_share_ids = all_share_ids[a_shares_count:a_shares_count + b_shares_count]
        self.unassigned_ids = all_share_ids[a_shares_count + b_shares_count:]

        # 情報を保存
        self.all_share_ids = all_share_ids
        self.a_shares_count = a_shares_count
        self.b_shares_count = b_shares_count
        self.unassigned_count = unassigned_count
        self.total_shares = total_shares

        # 統計的区別不可能性を検証
        self._verify_partition_distributions()

    def _verify_partition_distributions(self):
        """パーティション分布の統計的特性を検証"""
        # 実際の比率を計算
        actual_ratio_a = self.a_shares_count / self.total_shares
        actual_ratio_b = self.b_shares_count / self.total_shares
        actual_ratio_unassigned = self.unassigned_count / self.total_shares

        # 許容誤差
        tolerance = 0.01  # 1%の許容誤差

        # 目標比率と実際の比率の差を計算
        a_diff = abs(actual_ratio_a - self.ratio_a)
        b_diff = abs(actual_ratio_b - self.ratio_b)
        u_diff = abs(actual_ratio_unassigned - self.ratio_unassigned)

        # 許容誤差を超える場合は警告（エラーにはしない）
        if a_diff > tolerance or b_diff > tolerance or u_diff > tolerance:
            print(f"警告: パーティション比率が目標値から乖離しています")
            print(f"  目標比率: A={self.ratio_a:.2f}, B={self.ratio_b:.2f}, 未割当={self.ratio_unassigned:.2f}")
            print(f"  実際比率: A={actual_ratio_a:.2f}, B={actual_ratio_b:.2f}, 未割当={actual_ratio_unassigned:.2f}")

    def get_partition_statistics(self) -> Dict[str, Any]:
        """
        パーティション空間の統計情報を取得

        Returns:
            統計情報を含む辞書
        """
        # ID分布の基本統計
        a_min = min(self.a_share_ids) if self.a_share_ids else 0
        a_max = max(self.a_share_ids) if self.a_share_ids else 0
        a_avg = sum(self.a_share_ids) / len(self.a_share_ids) if self.a_share_ids else 0

        b_min = min(self.b_share_ids) if self.b_share_ids else 0
        b_max = max(self.b_share_ids) if self.b_share_ids else 0
        b_avg = sum(self.b_share_ids) / len(self.b_share_ids) if self.b_share_ids else 0

        u_min = min(self.unassigned_ids) if self.unassigned_ids else 0
        u_max = max(self.unassigned_ids) if self.unassigned_ids else 0
        u_avg = sum(self.unassigned_ids) / len(self.unassigned_ids) if self.unassigned_ids else 0

        # 実際の比率
        actual_ratio_a = self.a_shares_count / self.total_shares
        actual_ratio_b = self.b_shares_count / self.total_shares
        actual_ratio_unassigned = self.unassigned_count / self.total_shares

        # 統計情報を辞書として返す
        return {
            "total_shares": self.total_shares,
            "partition_a": {
                "count": self.a_shares_count,
                "ratio": actual_ratio_a,
                "min_id": a_min,
                "max_id": a_max,
                "avg_id": a_avg
            },
            "partition_b": {
                "count": self.b_shares_count,
                "ratio": actual_ratio_b,
                "min_id": b_min,
                "max_id": b_max,
                "avg_id": b_avg
            },
            "unassigned": {
                "count": self.unassigned_count,
                "ratio": actual_ratio_unassigned,
                "min_id": u_min,
                "max_id": u_max,
                "avg_id": u_avg
            },
            "indistinguishable": verify_statistical_indistinguishability(
                self.a_share_ids, self.b_share_ids, self.unassigned_ids
            )
        }


def verify_statistical_indistinguishability(
    partition_a: List[int],
    partition_b: List[int],
    unassigned: List[int],
    confidence_level: float = 0.05
) -> bool:
    """
    パーティション間の統計的区別不可能性を検証

    Args:
        partition_a: パーティションAのシェアIDリスト
        partition_b: パーティションBのシェアIDリスト
        unassigned: 未割当のシェアIDリスト
        confidence_level: 信頼水準（0.05 = 95%信頼区間）

    Returns:
        統計的に区別不可能ならTrue
    """
    # 各パーティション内のIDの分布について基本統計量を計算
    def calc_stats(ids):
        if not ids:
            return {"min": 0, "max": 0, "mean": 0, "variance": 0}
        n = len(ids)
        mean = sum(ids) / n
        variance = sum((x - mean) ** 2 for x in ids) / n
        return {
            "min": min(ids),
            "max": max(ids),
            "mean": mean,
            "variance": variance
        }

    # 各パーティションの統計量を計算
    stats_a = calc_stats(partition_a)
    stats_b = calc_stats(partition_b)
    stats_u = calc_stats(unassigned)

    # シェアID空間全体のサイズ（最大値）を取得
    all_ids = partition_a + partition_b + unassigned
    max_id = max(all_ids) if all_ids else 0

    # 平均値の差に基づく検定
    # 統計的区別不可能性のためには、平均値が近いはず
    mean_diff_ab = abs(stats_a["mean"] - stats_b["mean"])
    mean_diff_au = abs(stats_a["mean"] - stats_u["mean"])
    mean_diff_bu = abs(stats_b["mean"] - stats_u["mean"])

    # 平均値の差の閾値（ID空間の大きさの10%程度）
    threshold = max_id * 0.1

    # 分散の比率
    # 統計的区別不可能性のためには、分散の比率が1に近いはず
    variance_ratio_ab = (stats_a["variance"] / stats_b["variance"]) if stats_b["variance"] else float('inf')
    variance_ratio_au = (stats_a["variance"] / stats_u["variance"]) if stats_u["variance"] else float('inf')
    variance_ratio_bu = (stats_b["variance"] / stats_u["variance"]) if stats_u["variance"] else float('inf')

    # 分散比の閾値（0.5から2.0程度が一般的）
    variance_threshold_low = 0.5
    variance_threshold_high = 2.0

    # 均一性を確認
    is_mean_indistinguishable = (
        mean_diff_ab < threshold and
        mean_diff_au < threshold and
        mean_diff_bu < threshold
    )

    is_variance_indistinguishable = (
        variance_threshold_low < variance_ratio_ab < variance_threshold_high and
        variance_threshold_low < variance_ratio_au < variance_threshold_high and
        variance_threshold_low < variance_ratio_bu < variance_threshold_high
    )

    # 両方の条件を満たせば統計的に区別不可能と判断
    return is_mean_indistinguishable and is_variance_indistinguishable


def initialize_system(
    threshold: int = ShamirConstants.DEFAULT_THRESHOLD,
    share_id_space: int = ShamirConstants.SHARE_ID_SPACE
) -> Dict[str, Any]:
    """
    システムを初期化し、パーティションマップキーを生成

    Args:
        threshold: 閾値
        share_id_space: シェアID空間の大きさ

    Returns:
        システム初期化情報を含む辞書
    """
    # パーティションマップキーを生成
    partition_a_key = generate_partition_map_key()
    partition_b_key = generate_partition_map_key()

    # 同一キーの発生を防止
    while partition_a_key == partition_b_key:
        partition_b_key = generate_partition_map_key()

    # パーティションマネージャーを初期化
    partition_manager = PartitionManager(
        partition_a_key=partition_a_key,
        partition_b_key=partition_b_key,
        share_id_space=share_id_space
    )

    # 統計情報を取得
    partition_stats = partition_manager.get_partition_statistics()

    # システム情報を返す
    return {
        "threshold": threshold,
        "partition_a_key": partition_a_key,
        "partition_b_key": partition_b_key,
        "total_shares": partition_stats["total_shares"],
        "a_shares_count": partition_stats["partition_a"]["count"],
        "b_shares_count": partition_stats["partition_b"]["count"],
        "indistinguishable": partition_stats["indistinguishable"]
    }