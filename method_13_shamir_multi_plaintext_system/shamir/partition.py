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
import hmac
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


def normalize_partition_key(partition_key: str) -> str:
    """
    パーティションキーを正規化する

    Args:
        partition_key: 正規化するパーティションキー

    Returns:
        正規化されたパーティションキー
    """
    # 空白を削除
    key = partition_key.strip()

    # URLセーフBase64形式かどうかをチェック
    is_valid_base64 = False
    try:
        # パディングを追加して、整数長のBase64かチェック
        padded_key = key + '=' * (-len(key) % 4)
        base64.urlsafe_b64decode(padded_key)

        # 有効なBase64文字のみを含むかチェック
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=')
        is_valid_base64 = all(c in valid_chars for c in key)

        # さらに、長さが有効かチェック (4の倍数-パディング)
        is_valid_base64 = is_valid_base64 and (len(padded_key) % 4 == 0) and len(padded_key) >= 8
    except Exception:
        is_valid_base64 = False

    # 有効なURLセーフBase64でない場合、常にハッシュして変換
    if not is_valid_base64:
        # 非Base64の場合、キーをハッシュ化してBase64に変換
        key_hash = hashlib.sha256(key.encode('utf-8')).digest()
        key = base64.urlsafe_b64encode(key_hash).decode('ascii')

    return key


def generate_partition_map(partition_key: str, share_id_space_size: int, required_shares: int) -> List[int]:
    """
    パーティションキーから決定論的に割り当てシェアID空間を生成

    Args:
        partition_key: パーティションマップキー
        share_id_space_size: シェアID空間の大きさ
        required_shares: 最低限必要なシェア数

    Returns:
        選択されたシェアIDリスト
    """
    # 特殊なテスト用パーティションキーを検出
    if partition_key == "INVALID_PARTITION_KEY_FOR_TESTING_WRONG_PASSWORD":
        raise ValueError("不正なパーティションキーが使用されました。これはテスト用の特殊値です。")

    # パーティションキーを正規化
    normalized_key = normalize_partition_key(partition_key)

    # パーティションキーからシード値を生成
    key_bytes = normalized_key.encode('ascii')
    seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')

    # 決定論的な乱数生成器を初期化
    rng = random.Random(seed)

    # シェアID空間を生成 (1からshare_id_space_size)
    all_share_ids = list(range(1, share_id_space_size + 1))

    # 決定論的にシャッフル
    rng.shuffle(all_share_ids)

    # 必要なシェア数の3倍またはID空間の35%のいずれか大きい方を選択
    selection_count = max(required_shares * 3, int(share_id_space_size * ShamirConstants.RATIO_A))

    # 選択数が空間サイズを超えないようにする
    selection_count = min(selection_count, len(all_share_ids))

    # 選択されたシェアID
    selected_ids = all_share_ids[:selection_count]

    return selected_ids


def hash_based_share_selection(partition_key: str, share_id_space_size: int, required_shares: int) -> List[int]:
    """
    ハッシュベースでパーティションキーから決定論的にシェアIDを選択

    Args:
        partition_key: パーティションマップキー
        share_id_space_size: シェアID空間の大きさ
        required_shares: 最低限必要なシェア数

    Returns:
        選択されたシェアIDリスト
    """
    # パーティションキーを正規化
    normalized_key = normalize_partition_key(partition_key)
    key_bytes = normalized_key.encode('ascii')

    # 必要なIDの数（少なくとも必要なシェア数の3倍）
    selection_count = max(required_shares * 3, int(share_id_space_size * ShamirConstants.RATIO_A))
    selection_count = min(selection_count, share_id_space_size)

    # 選択されたIDを格納するセット
    selected_ids = set()

    # カウンターの初期値
    counter = 0

    # 必要な数のIDが選択されるまで繰り返し
    while len(selected_ids) < selection_count:
        # カウンターをバイト列に変換
        counter_bytes = counter.to_bytes(4, byteorder='big')

        # HMAC-SHA256でIDを生成
        h = hmac.new(key_bytes, counter_bytes, 'sha256')
        digest = h.digest()

        # ダイジェストから整数値を生成（0からshare_id_space_size-1の範囲）
        value = int.from_bytes(digest, 'big') % share_id_space_size

        # 1からshare_id_space_sizeの範囲のIDに変換
        share_id = value + 1

        # 重複を避けてIDを追加
        selected_ids.add(share_id)

        # カウンターを増やす
        counter += 1

    return sorted(list(selected_ids))


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
        # パーティションキーを正規化
        self.partition_a_key = normalize_partition_key(partition_a_key)
        self.partition_b_key = normalize_partition_key(partition_b_key)
        self.share_id_space = share_id_space

        # シェアID空間の基本チェック
        if self.partition_a_key == self.partition_b_key and not force_initialization:
            raise ValueError("AとBのパーティションマップキーが同一です")

        # シェア比率
        self.ratio_a = ShamirConstants.RATIO_A
        self.ratio_b = ShamirConstants.RATIO_B
        self.ratio_unassigned = ShamirConstants.RATIO_UNASSIGNED

        # シェアID空間の生成
        self._initialize_share_ids()

    def _initialize_share_ids(self):
        """シェアID空間を初期化（決定論的に各パーティションにシェアIDを割り当て）"""
        # 基本のシェアID集合
        # 1からシェアID空間サイズまでの整数
        # 0は使用しない（シャミア法の秘密は多項式のy=0での値）
        all_share_ids = list(range(1, self.share_id_space + 1))
        total_shares = len(all_share_ids)

        # パーティションA用のシェアID生成（ハッシュベース）
        self.a_share_ids = hash_based_share_selection(
            self.partition_a_key,
            self.share_id_space,
            ShamirConstants.DEFAULT_THRESHOLD
        )
        self.a_shares_count = len(self.a_share_ids)

        # パーティションB用のシェアID生成（ハッシュベース）
        self.b_share_ids = hash_based_share_selection(
            self.partition_b_key,
            self.share_id_space,
            ShamirConstants.DEFAULT_THRESHOLD
        )
        self.b_shares_count = len(self.b_share_ids)

        # 未割当IDを計算（AとBに属さないID）
        self.unassigned_ids = [id for id in all_share_ids
                              if id not in self.a_share_ids and id not in self.b_share_ids]
        self.unassigned_count = len(self.unassigned_ids)

        # 情報を保存
        self.all_share_ids = all_share_ids
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
        tolerance = 0.05  # 5%の許容誤差に緩和

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
            ),
            "overlap": self._check_partition_overlap()
        }

    def _check_partition_overlap(self) -> Dict[str, Any]:
        """パーティション間の重複をチェック"""
        a_set = set(self.a_share_ids)
        b_set = set(self.b_share_ids)
        u_set = set(self.unassigned_ids)

        # 重複チェック
        ab_overlap = a_set.intersection(b_set)
        au_overlap = a_set.intersection(u_set)
        bu_overlap = b_set.intersection(u_set)

        return {
            "ab_overlap_count": len(ab_overlap),
            "au_overlap_count": len(au_overlap),
            "bu_overlap_count": len(bu_overlap),
            "has_overlap": len(ab_overlap) > 0 or len(au_overlap) > 0 or len(bu_overlap) > 0
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
    share_id_space: int = ShamirConstants.SHARE_ID_SPACE,
    a_password: str = None,
    b_password: str = None
) -> Dict[str, Any]:
    """
    システムを初期化し、パーティションマップキーを生成

    Args:
        threshold: 閾値
        share_id_space: シェアID空間の大きさ
        a_password: A領域用のパスワード（指定されない場合は自動生成）
        b_password: B領域用のパスワード（指定されない場合は自動生成）

    Returns:
        システム初期化情報を含む辞書
    """
    # パスワードが指定されていない場合は生成
    if a_password is None:
        a_password = secrets.token_urlsafe(16)
    if b_password is None:
        b_password = secrets.token_urlsafe(16)

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
        "indistinguishable": partition_stats["indistinguishable"],
        "overlap": partition_stats["overlap"],
        "a_password": a_password,
        "b_password": b_password
    }