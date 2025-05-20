"""
シェアID生成と管理

このモジュールでは、シャミア秘密分散法で使用するシェアIDの生成と管理を行います。
メモリ効率のよいID生成、検証、重複チェックなどの機能を提供します。
"""

import random
import hashlib
import time
from typing import List, Set, Iterator, Optional, Tuple
from .constants import ShamirConstants


def create_share_id_space(size: int = ShamirConstants.SHARE_ID_SPACE) -> List[int]:
    """
    シェアID空間を作成

    Args:
        size: シェアID空間のサイズ

    Returns:
        シェアIDのリスト
    """
    # 1からsizeまでの整数のリスト（0は使用しない）
    return list(range(1, size + 1))


def generate_share_ids_iterator(
    size: int = ShamirConstants.SHARE_ID_SPACE,
    seed: Optional[int] = None
) -> Iterator[int]:
    """
    メモリ効率のよいシェアID生成イテレータ
    全IDをメモリに保持せずに順次生成します。

    Args:
        size: シェアID空間のサイズ
        seed: 乱数シード（Noneの場合は現在時刻を使用）

    Yields:
        シェアID
    """
    # シードが指定されていない場合は現在時刻を使用
    if seed is None:
        seed = int(time.time() * 1000)

    # 乱数生成器を初期化
    rng = random.Random(seed)

    # シャッフルされたインデックスを使用
    indices = list(range(1, size + 1))
    rng.shuffle(indices)

    # 順次シェアIDを生成
    for idx in indices:
        yield idx


def generate_share_ids_batch(
    count: int,
    size: int = ShamirConstants.SHARE_ID_SPACE,
    seed: Optional[int] = None,
    existing_ids: Optional[Set[int]] = None
) -> List[int]:
    """
    指定数のシェアIDをバッチ生成

    Args:
        count: 生成するシェアIDの数
        size: シェアID空間のサイズ
        seed: 乱数シード（Noneの場合は現在時刻を使用）
        existing_ids: 既存のシェアID（重複を避けるため）

    Returns:
        シェアIDのリスト
    """
    # countが空間サイズを超えていないことを確認
    if count > size:
        raise ValueError(f"生成するID数がシェアID空間サイズを超えています: {count} > {size}")

    # 既存IDのセット（指定がない場合は空セット）
    existing = set() if existing_ids is None else set(existing_ids)

    # シードが指定されていない場合は現在時刻を使用
    if seed is None:
        seed = int(time.time() * 1000)

    # 乱数生成器を初期化
    rng = random.Random(seed)

    # シェアIDの候補セット
    candidates = set(range(1, size + 1)) - existing

    # 候補が不足している場合はエラー
    if len(candidates) < count:
        raise ValueError(f"利用可能なシェアIDが不足しています: 必要数={count}, 利用可能数={len(candidates)}")

    # ランダムに選択
    selected_ids = rng.sample(list(candidates), count)

    return selected_ids


def deterministic_share_ids(
    key: str,
    count: int,
    size: int = ShamirConstants.SHARE_ID_SPACE
) -> List[int]:
    """
    キーから決定論的にシェアIDを生成

    Args:
        key: 生成のためのキー
        count: 生成するシェアIDの数
        size: シェアID空間のサイズ

    Returns:
        シェアIDのリスト
    """
    # countが空間サイズを超えていないことを確認
    if count > size:
        raise ValueError(f"生成するID数がシェアID空間サイズを超えています: {count} > {size}")

    # キーからシードを生成
    seed = int.from_bytes(hashlib.sha256(key.encode('utf-8')).digest(), 'big')

    # 乱数生成器を初期化
    rng = random.Random(seed)

    # 全シェアIDをリスト化
    all_ids = list(range(1, size + 1))

    # シャッフル
    rng.shuffle(all_ids)

    # 必要数を選択
    return all_ids[:count]


def verify_share_ids(
    share_ids: List[int],
    size: int = ShamirConstants.SHARE_ID_SPACE
) -> Tuple[bool, List[str]]:
    """
    シェアIDのリストを検証

    Args:
        share_ids: 検証するシェアIDのリスト
        size: シェアID空間のサイズ

    Returns:
        (検証結果, エラーメッセージのリスト)
    """
    errors = []

    # 空のリストをチェック
    if not share_ids:
        errors.append("シェアIDのリストが空です")
        return False, errors

    # 範囲外のIDをチェック
    out_of_range = [id for id in share_ids if id < 1 or id > size]
    if out_of_range:
        errors.append(f"範囲外のシェアIDが含まれています: {out_of_range}")

    # 重複をチェック
    unique_ids = set(share_ids)
    if len(unique_ids) != len(share_ids):
        duplicates = [id for id in share_ids if share_ids.count(id) > 1]
        errors.append(f"重複するシェアIDが含まれています: {list(set(duplicates))}")

    # 検証結果
    return len(errors) == 0, errors


class MemoryEfficientShareIDGenerator:
    """メモリ効率のよいシェアID生成器"""

    def __init__(
        self,
        size: int = ShamirConstants.SHARE_ID_SPACE,
        seed: Optional[int] = None
    ):
        """
        初期化

        Args:
            size: シェアID空間のサイズ
            seed: 乱数シード（Noneの場合は現在時刻を使用）
        """
        self.size = size
        self.seed = seed if seed is not None else int(time.time() * 1000)
        self.used_ids = set()
        self.id_generator = self._create_generator()

    def _create_generator(self) -> Iterator[int]:
        """ID生成イテレータを作成"""
        # シードを使用して乱数生成器を初期化
        rng = random.Random(self.seed)

        # シャッフルされたインデックスを使用
        indices = list(range(1, self.size + 1))
        rng.shuffle(indices)

        # 順次シェアIDを生成
        for idx in indices:
            yield idx

    def get_next_id(self) -> int:
        """
        次のシェアIDを取得

        Returns:
            シェアID
        """
        # すべてのIDが使用済みの場合はエラー
        if len(self.used_ids) >= self.size:
            raise ValueError("すべてのシェアIDが使用済みです")

        # 未使用のIDが見つかるまで生成を続ける
        for id in self.id_generator:
            if id not in self.used_ids:
                self.used_ids.add(id)
                return id

        # 通常はここには到達しないはず
        raise RuntimeError("シェアIDの生成に失敗しました")

    def get_multiple_ids(self, count: int) -> List[int]:
        """
        複数のシェアIDを取得

        Args:
            count: 取得するID数

        Returns:
            シェアIDのリスト
        """
        # 利用可能なIDが不足している場合はエラー
        if len(self.used_ids) + count > self.size:
            raise ValueError(f"利用可能なシェアIDが不足しています: 必要数={count}, 残り={self.size - len(self.used_ids)}")

        # 指定数のIDを取得
        ids = []
        for _ in range(count):
            ids.append(self.get_next_id())

        return ids

    def mark_as_used(self, ids: List[int]) -> None:
        """
        指定したIDを使用済みとしてマーク

        Args:
            ids: 使用済みとしてマークするIDのリスト
        """
        # 範囲外のIDをチェック
        out_of_range = [id for id in ids if id < 1 or id > self.size]
        if out_of_range:
            raise ValueError(f"範囲外のシェアIDが含まれています: {out_of_range}")

        # 使用済みとしてマーク
        self.used_ids.update(ids)

    def get_used_count(self) -> int:
        """
        使用済みIDの数を取得

        Returns:
            使用済みIDの数
        """
        return len(self.used_ids)

    def get_remaining_count(self) -> int:
        """
        残りの利用可能IDの数を取得

        Returns:
            残りの利用可能IDの数
        """
        return self.size - len(self.used_ids)

    def reset(self) -> None:
        """生成器をリセット"""
        self.used_ids.clear()
        self.id_generator = self._create_generator()