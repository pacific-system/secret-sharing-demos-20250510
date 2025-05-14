#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - エントロピー注入モジュール

暗号化プロセスにエントロピー（ランダム性）を注入する機能を提供します。
これにより、同じ平文と鍵からでも毎回異なる暗号文が生成されるようになります。
"""

import os
import time
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional, Any, Union, ByteString

# 内部モジュールのインポート
from .config import ENTROPY_POOL_SIZE

class EntropyPool:
    """エントロピープールクラス"""

    def __init__(self, pool_size: int = ENTROPY_POOL_SIZE):
        """
        エントロピープールを初期化

        Args:
            pool_size: プールサイズ（バイト）
        """
        self.pool_size = pool_size
        self.pool = bytearray(os.urandom(pool_size))
        self.position = 0
        self.last_refresh = time.time()
        self.refresh_counter = 0

    def get_bytes(self, num_bytes: int) -> bytes:
        """
        プールからバイト列を取得

        Args:
            num_bytes: 取得するバイト数

        Returns:
            ランダムなバイト列
        """
        # プールサイズを超える要求は分割して処理
        if num_bytes > self.pool_size:
            return b''.join(self.get_bytes(min(num_bytes, self.pool_size))
                          for _ in range((num_bytes // self.pool_size) + 1))[:num_bytes]

        # 必要に応じてプールを更新
        self._maybe_refresh_pool()

        # 循環バッファとして使用
        result = bytearray()
        remaining = num_bytes

        while remaining > 0:
            # 現在位置から末尾までの利用可能バイト数
            available = self.pool_size - self.position

            # 必要なバイト数か利用可能なバイト数の少ない方を取得
            chunk_size = min(remaining, available)
            result.extend(self.pool[self.position:self.position + chunk_size])

            # 位置を更新（循環）
            self.position = (self.position + chunk_size) % self.pool_size
            remaining -= chunk_size

            # プールから読み取る度に少しずつ更新
            self._perturb_pool(chunk_size)

        return bytes(result)

    def _maybe_refresh_pool(self):
        """必要に応じてプールを更新"""
        current_time = time.time()

        # 一定間隔または一定回数の使用後に更新
        if ((current_time - self.last_refresh > 60) or  # 1分ごと
            (self.refresh_counter >= 1000)):            # 1000回の使用ごと

            # プールの半分をランダムデータで更新
            half_size = self.pool_size // 2
            start_pos = secrets.randbelow(half_size)

            # 新しいランダムデータを生成
            new_data = os.urandom(half_size)

            # プールを更新
            for i in range(half_size):
                pos = (start_pos + i) % self.pool_size
                self.pool[pos] = new_data[i]

            # 状態を更新
            self.last_refresh = current_time
            self.refresh_counter = 0

    def _perturb_pool(self, num_bytes: int):
        """
        プールにわずかな変化を加える

        Args:
            num_bytes: 使用したバイト数
        """
        # 使用回数をカウント
        self.refresh_counter += 1

        # 小さな摂動を追加（数バイトのみ変更）
        if self.refresh_counter % 10 == 0:  # 10回ごとに実施
            perturb_size = min(8, self.pool_size // 100)  # 最大8バイトまたはプールの1%
            perturb_pos = secrets.randbelow(self.pool_size - perturb_size)

            # 摂動データの生成（時間情報なども混ぜる）
            time_data = str(time.time()).encode()
            perturb_data = hashlib.sha256(time_data + os.urandom(8)).digest()[:perturb_size]

            # プールに摂動を適用
            for i in range(perturb_size):
                self.pool[perturb_pos + i] ^= perturb_data[i]  # XORで適用

# グローバルエントロピープール
global_entropy_pool = EntropyPool()

def inject_entropy(data: ByteString, strength: float = 1.0) -> bytes:
    """
    データにエントロピーを注入

    Args:
        data: 元のデータ
        strength: 注入強度（0.0〜1.0）

    Returns:
        エントロピー注入後のデータ
    """
    if not data:
        return b''

    if strength <= 0:
        return bytes(data)

    # 入力をバイト列に変換
    if not isinstance(data, (bytes, bytearray)):
        if isinstance(data, str):
            data = data.encode('utf-8')
        else:
            data = bytes(data)

    # 強度に基づいて注入量を決定
    inject_ratio = min(1.0, max(0.0, strength))
    inject_bytes = int(len(data) * inject_ratio * 0.2)  # 最大で20%のデータを注入

    if inject_bytes <= 0:
        return bytes(data)

    # エントロピープールからデータを取得
    entropy = global_entropy_pool.get_bytes(inject_bytes)

    # 結果のバイト配列
    result = bytearray(data)

    # エントロピーの注入（XOR操作）
    for i in range(inject_bytes):
        # ランダムな位置を選択
        pos = secrets.randbelow(len(result))

        # エントロピーを注入（XOR）
        result[pos] ^= entropy[i]

    return bytes(result)

def get_entropy_bytes(num_bytes: int) -> bytes:
    """
    エントロピープールからランダムなバイト列を取得

    Args:
        num_bytes: 取得するバイト数

    Returns:
        ランダムなバイト列
    """
    return global_entropy_pool.get_bytes(num_bytes)

def reset_entropy_pool():
    """エントロピープールをリセット（主にテスト用）"""
    global global_entropy_pool
    global_entropy_pool = EntropyPool()
