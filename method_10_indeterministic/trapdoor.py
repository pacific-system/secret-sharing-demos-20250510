#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - トラップドアモジュール

不確定性暗号化の特性を利用して、「ハニーポット戦略」や「リバーストラップ」を
実現するための機能を提供します。攻撃者に偽の情報を信じ込ませながら、
実際の重要情報を非正規側に隠すことができます。
"""

import os
import hashlib
import secrets
import binascii
import datetime
from typing import Dict, List, Tuple, Optional, Any, Union, ByteString

# 内部モジュールのインポート
from .config import (
    KEY_SIZE_BYTES, TRUE_TEXT_PATH, FALSE_TEXT_PATH,
    ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR
)
from .state_matrix import StateMatrix
from .probability_engine import ProbabilityEngine, calculate_probability_distribution

# 循環インポートを避けるため、indeterministicモジュールはインポートしない
# from .indeterministic import create_indeterministic_capsule, IndeterministicCapsule

class TrapdoorStrategy:
    """トラップドア戦略クラス"""

    def __init__(self):
        """トラップドア戦略を初期化"""
        self.true_key = None
        self.false_key = None
        self.honeypot_key = None
        self.trap_signature = None
        self.creation_time = datetime.datetime.now()
        self.metadata = {}

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        真/偽の鍵ペアを生成

        Returns:
            (true_key, false_key): 真の鍵と偽の鍵のペア
        """
        # ランダムな鍵を生成
        self.true_key = os.urandom(KEY_SIZE_BYTES)
        self.false_key = os.urandom(KEY_SIZE_BYTES)

        # 鍵ペアのシグネチャを生成
        self._update_trap_signature()

        return self.true_key, self.false_key

    def set_key_pair(self, true_key: bytes, false_key: bytes) -> None:
        """
        既存の鍵ペアを設定

        Args:
            true_key: 真の鍵
            false_key: 偽の鍵
        """
        self.true_key = true_key
        self.false_key = false_key

        # 鍵ペアのシグネチャを生成
        self._update_trap_signature()

    def _update_trap_signature(self) -> None:
        """トラップシグネチャを更新"""
        if self.true_key and self.false_key:
            # 両方の鍵を組み合わせたハッシュ
            combined = self.true_key + self.false_key + str(self.creation_time).encode()
            self.trap_signature = hashlib.sha256(combined).digest()

    def setup_honeypot(self, decoy_factor: float = 0.8) -> bytes:
        """
        ハニーポット戦略をセットアップ

        Args:
            decoy_factor: 囮の強さ（0.0〜1.0）

        Returns:
            ハニーポット鍵
        """
        if not self.true_key or not self.false_key:
            raise ValueError("鍵ペアが生成または設定されていません")

        # ハニーポット鍵を生成
        seed = hashlib.sha256(self.true_key + self.false_key).digest()
        entropy = secrets.token_bytes(16)
        self.honeypot_key = hashlib.sha256(seed + entropy).digest()[:KEY_SIZE_BYTES]

        # メタデータを更新
        self.metadata["strategy"] = "honeypot"
        self.metadata["decoy_factor"] = decoy_factor
        self.metadata["setup_time"] = datetime.datetime.now().isoformat()

        return self.honeypot_key

    def setup_reverse_trap(self, importance_factor: float = 0.7) -> Dict[str, Any]:
        """
        リバーストラップ戦略をセットアップ

        Args:
            importance_factor: 重要度ファクター（0.0〜1.0）

        Returns:
            戦略情報の辞書
        """
        if not self.true_key or not self.false_key:
            raise ValueError("鍵ペアが生成または設定されていません")

        # リバーストラップは「正規」鍵の表に見える認証を「非正規」鍵に与える
        # 実装では単に鍵の役割を入れ替える

        # 一時的に鍵を保存
        temp_true = self.true_key

        # 「正規」と「非正規」を入れ替え
        self.true_key = self.false_key
        self.false_key = temp_true

        # シグネチャを更新
        self._update_trap_signature()

        # メタデータを更新
        self.metadata["strategy"] = "reverse_trap"
        self.metadata["importance_factor"] = importance_factor
        self.metadata["setup_time"] = datetime.datetime.now().isoformat()

        return {
            "strategy": "reverse_trap",
            "notes": "正規鍵と非正規鍵が入れ替えられました",
            "importance_factor": importance_factor
        }

    def create_trap_capsule(self, true_data: bytes, false_data: bytes):
        """
        トラップカプセルを作成

        注: 循環インポートを避けるため、こちらでは実装せず
        indeterministic.pyから直接呼び出すように変更

        Args:
            true_data: 真のデータ
            false_data: 偽のデータ

        Returns:
            初期化された不確定性カプセル
        """
        # この機能は削除し、代わりにindeterministic.pyで直接実装
        raise NotImplementedError(
            "このメソッドは循環インポートを避けるため削除されました。" +
            "代わりにindeterministic.pyのcreate_indeterministic_capsuleを使用してください。"
        )

    def verify_key(self, key: bytes) -> Dict[str, Any]:
        """
        鍵を検証して種類を判定

        Args:
            key: 検証する鍵

        Returns:
            検証結果の辞書
        """
        # 鍵のハッシュを計算
        key_hash = hashlib.sha256(key).digest()

        # 真の鍵と一致するか確認
        is_true = False
        if self.true_key:
            true_key_hash = hashlib.sha256(self.true_key).digest()
            is_true = key_hash == true_key_hash

        # 偽の鍵と一致するか確認
        is_false = False
        if self.false_key:
            false_key_hash = hashlib.sha256(self.false_key).digest()
            is_false = key_hash == false_key_hash

        # ハニーポット鍵と一致するか確認
        is_honeypot = False
        if self.honeypot_key:
            honeypot_key_hash = hashlib.sha256(self.honeypot_key).digest()
            is_honeypot = key_hash == honeypot_key_hash

        # 一致するものがない場合は未知の鍵
        is_unknown = not (is_true or is_false or is_honeypot)

        # 戦略に基づいて結果を調整
        if self.metadata.get("strategy") == "reverse_trap":
            # リバーストラップの場合は真/偽の判定を入れ替え
            is_true, is_false = is_false, is_true

        return {
            "is_true_key": is_true,
            "is_false_key": is_false,
            "is_honeypot_key": is_honeypot,
            "is_unknown_key": is_unknown,
            "strategy": self.metadata.get("strategy", "standard")
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        戦略情報を辞書に変換

        Returns:
            戦略情報の辞書
        """
        result = {
            "metadata": self.metadata,
            "creation_time": self.creation_time.isoformat()
        }

        # 鍵情報を16進数形式で格納
        if self.true_key:
            result["true_key"] = binascii.hexlify(self.true_key).decode('ascii')
        if self.false_key:
            result["false_key"] = binascii.hexlify(self.false_key).decode('ascii')
        if self.honeypot_key:
            result["honeypot_key"] = binascii.hexlify(self.honeypot_key).decode('ascii')
        if self.trap_signature:
            result["trap_signature"] = binascii.hexlify(self.trap_signature).decode('ascii')

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrapdoorStrategy':
        """
        辞書から戦略を復元

        Args:
            data: 戦略情報の辞書

        Returns:
            復元された戦略
        """
        strategy = cls()

        # メタデータを復元
        strategy.metadata = data.get("metadata", {})

        # 作成時間を復元
        if "creation_time" in data:
            strategy.creation_time = datetime.datetime.fromisoformat(data["creation_time"])

        # 鍵情報を復元
        if "true_key" in data:
            strategy.true_key = binascii.unhexlify(data["true_key"])
        if "false_key" in data:
            strategy.false_key = binascii.unhexlify(data["false_key"])
        if "honeypot_key" in data:
            strategy.honeypot_key = binascii.unhexlify(data["honeypot_key"])
        if "trap_signature" in data:
            strategy.trap_signature = binascii.unhexlify(data["trap_signature"])

        return strategy

def create_trapdoor(key: bytes, salt: Optional[bytes] = None) -> Dict[str, Any]:
    """
    与えられた鍵からトラップドア情報を生成

    Args:
        key: 鍵
        salt: ソルト（省略時はランダム生成）

    Returns:
        トラップドア情報の辞書
    """
    # ソルトを設定
    if salt is None:
        salt = os.urandom(16)

    # 鍵からシード値を生成
    seed = hashlib.sha256(key + salt).digest()

    # トラップドア情報を生成
    crypto_strength = int.from_bytes(seed[0:4], byteorder='big') % 100
    complexity = int.from_bytes(seed[4:8], byteorder='big') % 100
    resistance = int.from_bytes(seed[8:12], byteorder='big') % 100

    # 戦略タイプを決定（シード値に基づく）
    strategy_byte = seed[12]
    if strategy_byte < 85:  # ~33%
        strategy = "standard"
    elif strategy_byte < 170:  # ~33%
        strategy = "honeypot"
    else:  # ~33%
        strategy = "reverse_trap"

    # トラップドア情報を辞書形式で返す
    return {
        "crypto_strength": crypto_strength,
        "complexity": complexity,
        "resistance": resistance,
        "strategy": strategy,
        "created_at": datetime.datetime.now().isoformat(),
        "signature": binascii.hexlify(seed[13:29]).decode('ascii')
    }

def create_honeypot_strategy(decoy_factor: float = 0.8) -> TrapdoorStrategy:
    """
    ハニーポット戦略を作成

    Args:
        decoy_factor: 囮の強さ（0.0〜1.0）

    Returns:
        設定済みの戦略
    """
    strategy = TrapdoorStrategy()
    strategy.generate_key_pair()
    strategy.setup_honeypot(decoy_factor)
    return strategy

def create_reverse_trap_strategy(importance_factor: float = 0.7) -> TrapdoorStrategy:
    """
    リバーストラップ戦略を作成

    Args:
        importance_factor: 重要度ファクター（0.0〜1.0）

    Returns:
        設定済みの戦略
    """
    strategy = TrapdoorStrategy()
    strategy.generate_key_pair()
    strategy.setup_reverse_trap(importance_factor)
    return strategy
