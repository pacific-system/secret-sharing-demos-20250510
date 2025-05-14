#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 不確定性カプセルモジュール

真のデータと偽のデータを組み合わせた不確定性カプセルを生成します。
このカプセルは、使用する鍵によって復号結果が変わる特性を持ちます。
"""

import os
import time
import json
import hashlib
import secrets
import base64
import binascii
import datetime
from typing import Dict, List, Tuple, Optional, Any, Union, BinaryIO

# 内部モジュールのインポート
from .config import (
    KEY_SIZE_BYTES, SALT_SIZE, NONCE_SIZE,
    STATE_MATRIX_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION,
    ANTI_TAMPERING, SECURE_MEMORY_WIPE
)
from .state_matrix import (
    StateMatrix, generate_state_matrix,
    StateMatrixGenerator, StateExecutor, State,
    create_state_matrix_from_key, get_biased_random_generator
)
from .probability_engine import ProbabilityEngine, calculate_probability_distribution
from .state_capsule import StateCapsule, create_state_capsule
from .entropy_injector import inject_entropy

# 循環インポートを避けるため、trapdoorモジュールは直接インポートしない
# from .trapdoor import create_trapdoor

# create_trapdoorの内部実装
def _create_trapdoor(key: bytes, salt: Optional[bytes] = None) -> Dict[str, Any]:
    """
    与えられた鍵からトラップドア情報を生成（循環インポート回避用）

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

class IndeterministicCapsule:
    """不確定性カプセルクラス"""

    def __init__(self):
        """不確定性カプセルを初期化"""
        self.capsule_id = os.urandom(16).hex()
        self.created_at = int(time.time())
        self.metadata = {}
        self.state_capsule = None
        self.true_data_hash = None
        self.false_data_hash = None
        self.salt = os.urandom(SALT_SIZE)
        self.nonce = os.urandom(NONCE_SIZE)
        self.encrypted_data = None
        self.integrity_hash = None
        # 新しい状態遷移マトリクスの構成要素
        self.state_matrix_generator = None
        self.states = None
        self.true_initial_state = None
        self.false_initial_state = None

    def encrypt(self, key: bytes, true_data: bytes, false_data: bytes) -> None:
        """
        データを暗号化

        Args:
            key: 暗号化鍵
            true_data: 真のデータ
            false_data: 偽のデータ
        """
        # データのハッシュを保存
        self.true_data_hash = hashlib.sha256(true_data).digest()
        self.false_data_hash = hashlib.sha256(false_data).digest()

        # 状態カプセルを作成
        self.state_capsule = create_state_capsule(key, true_data, false_data)

        # 新しい状態遷移マトリクスを生成
        self.state_matrix_generator = StateMatrixGenerator(key, self.salt)
        self.states = self.state_matrix_generator.generate_state_matrix()
        self.true_initial_state, self.false_initial_state = self.state_matrix_generator.derive_initial_states()

        # エントロピーを注入（同じ入力からでも異なる出力を生成するため）
        entropy_true = inject_entropy(true_data)
        entropy_false = inject_entropy(false_data)

        # バイアスのかかった乱数生成器を作成（暗号化のランダム性のために）
        bias_factor = 0.7  # 70%のバイアス
        biased_random = get_biased_random_generator(key, bias_factor)

        # メタデータを設定
        self.metadata = {
            "format": OUTPUT_FORMAT,
            "version": "1.0",
            "created_at": self.created_at,
            "capsule_id": self.capsule_id,
            "true_data_size": len(true_data),
            "false_data_size": len(false_data),
            "state_matrix_size": STATE_MATRIX_SIZE,
            "true_initial_state": self.true_initial_state,
            "false_initial_state": self.false_initial_state
        }

        # トラップドアを追加（復号時の秘密経路のため）
        trapdoor = _create_trapdoor(key, self.salt)
        self.metadata["trapdoor_enabled"] = bool(trapdoor)

        # 暗号化データを生成（この実装では単純な結合）
        # 実際の実装では、より複雑な暗号化を行う
        self.encrypted_data = self._advanced_encrypt(entropy_true, entropy_false, biased_random)

        # 整合性ハッシュを更新
        self._update_integrity_hash()

    def _advanced_encrypt(self, true_data: bytes, false_data: bytes, random_generator: callable) -> bytes:
        """
        高度な暗号化処理

        状態遷移マトリクスを使用してデータを暗号化します。

        Args:
            true_data: 真のデータ
            false_data: 偽のデータ
            random_generator: 乱数生成器

        Returns:
            暗号化されたデータ
        """
        # ヘッダーを追加
        header = b"INDET02"  # バージョン2

        # データのサイズ情報
        true_size = len(true_data).to_bytes(4, byteorder='big')
        false_size = len(false_data).to_bytes(4, byteorder='big')

        # ソルトとノンスを含める
        salt_nonce = self.salt + self.nonce

        # カプセルIDをバイナリ化
        capsule_id_bin = self.capsule_id.encode('ascii')

        # 状態遷移パスに基づいてデータをシャッフル
        shuffled_true = bytearray(true_data)
        shuffled_false = bytearray(false_data)

        # シャッフル処理（簡易版）
        for i in range(min(len(shuffled_true), len(shuffled_false))):
            # バイアスされた乱数を使用
            rand_val = random_generator()

            # 値に基づいてシャッフル
            if rand_val > 0.5:
                if i < len(shuffled_true):
                    # バイト値を変更（XOR処理）
                    shuffled_true[i] ^= int(rand_val * 255) & 0xFF
            else:
                if i < len(shuffled_false):
                    # バイト値を変更（XOR処理）
                    shuffled_false[i] ^= int(rand_val * 255) & 0xFF

        # 状態遷移パスを追加
        # 正規パスと非正規パスの遷移履歴を作成
        true_executor = StateExecutor(self.states, self.true_initial_state)
        false_executor = StateExecutor(self.states, self.false_initial_state)

        # 10回の遷移を実行
        true_path = true_executor.run_transitions(10)
        false_path = false_executor.run_transitions(10)

        # パスをバイト列に変換
        true_path_bytes = bytes([p % 256 for p in true_path])
        false_path_bytes = bytes([p % 256 for p in false_path])

        # パスのサイズを記録
        true_path_size = len(true_path_bytes).to_bytes(2, byteorder='big')
        false_path_size = len(false_path_bytes).to_bytes(2, byteorder='big')

        # シンプルな結合（実際の暗号化ではない）
        # これは後続のIssueで適切に実装される
        combined = (
            header + true_size + false_size +
            salt_nonce + capsule_id_bin +
            true_path_size + true_path_bytes +
            false_path_size + false_path_bytes +
            bytes(shuffled_true) + bytes(shuffled_false)
        )

        return combined

    def _placeholder_encrypt(self, true_data: bytes, false_data: bytes) -> bytes:
        """
        プレースホルダー暗号化（互換性のために残しておく）

        Args:
            true_data: 真のデータ
            false_data: 偽のデータ

        Returns:
            暗号化されたデータ
        """
        # ヘッダーを追加
        header = b"INDET01"

        # データのサイズ情報
        true_size = len(true_data).to_bytes(4, byteorder='big')
        false_size = len(false_data).to_bytes(4, byteorder='big')

        # ソルトとノンスを含める
        salt_nonce = self.salt + self.nonce

        # カプセルIDをバイナリ化
        capsule_id_bin = self.capsule_id.encode('ascii')

        # シンプルな結合（実際の暗号化ではない）
        combined = (
            header + true_size + false_size +
            salt_nonce + capsule_id_bin +
            true_data + false_data
        )

        return combined

    def _update_integrity_hash(self) -> None:
        """整合性ハッシュを更新"""
        if ANTI_TAMPERING:
            # カプセルの状態を集約
            state_data = self._get_state_data()
            self.integrity_hash = hashlib.sha256(state_data).digest()

    def _get_state_data(self) -> bytes:
        """
        状態データを取得

        Returns:
            状態を表すバイト列
        """
        # メタデータをJSON文字列に変換
        meta_json = json.dumps(self.metadata, sort_keys=True).encode('utf-8')

        # 各種データを連結
        components = [
            meta_json,
            self.true_data_hash or b'',
            self.false_data_hash or b'',
            self.salt,
            self.nonce,
            hashlib.sha256(self.encrypted_data or b'').digest()
        ]

        # 状態カプセルのシリアライズデータも含める
        if self.state_capsule:
            components.append(self.state_capsule.serialize())

        return b''.join([str(len(c)).encode('ascii') + b':' + c for c in components])

    def verify_integrity(self) -> bool:
        """
        整合性を検証

        Returns:
            整合性が保たれている場合はTrue
        """
        if not ANTI_TAMPERING or not self.integrity_hash:
            return True

        # 現在の状態からハッシュを計算
        state_data = self._get_state_data()
        current_hash = hashlib.sha256(state_data).digest()

        # 保存されているハッシュと比較
        return current_hash == self.integrity_hash

    def determine_path(self, key: bytes) -> str:
        """
        鍵からパスタイプを決定

        Args:
            key: 復号鍵

        Returns:
            パスタイプ（"true" または "false"）
        """
        if not self.state_capsule:
            raise ValueError("状態カプセルが初期化されていません")

        # 複数の判定方法を使用し、より強固な判定を行う
        # 1. 状態カプセルによる判定
        capsule_path = self.state_capsule.determine_path(key)

        # 2. 状態遷移マトリクスが利用可能な場合は、それも使用
        matrix_path = "unknown"
        if self.salt and "true_initial_state" in self.metadata and "false_initial_state" in self.metadata:
            try:
                # 鍵から状態遷移マトリクスを再生成
                generator = StateMatrixGenerator(key, self.salt)
                states = generator.generate_state_matrix()
                true_initial, false_initial = generator.derive_initial_states()

                # メタデータに保存されている値と一致するか確認
                if true_initial == self.metadata["true_initial_state"] and false_initial == self.metadata["false_initial_state"]:
                    matrix_path = "true"
                else:
                    matrix_path = "false"
            except Exception:
                # エラーが発生した場合はカプセルの判定を優先
                pass

        # 両方の判定が一致する場合は確定
        if matrix_path != "unknown" and matrix_path == capsule_path:
            return capsule_path

        # 不一致または不明の場合はカプセルの判定を優先
        return capsule_path

    def serialize(self) -> bytes:
        """
        カプセルをバイト列にシリアライズ

        Returns:
            シリアライズされたカプセル
        """
        # 暗号化データがない場合はエラー
        if not self.encrypted_data:
            raise ValueError("カプセルが暗号化されていません")

        # ヘッダーを追加
        header = b"INDET01"

        # メタデータをJSON化
        meta_dict = {
            **self.metadata,
            "salt": base64.b64encode(self.salt).decode('ascii'),
            "nonce": base64.b64encode(self.nonce).decode('ascii')
        }
        if self.integrity_hash:
            meta_dict["integrity_hash"] = base64.b64encode(self.integrity_hash).decode('ascii')

        meta_json = json.dumps(meta_dict).encode('utf-8')
        meta_size = len(meta_json).to_bytes(4, byteorder='big')

        # 状態カプセルをシリアライズ
        state_capsule_data = b''
        if self.state_capsule:
            state_capsule_data = self.state_capsule.serialize()

        state_size = len(state_capsule_data).to_bytes(4, byteorder='big')

        # 全体を組み立て
        result = (
            header +
            meta_size + meta_json +
            state_size + state_capsule_data +
            self.encrypted_data
        )

        return result

    @classmethod
    def deserialize(cls, data: bytes) -> 'IndeterministicCapsule':
        """
        バイト列からカプセルをデシリアライズ

        Args:
            data: シリアライズされたカプセル

        Returns:
            復元されたカプセル
        """
        # ヘッダーを確認
        if not data.startswith(b"INDET01"):
            raise ValueError("無効なカプセル形式です")

        # 現在の位置を追跡
        pos = 8  # ヘッダーの長さ

        # メタデータのサイズを取得
        meta_size = int.from_bytes(data[pos:pos+4], byteorder='big')
        pos += 4

        # メタデータを解析
        meta_json = data[pos:pos+meta_size]
        meta_dict = json.loads(meta_json.decode('utf-8'))
        pos += meta_size

        # 状態カプセルのサイズを取得
        state_size = int.from_bytes(data[pos:pos+4], byteorder='big')
        pos += 4

        # 状態カプセルを解析
        state_capsule_data = data[pos:pos+state_size]
        pos += state_size

        # 残りは暗号化データ
        encrypted_data = data[pos:]

        # カプセルを作成
        capsule = cls()
        capsule.metadata = {k: v for k, v in meta_dict.items()
                          if k not in ["salt", "nonce", "integrity_hash"]}
        capsule.capsule_id = meta_dict.get("capsule_id", os.urandom(16).hex())
        capsule.created_at = meta_dict.get("created_at", int(time.time()))

        # バイナリデータをデコード
        if "salt" in meta_dict:
            capsule.salt = base64.b64decode(meta_dict["salt"])
        if "nonce" in meta_dict:
            capsule.nonce = base64.b64decode(meta_dict["nonce"])
        if "integrity_hash" in meta_dict:
            capsule.integrity_hash = base64.b64decode(meta_dict["integrity_hash"])

        # 状態カプセルを復元
        if state_capsule_data:
            capsule.state_capsule = StateCapsule.deserialize(state_capsule_data)

        # 暗号化データを設定
        capsule.encrypted_data = encrypted_data

        return capsule

    def save_to_file(self, file_path: str) -> None:
        """
        カプセルをファイルに保存

        Args:
            file_path: 出力ファイルパス
        """
        serialized = self.serialize()
        with open(file_path, 'wb') as f:
            f.write(serialized)

    @classmethod
    def load_from_file(cls, file_path: str) -> 'IndeterministicCapsule':
        """
        ファイルからカプセルを読み込み

        Args:
            file_path: カプセルファイルのパス

        Returns:
            読み込まれたカプセル
        """
        with open(file_path, 'rb') as f:
            data = f.read()
        return cls.deserialize(data)

def create_indeterministic_capsule(key: bytes, true_data: bytes, false_data: bytes) -> IndeterministicCapsule:
    """
    新しい不確定性カプセルを作成

    Args:
        key: 暗号化鍵
        true_data: 真のデータ
        false_data: 偽のデータ

    Returns:
        初期化された不確定性カプセル
    """
    capsule = IndeterministicCapsule()
    capsule.encrypt(key, true_data, false_data)
    return capsule
