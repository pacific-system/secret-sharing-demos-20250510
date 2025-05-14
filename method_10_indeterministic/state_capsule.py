#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 状態カプセルモジュール

暗号化・復号プロセスのための状態とメタデータをカプセル化します。
これにより、暗号化した状態を保存し、復号時に再現することが可能になります。
"""

import os
import json
import time
import hashlib
import binascii
import datetime
import base64
from typing import Dict, List, Tuple, Optional, Any, Union, BinaryIO

# 内部モジュールのインポート
from .config import (
    KEY_SIZE_BYTES, SALT_SIZE, NONCE_SIZE,
    STATE_MATRIX_SIZE, OUTPUT_FORMAT, ANTI_TAMPERING
)
from .state_matrix import StateMatrix
from .probability_engine import ProbabilityEngine

class StateCapsule:
    """状態カプセルクラス"""

    def __init__(self):
        """状態カプセルを初期化"""
        self.capsule_id = os.urandom(16).hex()
        self.created_at = int(time.time())
        self.metadata = {}
        self.state_matrix = None
        self.probability_engine = None
        self.key_hash = None
        self.salt = None
        self.nonce = None
        self.integrity_hash = None

    def set_key(self, key: bytes) -> None:
        """
        鍵を設定

        Args:
            key: 鍵データ
        """
        # 鍵のハッシュを保存（鍵自体は保存しない）
        self.key_hash = hashlib.sha256(key).digest()
        # ソルトとノンスを生成
        self.salt = os.urandom(SALT_SIZE)
        self.nonce = os.urandom(NONCE_SIZE)

    def initialize_state(self, key: bytes, true_data: bytes, false_data: bytes) -> None:
        """
        状態を初期化

        Args:
            key: 鍵
            true_data: 真のデータ
            false_data: 偽のデータ
        """
        # 鍵を設定
        self.set_key(key)

        # 状態マトリクスを初期化
        self.state_matrix = StateMatrix()
        # 鍵とソルトから初期化
        combined_key = key + self.salt
        true_bias = 0.5  # 中立的なバイアス
        self.state_matrix.initialize(combined_key, true_data + false_data, self.salt, true_bias)

        # 確率エンジンを初期化
        self.probability_engine = ProbabilityEngine()
        self.probability_engine.initialize(key + self.salt, self.state_matrix)

        # メタデータを設定
        self.metadata = {
            "format": OUTPUT_FORMAT,
            "version": "1.0",
            "created_at": self.created_at,
            "capsule_id": self.capsule_id,
            "state_matrix_size": STATE_MATRIX_SIZE,
            "true_data_size": len(true_data),
            "false_data_size": len(false_data)
        }

        # 整合性ハッシュを更新
        self._update_integrity_hash()

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

        # 状態マトリクスのシグネチャを取得
        matrix_signature = b''
        if self.state_matrix and self.state_matrix.initialized:
            matrix_signature = self.state_matrix.get_state_signature()

        # 各種データを連結
        components = [
            meta_json,
            self.key_hash or b'',
            self.salt or b'',
            self.nonce or b'',
            matrix_signature
        ]

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
        if not self.probability_engine or not self.probability_engine.initialized:
            raise ValueError("確率エンジンが初期化されていません")

        # 鍵からハッシュを計算
        key_hash = hashlib.sha256(key).digest()

        # この鍵が登録されている鍵と一致するか確認
        if self.key_hash and key_hash == self.key_hash:
            # 完全に一致する場合は確率エンジンに判断を委ねる
            return self.probability_engine.determine_path()
        else:
            # 異なる鍵の場合、その鍵に基づいた判断を行う
            # 新しい確率エンジンを初期化
            engine = ProbabilityEngine()
            engine.initialize(key + (self.salt or b''))
            return engine.determine_path()

    def to_dict(self) -> Dict[str, Any]:
        """
        カプセルを辞書に変換

        Returns:
            カプセルを表す辞書
        """
        result = {
            "capsule_id": self.capsule_id,
            "created_at": self.created_at,
            "metadata": self.metadata
        }

        # バイナリデータをBase64エンコード
        if self.salt:
            result["salt"] = base64.b64encode(self.salt).decode('ascii')
        if self.nonce:
            result["nonce"] = base64.b64encode(self.nonce).decode('ascii')
        if self.integrity_hash:
            result["integrity_hash"] = base64.b64encode(self.integrity_hash).decode('ascii')

        return result

    def from_dict(self, data: Dict[str, Any]) -> None:
        """
        辞書からカプセルを復元

        Args:
            data: カプセルデータの辞書
        """
        self.capsule_id = data.get("capsule_id", os.urandom(16).hex())
        self.created_at = data.get("created_at", int(time.time()))
        self.metadata = data.get("metadata", {})

        # バイナリデータをデコード
        if "salt" in data:
            self.salt = base64.b64decode(data["salt"])
        if "nonce" in data:
            self.nonce = base64.b64decode(data["nonce"])
        if "integrity_hash" in data:
            self.integrity_hash = base64.b64decode(data["integrity_hash"])

    def serialize(self) -> bytes:
        """
        カプセルをバイト列にシリアライズ

        Returns:
            シリアライズされたカプセル
        """
        data = self.to_dict()
        json_data = json.dumps(data).encode('utf-8')

        # ヘッダーを追加
        header = b"INDCAP01"  # バージョン1の状態カプセル
        length = len(json_data).to_bytes(4, byteorder='big')

        return header + length + json_data

    @classmethod
    def deserialize(cls, data: bytes) -> 'StateCapsule':
        """
        バイト列からカプセルをデシリアライズ

        Args:
            data: シリアライズされたカプセル

        Returns:
            復元されたカプセル
        """
        # ヘッダーを確認
        if not data.startswith(b"INDCAP01"):
            raise ValueError("無効なカプセル形式です")

        # 長さを取得
        length = int.from_bytes(data[8:12], byteorder='big')

        # JSONデータを解析
        json_data = data[12:12+length]
        parsed_data = json.loads(json_data.decode('utf-8'))

        # カプセルを作成
        capsule = cls()
        capsule.from_dict(parsed_data)

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
    def load_from_file(cls, file_path: str) -> 'StateCapsule':
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

def create_state_capsule(key: bytes, true_data: bytes, false_data: bytes) -> StateCapsule:
    """
    新しい状態カプセルを作成

    Args:
        key: 暗号化鍵
        true_data: 真のデータ
        false_data: 偽のデータ

    Returns:
        初期化された状態カプセル
    """
    capsule = StateCapsule()
    capsule.initialize_state(key, true_data, false_data)
    return capsule
