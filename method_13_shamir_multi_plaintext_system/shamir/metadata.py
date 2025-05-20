"""
メタデータ管理

このモジュールでは、シャミア秘密分散法による複数平文復号システムの
メタデータを管理します。各パーティションのチャンク数、最終更新日時などを追跡します。
"""

import os
import json
import time
import hashlib
from typing import Dict, List, Any, Optional
from .constants import ShamirConstants


class MetadataManager:
    """メタデータを管理するクラス"""

    def __init__(self, metadata_file_path: str = "shamir_metadata.json"):
        """
        メタデータマネージャーの初期化

        Args:
            metadata_file_path: メタデータファイルのパス
        """
        self.metadata_file_path = metadata_file_path
        self.metadata = self._load_metadata()

    def _load_metadata(self) -> Dict[str, Any]:
        """
        メタデータをファイルから読み込む

        Returns:
            メタデータの辞書
        """
        if not os.path.exists(self.metadata_file_path):
            # デフォルトのメタデータを作成
            default_metadata = self._create_default_metadata()
            # ディレクトリが存在しなければ作成
            os.makedirs(os.path.dirname(os.path.abspath(self.metadata_file_path)), exist_ok=True)
            # 初期メタデータを保存
            try:
                with open(self.metadata_file_path, 'w') as f:
                    json.dump(default_metadata, f, indent=2)
                print(f"DEBUG: MetadataManager - created new metadata file at {self.metadata_file_path}")
            except Exception as e:
                print(f"WARNING: MetadataManager - failed to create metadata file: {str(e)}")
            return default_metadata

        try:
            with open(self.metadata_file_path, 'r') as f:
                metadata = json.load(f)
                print(f"DEBUG: MetadataManager - loaded metadata from {self.metadata_file_path}")

            # バージョンチェック
            if metadata.get("version", 1) < 2:
                # 古いバージョンのメタデータを新バージョンに変換
                metadata = self._migrate_metadata(metadata)
                print(f"DEBUG: MetadataManager - migrated metadata from older version")

            return metadata
        except (json.JSONDecodeError, IOError) as e:
            print(f"WARNING: MetadataManager - error loading metadata: {str(e)}")
            # ファイル読み込みエラーの場合はデフォルトのメタデータを作成
            return self._create_default_metadata()

    def _create_default_metadata(self) -> Dict[str, Any]:
        """
        デフォルトのメタデータを作成

        Returns:
            デフォルトのメタデータ
        """
        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return {
            "version": 2,
            "created_at": current_time,
            "updated_at": current_time,
            "partitions": {
                "a": {
                    "chunk_count": 0,
                    "last_updated": None
                },
                "b": {
                    "chunk_count": 0,
                    "last_updated": None
                }
            },
            "file_info": {},
            "wal": {
                "active": False,
                "started_at": None,
                "operation": None
            }
        }

    def _migrate_metadata(self, old_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        古いバージョンのメタデータを新バージョンに変換

        Args:
            old_metadata: 古いメタデータ

        Returns:
            変換後のメタデータ
        """
        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # 基本情報を抽出
        chunk_count = old_metadata.get("chunk_count", 0)
        last_updated = old_metadata.get("last_updated", current_time)

        # 新しいメタデータ形式を作成
        new_metadata = {
            "version": 2,
            "created_at": old_metadata.get("created_at", current_time),
            "updated_at": current_time,
            "partitions": {
                "a": {
                    "chunk_count": chunk_count,
                    "last_updated": last_updated
                },
                "b": {
                    "chunk_count": chunk_count,
                    "last_updated": last_updated
                }
            },
            "file_info": old_metadata.get("file_info", {}),
            "wal": {
                "active": False,
                "started_at": None,
                "operation": None
            },
            "migrated_from_v1": True
        }

        return new_metadata

    def save_metadata(self) -> bool:
        """
        メタデータをファイルに保存

        Returns:
            保存成功ならTrue
        """
        # 更新日時を更新
        self.metadata["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            # ディレクトリが存在しない場合は作成
            os.makedirs(os.path.dirname(os.path.abspath(self.metadata_file_path)), exist_ok=True)

            # メタデータをJSON形式で保存
            with open(self.metadata_file_path, 'w') as f:
                json.dump(self.metadata, f, indent=2)

            return True
        except IOError:
            return False

    def get_partition_info(self, partition: str) -> Dict[str, Any]:
        """
        パーティションの情報を取得

        Args:
            partition: パーティション名 ('a' または 'b')

        Returns:
            パーティション情報
        """
        if partition not in ('a', 'b'):
            raise ValueError("パーティションは 'a' または 'b' のみ指定可能です")

        return self.metadata["partitions"].get(partition, {
            "chunk_count": 0,
            "last_updated": None
        })

    def update_partition_info(self, partition: str, chunk_count: int) -> bool:
        """
        パーティションの情報を更新

        Args:
            partition: パーティション名 ('a' または 'b')
            chunk_count: チャンク数

        Returns:
            更新成功ならTrue
        """
        if partition not in ('a', 'b'):
            raise ValueError("パーティションは 'a' または 'b' のみ指定可能です")

        # 現在時刻を取得
        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # パーティション情報を更新
        self.metadata["partitions"][partition] = {
            "chunk_count": chunk_count,
            "last_updated": current_time
        }

        # メタデータを保存
        return self.save_metadata()

    def register_file(self, file_path: str, partition_key: str, salt_value: str) -> bool:
        """
        ファイル情報を登録

        Args:
            file_path: ファイルパス
            partition_key: パーティションキー
            salt_value: ソルト値

        Returns:
            登録成功ならTrue
        """
        # ファイルIDを生成
        file_id = hashlib.sha256(
            (file_path + partition_key).encode('utf-8')
        ).hexdigest()[:16]

        # 現在時刻を取得
        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # ファイル情報を登録
        self.metadata.setdefault("file_info", {})[file_id] = {
            "path": file_path,
            "partition_key_hash": hashlib.sha256(partition_key.encode('utf-8')).hexdigest()[:16],
            "salt_hash": hashlib.sha256(salt_value.encode('utf-8')).hexdigest()[:16],
            "registered_at": current_time,
            "last_accessed": current_time
        }

        # メタデータを保存
        return self.save_metadata()

    def update_file_access(self, file_path: str, partition_key: str) -> bool:
        """
        ファイルのアクセス日時を更新

        Args:
            file_path: ファイルパス
            partition_key: パーティションキー

        Returns:
            更新成功ならTrue
        """
        # ファイルIDを生成
        file_id = hashlib.sha256(
            (file_path + partition_key).encode('utf-8')
        ).hexdigest()[:16]

        # ファイル情報が存在するか確認
        if file_id not in self.metadata.get("file_info", {}):
            return False

        # 現在時刻を取得
        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # アクセス日時を更新
        self.metadata["file_info"][file_id]["last_accessed"] = current_time

        # メタデータを保存
        return self.save_metadata()

    def start_wal(self, operation: str) -> bool:
        """
        Write Ahead Logging (WAL)を開始

        Args:
            operation: 実行する操作の種類

        Returns:
            開始成功ならTrue
        """
        # WALが既に実行中の場合はエラー
        if self.metadata.get("wal", {}).get("active", False):
            # WALが長時間実行中の場合はリセット
            started_at = self.metadata["wal"].get("started_at")
            if started_at:
                # 開始時刻をパース
                try:
                    started_time = time.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ")
                    started_timestamp = time.mktime(started_time)
                    current_timestamp = time.time()

                    # WALのタイムアウトをチェック
                    if current_timestamp - started_timestamp > ShamirConstants.WAL_TIMEOUT:
                        # タイムアウトしたWALをリセット
                        self.metadata["wal"] = {
                            "active": False,
                            "started_at": None,
                            "operation": None
                        }
                    else:
                        # アクティブなWALがある場合はエラー
                        return False
                except ValueError:
                    # 日時解析エラーの場合はリセット
                    self.metadata["wal"] = {
                        "active": False,
                        "started_at": None,
                        "operation": None
                    }
            else:
                return False

        # 現在時刻を取得
        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # WAL情報を設定
        self.metadata["wal"] = {
            "active": True,
            "started_at": current_time,
            "operation": operation
        }

        # メタデータを保存
        return self.save_metadata()

    def end_wal(self) -> bool:
        """
        Write Ahead Logging (WAL)を終了

        Returns:
            終了成功ならTrue
        """
        # WAL情報をリセット
        self.metadata["wal"] = {
            "active": False,
            "started_at": None,
            "operation": None
        }

        # メタデータを保存
        return self.save_metadata()

    def is_wal_active(self) -> bool:
        """
        WALがアクティブかどうかを確認

        Returns:
            WALがアクティブならTrue
        """
        return self.metadata.get("wal", {}).get("active", False)

    def get_wal_info(self) -> Dict[str, Any]:
        """
        WAL情報を取得

        Returns:
            WAL情報
        """
        return self.metadata.get("wal", {
            "active": False,
            "started_at": None,
            "operation": None
        })

    def get_summary(self) -> Dict[str, Any]:
        """
        メタデータの概要を取得

        Returns:
            メタデータの概要
        """
        file_count = len(self.metadata.get("file_info", {}))
        partition_a = self.get_partition_info('a')
        partition_b = self.get_partition_info('b')

        return {
            "version": self.metadata.get("version", 2),
            "created_at": self.metadata.get("created_at"),
            "updated_at": self.metadata.get("updated_at"),
            "file_count": file_count,
            "partition_a": partition_a,
            "partition_b": partition_b,
            "wal_active": self.is_wal_active()
        }