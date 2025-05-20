"""
パーティションキー管理

このモジュールでは、シャミア秘密分散法におけるパーティションキーの管理機能を提供します。
キーの生成、読み込み、保存、検証などの機能を含みます。
"""

import os
import json
import base64
import hashlib
import secrets
import time
from typing import Dict, List, Optional, Any, Tuple
from .constants import ShamirConstants
from .partition import normalize_partition_key, generate_partition_map_key


class PartitionKeyManager:
    """パーティションキーを管理するクラス"""

    def __init__(self, key_file_path: str = "keys.json"):
        """
        パーティションキーマネージャーの初期化

        Args:
            key_file_path: キーファイルのパス
        """
        self.key_file_path = key_file_path
        self.keys = self._load_keys()

    def _load_keys(self) -> Dict[str, Any]:
        """
        キーファイルから鍵情報を読み込む

        Returns:
            鍵情報の辞書
        """
        if not os.path.exists(self.key_file_path):
            # キーファイルが存在しない場合は、空の鍵情報を作成
            return {
                "version": 1,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "a_key": None,
                "b_key": None
            }

        try:
            with open(self.key_file_path, 'r') as f:
                keys = json.load(f)

            # バージョンチェック（将来の拡張用）
            if "version" not in keys:
                keys["version"] = 1

            return keys
        except (json.JSONDecodeError, IOError):
            # 読み込みエラーの場合は、空の鍵情報を作成
            return {
                "version": 1,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "a_key": None,
                "b_key": None
            }

    def _save_keys(self) -> bool:
        """
        鍵情報をファイルに保存

        Returns:
            保存成功ならTrue
        """
        # 更新日時を設定
        self.keys["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            # キーファイルのディレクトリが存在しない場合は作成
            os.makedirs(os.path.dirname(os.path.abspath(self.key_file_path)), exist_ok=True)

            # 鍵情報を保存
            with open(self.key_file_path, 'w') as f:
                json.dump(self.keys, f, indent=2)

            return True
        except IOError:
            return False

    def get_partition_key(self, partition: str) -> Optional[str]:
        """
        パーティションキーを取得する

        Args:
            partition: パーティション名（'a'または'b'）

        Returns:
            パーティションキー（存在しない場合はNone）
        """
        if partition not in ('a', 'b'):
            raise ValueError("パーティションは 'a' または 'b' のみ指定可能です")

        return self.keys.get(f"{partition}_key")

    def set_partition_key(self, partition: str, key: str) -> bool:
        """
        パーティションキーを設定する

        Args:
            partition: パーティション名（'a'または'b'）
            key: パーティションキー

        Returns:
            設定が成功した場合True
        """
        if partition not in ('a', 'b'):
            raise ValueError("パーティションは 'a' または 'b' のみ指定可能です")

        # キーの正規化
        normalized_key = normalize_partition_key(key)

        # 鍵情報に保存
        self.keys[f"{partition}_key"] = normalized_key

        return self._save_keys()

    def generate_and_set_partition_keys(self) -> Tuple[str, str]:
        """
        パーティションキーを自動生成して設定

        Returns:
            (パーティションA用キー, パーティションB用キー)のタプル
        """
        # パーティションキーを生成
        a_key = generate_partition_map_key()
        b_key = generate_partition_map_key()

        # 同一キーの発生を防止（衝突確率は非常に低いが念のため）
        while a_key == b_key:
            b_key = generate_partition_map_key()

        # キーを設定
        self.set_partition_key('a', a_key)
        self.set_partition_key('b', b_key)

        return (a_key, b_key)

    def validate_partition_keys(self) -> Dict[str, Any]:
        """
        パーティションキーの検証

        Returns:
            検証結果を含む辞書
        """
        a_key = self.get_partition_key('a')
        b_key = self.get_partition_key('b')

        # 両方のキーが存在するか確認
        has_a_key = a_key is not None
        has_b_key = b_key is not None

        # キーの重複がないか確認
        unique_keys = True
        if has_a_key and has_b_key:
            unique_keys = a_key != b_key

        # 検証結果
        return {
            "has_a_key": has_a_key,
            "has_b_key": has_b_key,
            "unique_keys": unique_keys,
            "all_valid": has_a_key and has_b_key and unique_keys
        }

    def get_key_information(self) -> Dict[str, Any]:
        """
        キー情報の取得

        Returns:
            キー情報を含む辞書
        """
        a_key = self.get_partition_key('a')
        b_key = self.get_partition_key('b')

        # キー情報（セキュリティのため部分的な情報のみ）
        info = {
            "is_valid": self.validate_partition_keys()["all_valid"],
            "a_key_prefix": a_key[:6] + "..." if a_key else None,
            "b_key_prefix": b_key[:6] + "..." if b_key else None,
            "a_key_length": len(a_key) if a_key else 0,
            "b_key_length": len(b_key) if b_key else 0,
            "stored_at": self.keys.get("stored_at"),
            "last_validated": self.keys.get("last_validated")
        }

        return info

    def export_keys(self, export_path: str = "exported_keys.json") -> bool:
        """
        キー情報をエクスポート

        Args:
            export_path: エクスポート先ファイルパス

        Returns:
            エクスポート成功ならTrue
        """
        try:
            # キー情報をコピー
            export_data = {
                "partition_keys": {
                    "a": self.keys["partition_keys"]["a"],
                    "b": self.keys["partition_keys"]["b"]
                },
                "metadata": {
                    "exported_at": self.keys["metadata"]["updated_at"],
                    "version": self.keys["metadata"]["version"]
                }
            }

            # エクスポート情報を保存
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)

            return True
        except IOError:
            return False

    def import_keys(self, import_path: str) -> bool:
        """
        キー情報をインポート

        Args:
            import_path: インポート元ファイルパス

        Returns:
            インポート成功ならTrue
        """
        try:
            # インポートデータを読み込み
            with open(import_path, 'r') as f:
                import_data = json.load(f)

            # パーティションキーをインポート
            if "partition_keys" in import_data:
                a_key = import_data["partition_keys"].get("a")
                b_key = import_data["partition_keys"].get("b")

                if a_key:
                    self.set_partition_key('a', a_key)

                if b_key:
                    self.set_partition_key('b', b_key)

                return True
            else:
                return False
        except (json.JSONDecodeError, IOError):
            return False