"""
暗号化ファイル形式の定義と処理

このモジュールでは、シャミア秘密分散法による複数平文復号システムの
暗号化ファイル形式を定義し、ファイルの読み書き、形式変換などの機能を提供します。
"""

import os
import json
import base64
import time
import zlib
from typing import Dict, List, Any, Optional, Tuple, Union
from .constants import ShamirConstants


class FileFormatV1:
    """
    バージョン1のファイル形式（元の実装形式）

    各シェアが冗長なメタデータを含む形式:
    {
        "metadata": {
            "salt": "base64_encoded_salt",
            "total_chunks": 10,
            "threshold": 3
        },
        "shares": [
            {
                "chunk_index": 0,
                "share_id": 123,
                "value": "12345678901234567890"
            },
            ...
        ]
    }
    """

    @staticmethod
    def read_file(file_path: str) -> Dict[str, Any]:
        """
        V1形式のファイルを読み込む

        Args:
            file_path: 読み込むファイルのパス

        Returns:
            ファイルの内容
        """
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            raise ValueError(f"ファイルの読み込みに失敗しました: {e}")

    @staticmethod
    def write_file(data: Dict[str, Any], file_path: str) -> None:
        """
        V1形式でファイルを書き込む

        Args:
            data: 書き込むデータ
            file_path: 書き込み先のファイルパス
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f)
        except IOError as e:
            raise ValueError(f"ファイルの書き込みに失敗しました: {e}")

    @staticmethod
    def validate(data: Dict[str, Any]) -> bool:
        """
        V1形式のデータを検証

        Args:
            data: 検証するデータ

        Returns:
            検証結果
        """
        # 必須フィールドをチェック
        if "metadata" not in data or "shares" not in data:
            return False

        metadata = data["metadata"]
        if not all(k in metadata for k in ["salt", "total_chunks", "threshold"]):
            return False

        # シェアの形式をチェック
        shares = data["shares"]
        if not shares or not isinstance(shares, list):
            return False

        # 各シェアのフィールドをチェック
        for share in shares:
            if not all(k in share for k in ["chunk_index", "share_id", "value"]):
                return False

        return True


class FileFormatV2:
    """
    バージョン2のファイル形式（最適化形式）

    シェア値のみを格納する効率的な形式:
    {
        "header": {
            "magic": "SHAMIR_MP",
            "version": 2,
            "salt": "base64_encoded_salt",
            "threshold": 3,
            "total_chunks": 10,
            "created_at": "2023-06-01T12:34:56Z",
            "share_id_space": 10000
        },
        "chunks": [
            [
                {"id": 123, "value": "12345678901234567890"},
                {"id": 456, "value": "09876543210987654321"},
                ...
            ],
            [
                {"id": 123, "value": "11111222223333344444"},
                {"id": 456, "value": "55555666667777788888"},
                ...
            ],
            ...
        ]
    }
    """

    @staticmethod
    def read_file(file_path: str) -> Dict[str, Any]:
        """
        V2形式のファイルを読み込む

        Args:
            file_path: 読み込むファイルのパス

        Returns:
            ファイルの内容
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # バージョンチェック
            header = data.get("header", {})
            if header.get("version") != 2 or header.get("magic") != ShamirConstants.FILE_HEADER_MAGIC:
                raise ValueError("サポートされていないファイル形式です")

            return data
        except (json.JSONDecodeError, IOError) as e:
            raise ValueError(f"ファイルの読み込みに失敗しました: {e}")

    @staticmethod
    def write_file(data: Dict[str, Any], file_path: str) -> None:
        """
        V2形式でファイルを書き込む

        Args:
            data: 書き込むデータ
            file_path: 書き込み先のファイルパス
        """
        try:
            # ヘッダーがない場合は作成
            if "header" not in data:
                data["header"] = {
                    "magic": ShamirConstants.FILE_HEADER_MAGIC,
                    "version": 2,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
            else:
                # 既存のヘッダーを更新
                data["header"]["magic"] = ShamirConstants.FILE_HEADER_MAGIC
                data["header"]["version"] = 2

            # 圧縮オプション（大きなファイルの場合）
            if os.path.exists(file_path) and os.path.getsize(file_path) > 1024 * 1024:  # 1MB以上
                # データをJSON文字列に変換
                json_str = json.dumps(data)
                # 圧縮
                compressed = zlib.compress(json_str.encode('utf-8'), level=9)
                # Base64エンコード
                encoded = base64.urlsafe_b64encode(compressed)

                # ヘッダー付きで書き込み
                with open(file_path, 'wb') as f:
                    f.write(b"SHAMIR_MP_COMPRESSED\n")
                    f.write(encoded)
            else:
                # 通常のJSON形式で書き込み
                with open(file_path, 'w') as f:
                    json.dump(data, f)
        except IOError as e:
            raise ValueError(f"ファイルの書き込みに失敗しました: {e}")

    @staticmethod
    def validate(data: Dict[str, Any]) -> bool:
        """
        V2形式のデータを検証

        Args:
            data: 検証するデータ

        Returns:
            検証結果
        """
        # 必須フィールドをチェック
        if "header" not in data or "chunks" not in data:
            return False

        header = data["header"]
        if not all(k in header for k in ["magic", "version", "salt", "threshold", "total_chunks"]):
            return False

        # バージョンとマジックをチェック
        if header["version"] != 2 or header["magic"] != ShamirConstants.FILE_HEADER_MAGIC:
            return False

        # チャンクの形式をチェック
        chunks = data["chunks"]
        if not isinstance(chunks, list) or not chunks:
            return False

        # 各チャンクのシェアをチェック
        for chunk in chunks:
            if not isinstance(chunk, list):
                return False

            # 各シェアのフィールドをチェック
            for share in chunk:
                if not isinstance(share, dict) or not all(k in share for k in ["id", "value"]):
                    return False

        return True


def convert_v1_to_v2(v1_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    V1形式からV2形式に変換

    Args:
        v1_data: V1形式のデータ

    Returns:
        V2形式のデータ
    """
    # V1形式の検証
    if not FileFormatV1.validate(v1_data):
        raise ValueError("無効なV1形式データです")

    # メタデータを抽出
    v1_metadata = v1_data["metadata"]
    total_chunks = v1_metadata["total_chunks"]

    # V2形式のヘッダーを作成
    v2_header = {
        "magic": ShamirConstants.FILE_HEADER_MAGIC,
        "version": 2,
        "salt": v1_metadata["salt"],
        "threshold": v1_metadata["threshold"],
        "total_chunks": total_chunks,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "share_id_space": ShamirConstants.SHARE_ID_SPACE,
        "converted_from_v1": True
    }

    # チャンク別にシェアを整理
    chunk_shares = [[] for _ in range(total_chunks)]
    for share in v1_data["shares"]:
        chunk_idx = share["chunk_index"]
        # V2形式のシェアに変換
        v2_share = {
            "id": share["share_id"],
            "value": share["value"]
        }
        chunk_shares[chunk_idx].append(v2_share)

    # V2形式のデータを構築
    v2_data = {
        "header": v2_header,
        "chunks": chunk_shares
    }

    return v2_data


def convert_v2_to_v1(v2_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    V2形式からV1形式に変換（後方互換性用）

    Args:
        v2_data: V2形式のデータ

    Returns:
        V1形式のデータ
    """
    # V2形式の検証
    if not FileFormatV2.validate(v2_data):
        raise ValueError("無効なV2形式データです")

    # メタデータを抽出
    v2_header = v2_data["header"]

    # V1形式のメタデータを作成
    v1_metadata = {
        "salt": v2_header["salt"],
        "total_chunks": v2_header["total_chunks"],
        "threshold": v2_header["threshold"]
    }

    # V1形式のシェアリストを作成
    v1_shares = []
    for chunk_idx, chunk in enumerate(v2_data["chunks"]):
        for share in chunk:
            # V1形式のシェアに変換
            v1_share = {
                "chunk_index": chunk_idx,
                "share_id": share["id"],
                "value": share["value"]
            }
            v1_shares.append(v1_share)

    # V1形式のデータを構築
    v1_data = {
        "metadata": v1_metadata,
        "shares": v1_shares
    }

    return v1_data


def detect_file_format(file_path: str) -> int:
    """
    ファイルの形式バージョンを検出

    Args:
        file_path: 検出するファイルのパス

    Returns:
        ファイル形式バージョン（1または2）
    """
    try:
        # まずファイルが圧縮されているかチェック
        with open(file_path, 'rb') as f:
            first_line = f.readline().strip()
            if first_line == b"SHAMIR_MP_COMPRESSED":
                # 圧縮されたV2形式
                return 2

        # 通常のJSONファイルとして読み込み
        with open(file_path, 'r') as f:
            data = json.load(f)

        # ヘッダーとマジックの有無でバージョンを判定
        if "header" in data and "magic" in data["header"] and data["header"]["magic"] == ShamirConstants.FILE_HEADER_MAGIC:
            return data["header"]["version"]
        elif "metadata" in data and "shares" in data:
            return 1
        else:
            raise ValueError("不明なファイル形式です")
    except Exception as e:
        raise ValueError(f"ファイル形式の検出に失敗しました: {e}")


def load_encrypted_file(file_path: str) -> Dict[str, Any]:
    """
    暗号化ファイルを読み込み、最新の形式に変換

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        V2形式のデータ
    """
    try:
        # ファイル形式を検出
        format_version = detect_file_format(file_path)

        if format_version == 1:
            # V1形式を読み込み
            v1_data = FileFormatV1.read_file(file_path)
            # V2形式に変換
            return convert_v1_to_v2(v1_data)
        elif format_version == 2:
            # V2形式を読み込み
            return FileFormatV2.read_file(file_path)
        else:
            raise ValueError(f"サポートされていないファイル形式バージョンです: {format_version}")
    except Exception as e:
        raise ValueError(f"ファイルの読み込みに失敗しました: {e}")


def save_encrypted_file(data: Dict[str, Any], file_path: str, format_version: int = ShamirConstants.FILE_FORMAT_VERSION) -> None:
    """
    暗号化ファイルを保存

    Args:
        data: 保存するデータ
        file_path: 保存先のファイルパス
        format_version: 保存するファイル形式バージョン
    """
    try:
        if format_version == 1:
            # データがV2形式の場合、V1形式に変換
            if "header" in data and "chunks" in data:
                data = convert_v2_to_v1(data)

            # V1形式で保存
            FileFormatV1.write_file(data, file_path)
        elif format_version == 2:
            # データがV1形式の場合、V2形式に変換
            if "metadata" in data and "shares" in data:
                data = convert_v1_to_v2(data)

            # V2形式で保存
            FileFormatV2.write_file(data, file_path)
        else:
            raise ValueError(f"サポートされていないファイル形式バージョンです: {format_version}")
    except Exception as e:
        raise ValueError(f"ファイルの保存に失敗しました: {e}")


def convert_file_format(input_path: str, output_path: str, target_version: int) -> None:
    """
    暗号化ファイルの形式を変換

    Args:
        input_path: 入力ファイルのパス
        output_path: 出力ファイルのパス
        target_version: 変換先のバージョン
    """
    try:
        # 入力ファイルを読み込み
        data = load_encrypted_file(input_path)

        # 指定バージョンで保存
        save_encrypted_file(data, output_path, target_version)
    except Exception as e:
        raise ValueError(f"ファイル形式の変換に失敗しました: {e}")


def extract_metadata(file_path: str) -> Dict[str, Any]:
    """
    暗号化ファイルからメタデータを抽出

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        メタデータ
    """
    try:
        # ファイル形式を検出
        format_version = detect_file_format(file_path)

        if format_version == 1:
            # V1形式を読み込み
            data = FileFormatV1.read_file(file_path)
            return data["metadata"]
        elif format_version == 2:
            # V2形式を読み込み
            data = FileFormatV2.read_file(file_path)
            return data["header"]
        else:
            raise ValueError(f"サポートされていないファイル形式バージョンです: {format_version}")
    except Exception as e:
        raise ValueError(f"メタデータの抽出に失敗しました: {e}")