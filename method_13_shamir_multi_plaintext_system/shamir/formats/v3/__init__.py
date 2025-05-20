"""
シャミア秘密分散法による複数平文復号システムの新しいファイル形式（V3）

このモジュールでは、設計書に完全準拠した新しいファイル形式を提供します。
過去形式との互換性は考慮せず、メタデータを極小化（ソルト値のみ）し、
完全インデックスベースのシェア保存を実装しています。
"""

import os
import json
import base64
import uuid
import secrets
import time
from typing import Dict, List, Any, Optional, Tuple, Union

from ...constants import ShamirConstants

class FileFormatV3:
    """
    バージョン3のファイル形式（設計書完全準拠）

    最小限のヘッダー情報（ソルト値のみ）と一次元配列でのシェア値保存形式:
    {
        "header": {
            "salt": "base64_encoded_salt"
        },
        "values": [
            "value1", "value2", "value3", ... // 一次元配列で全シェア値を格納
        ]
    }
    """

    @staticmethod
    def read_file(file_path: str) -> Dict[str, Any]:
        """
        V3形式のファイルを読み込む

        Args:
            file_path: 読み込むファイルのパス

        Returns:
            ファイルの内容
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # 必須ヘッダーの存在確認
            if "header" not in data or "salt" not in data["header"]:
                raise ValueError("無効なV3ファイル形式です。必須ヘッダーが不足しています。")

            # 値の配列の存在確認
            if "values" not in data or not isinstance(data["values"], list):
                raise ValueError("無効なV3ファイル形式です。values配列が不足しています。")

            return data
        except (json.JSONDecodeError, IOError) as e:
            raise ValueError(f"ファイルの読み込みに失敗しました: {e}")

    @staticmethod
    def write_file(data: Dict[str, Any], file_path: str) -> None:
        """
        V3形式でファイルを書き込む

        Args:
            data: 書き込むデータ
            file_path: 書き込み先のファイルパス
        """
        try:
            # ヘッダーの存在確認
            if "header" not in data or "salt" not in data["header"]:
                raise ValueError("無効なV3データ形式です。ヘッダーが正しく構成されていません。")

            # 値の配列の存在確認
            if "values" not in data or not isinstance(data["values"], list):
                raise ValueError("無効なV3データ形式です。values配列が正しく構成されていません。")

            # ファイルに書き込み
            with open(file_path, 'w') as f:
                json.dump(data, f)
        except IOError as e:
            raise ValueError(f"ファイルの書き込みに失敗しました: {e}")

    @staticmethod
    def validate(data: Dict[str, Any]) -> bool:
        """
        V3形式のデータを検証

        Args:
            data: 検証するデータ

        Returns:
            検証結果
        """
        # 基本構造をチェック
        if not isinstance(data, dict):
            return False

        # 必須フィールドの存在チェック
        if "header" not in data or "values" not in data:
            return False

        # ヘッダー内のソルト値をチェック
        header = data["header"]
        if not isinstance(header, dict) or "salt" not in header:
            return False

        # 値の配列をチェック
        values = data["values"]
        if not isinstance(values, list) or not values:
            return False

        return True

    @staticmethod
    def create_empty_file(salt: Optional[bytes] = None) -> Dict[str, Any]:
        """
        空のV3形式ファイルデータを作成する

        Args:
            salt: ソルト値（Noneの場合は自動生成）

        Returns:
            空のV3形式データ
        """
        # ソルト値を生成または変換
        if salt is None:
            salt = secrets.token_bytes(16)
            salt_base64 = base64.urlsafe_b64encode(salt).decode('ascii')
        elif isinstance(salt, bytes):
            salt_base64 = base64.urlsafe_b64encode(salt).decode('ascii')
        else:
            salt_base64 = salt

        # 計算パラメータの取得
        share_id_space = ShamirConstants.SHARE_ID_SPACE

        # チャンク数の計算（この例では1チャンクで初期化）
        total_chunks = 1

        # 一次元配列を初期化
        total_values = total_chunks * share_id_space
        values = ["0"] * total_values

        # 最小限のヘッダー情報でデータ構造を構築
        data = {
            "header": {
                "salt": salt_base64
            },
            "values": values
        }

        return data

    @staticmethod
    def fixed_length_serialize(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        データを完全固定長形式でシリアライズ

        Args:
            data: シリアライズするデータ

        Returns:
            固定長シリアライズされたデータ
        """
        # ヘッダー情報を確認
        if "header" not in data or "salt" not in data["header"]:
            raise ValueError("無効なデータ形式です。ヘッダーが正しく構成されていません。")

        salt = data["header"]["salt"]

        # 全てのシェア値を固定長形式でシリアライズ
        if "values" not in data or not isinstance(data["values"], list):
            raise ValueError("無効なデータ形式です。values配列が正しく構成されていません。")

        serialized_values = []
        for value in data["values"]:
            # 各シェア値を固定長に変換
            serialized_value = value.ljust(ShamirConstants.FIXED_VALUE_LENGTH, '0')
            serialized_values.append(serialized_value)

        # 固定長シリアライズ済みデータを構築
        serialized_data = {
            "header": {
                "salt": salt
            },
            "values": serialized_values
        }

        return serialized_data

    @staticmethod
    def get_share_index(chunk_index: int, share_id: int) -> int:
        """
        多段MAP方式で特定されたチャンクとシェアIDから一次元配列内の位置を算出

        Args:
            chunk_index: チャンクインデックス
            share_id: シェアID

        Returns:
            一次元配列内のインデックス
        """
        # パーティション設計パラメータを取得
        share_id_space = ShamirConstants.SHARE_ID_SPACE

        # 線形インデックス計算: チャンク番号 × シェアID空間サイズ + (シェアID - 1)
        return (chunk_index * share_id_space) + (share_id - 1)

    @staticmethod
    def get_share_value(data: Dict[str, Any], chunk_index: int, share_id: int) -> Optional[str]:
        """
        多段MAP方式で特定されたシェアの値を取得

        Args:
            data: 暗号化データ
            chunk_index: チャンクインデックス
            share_id: シェアID

        Returns:
            シェア値またはNone（値が見つからない場合）
        """
        # 必ず新しい形式であることを検証
        if "header" not in data or "values" not in data:
            raise ValueError("非対応のファイル形式です。V3形式のみがサポートされています。")

        # share_id_spaceは配列から計算
        values_length = len(data["values"])

        # チャンク数の計算
        share_id_space = ShamirConstants.SHARE_ID_SPACE
        total_chunks = values_length // share_id_space

        # インデックスの計算
        index = FileFormatV3.get_share_index(chunk_index, share_id)

        # インデックスが範囲内かチェック
        if 0 <= index < len(data["values"]):
            return data["values"][index]

        return None

    @staticmethod
    def set_share_value(data: Dict[str, Any], chunk_index: int, share_id: int, value: str) -> Dict[str, Any]:
        """
        多段MAP方式で特定されたシェアに値を設定

        Args:
            data: 暗号化データ
            chunk_index: チャンクインデックス
            share_id: シェアID
            value: 設定するシェア値

        Returns:
            更新された暗号化データ
        """
        # 必ず新しい形式であることを検証
        if "header" not in data or "values" not in data:
            raise ValueError("非対応のファイル形式です。V3形式のみがサポートされています。")

        # share_id_spaceは配列から計算
        values_length = len(data["values"])

        # チャンク数の計算
        share_id_space = ShamirConstants.SHARE_ID_SPACE
        total_chunks = values_length // share_id_space

        # 必要に応じて配列を拡張
        if chunk_index >= total_chunks:
            additional_chunks = chunk_index - total_chunks + 1
            additional_values = ["0"] * (additional_chunks * share_id_space)
            data["values"].extend(additional_values)

        # インデックスの計算と値の設定
        index = FileFormatV3.get_share_index(chunk_index, share_id)

        # インデックスが範囲内かを確認
        if 0 <= index < len(data["values"]):
            data["values"][index] = value
        else:
            raise ValueError(f"インデックスが範囲外です: {index}")

        return data

    @staticmethod
    def generate_unique_filename(base_dir='./output', prefix='encrypted', ext='.json'):
        """
        一意なファイル名を生成する関数

        Args:
            base_dir: 出力ディレクトリパス
            prefix: ファイル名の接頭辞
            ext: ファイル拡張子

        Returns:
            生成されたファイルパス
        """
        # ディレクトリが存在しない場合は作成
        os.makedirs(base_dir, exist_ok=True)

        # 常に新たなUUIDを生成（既存ファイルは上書きしない）
        # 暗号論的に安全な乱数ベースでUUID生成（バージョン4）
        file_uuid = str(uuid.uuid4())

        # ファイル名を組み立て（ファイル種別は含めない）
        filename = f"{prefix}_{file_uuid}{ext}"

        # 完全なパスを返す
        return os.path.join(base_dir, filename)

    @staticmethod
    def generate_empty_encrypted_file(output_dir='./output'):
        """
        初期化時に全てのシェアIDをガベージシェアで埋めた暗号化ファイルの雛形を生成

        Args:
            output_dir: 出力ディレクトリ

        Returns:
            生成したファイルパス
        """
        # 出力ディレクトリの確認・作成
        os.makedirs(output_dir, exist_ok=True)

        # UUIDを用いたファイル名を生成
        output_path = FileFormatV3.generate_unique_filename(output_dir)

        # ソルト値を生成
        salt = secrets.token_bytes(16)

        # パーティション設計パラメータを取得
        share_id_space = ShamirConstants.SHARE_ID_SPACE

        # チャンク数の計算（この例では1チャンクで初期化）
        total_chunks = 1

        # 空のファイルデータを作成
        empty_file = FileFormatV3.create_empty_file(salt)

        # ファイル内の全値をガベージシェアで埋める
        values = empty_file["values"]
        for i in range(len(values)):
            # 大きな素数p未満のランダム値を生成（有限体GF(p)上で均一分布）
            random_value = str(secrets.randbelow(int(ShamirConstants.PRIME - 1)) + 1)
            values[i] = random_value

        # 固定長シリアライズを適用
        serialized_data = FileFormatV3.fixed_length_serialize(empty_file)

        # ファイルに書き込み
        FileFormatV3.write_file(serialized_data, output_path)

        return output_path
