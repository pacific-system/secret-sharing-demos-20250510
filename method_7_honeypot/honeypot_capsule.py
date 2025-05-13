"""
ハニーポットカプセル生成機構モジュール

複数の暗号化データを単一のカプセルにまとめ、鍵の種類に応じて
異なるデータを復元可能にするための機能を提供します。
"""

import os
import sys
import hashlib
import hmac
import secrets
import struct
import json
import random
from typing import Dict, List, Tuple, Any, Optional, Union, BinaryIO
import io

# 内部モジュールからのインポート
from .trapdoor import (
    KEY_TYPE_TRUE, KEY_TYPE_FALSE,
    generate_honey_token
)
from .config import TOKEN_SIZE

# カプセル形式のバージョンとマジックナンバー
CAPSULE_VERSION = 1
CAPSULE_MAGIC = b"HPOT01"

# データブロックのタイプ
DATA_TYPE_TRUE = 1
DATA_TYPE_FALSE = 2
DATA_TYPE_META = 3
DATA_TYPE_DUMMY = 4  # ダミーデータ - 攻撃者を混乱させるためのもの

# 分割処理のための定数
DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024  # 10MB
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50MB

# カプセルヘッダーの構造
# | マジック(6) | バージョン(2) | データブロック数(4) | シード(16) | 予約(4) |
HEADER_FORMAT = "!6sHI16sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# データブロックヘッダーの構造
# | ブロックタイプ(4) | ブロックサイズ(4) | データオフセット(8) | ブロックハッシュ(32) |
BLOCK_HEADER_FORMAT = "!IIQ32s"
BLOCK_HEADER_SIZE = struct.calcsize(BLOCK_HEADER_FORMAT)


class HoneypotCapsule:
    """
    ハニーポットカプセルを生成・管理するクラス

    このクラスは、複数のデータブロックを効率的に格納し、
    データの整合性を保証する機能を提供します。
    """

    def __init__(self):
        """
        新しいハニーポットカプセルを初期化
        """
        self.version = CAPSULE_VERSION
        self.magic = CAPSULE_MAGIC
        self.seed = os.urandom(16)
        self.blocks = []
        self.metadata = {}

        # 内部状態 - これは実際の処理には使用されないダミー
        self._counter = int.from_bytes(os.urandom(4), byteorder='big') % 100

    def add_data_block(self, data: bytes, block_type: int, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        データブロックをカプセルに追加

        Args:
            data: 追加するデータ
            block_type: ブロックタイプ（DATA_TYPE_*）
            metadata: ブロックに関連するメタデータ（省略可）
        """
        # データハッシュの計算
        block_hash = hashlib.sha256(self.seed + data).digest()

        # ブロック情報を追加
        self.blocks.append({
            'type': block_type,
            'size': len(data),
            'hash': block_hash,
            'data': data,
            'metadata': metadata or {}
        })

        # ダミーカウンタ操作
        self._counter = (self._counter + len(data) % 10) % 100

    def add_true_data(self, data: bytes, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        正規データをカプセルに追加

        Args:
            data: 正規データ（暗号化済み）
            metadata: メタデータ（省略可）
        """
        self.add_data_block(data, DATA_TYPE_TRUE, metadata)

        # ダミーデータも一緒に追加（攻撃者を混乱させるため）
        # 実際の処理には影響しない
        if random.random() < 0.5:  # 50%の確率でダミーを追加
            dummy_size = random.randint(64, 256)
            dummy_data = os.urandom(dummy_size)
            self.add_data_block(dummy_data, DATA_TYPE_DUMMY, {'purpose': 'decoy'})

    def add_false_data(self, data: bytes, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        非正規データをカプセルに追加

        Args:
            data: 非正規データ（暗号化済み）
            metadata: メタデータ（省略可）
        """
        self.add_data_block(data, DATA_TYPE_FALSE, metadata)

        # ダミーデータも一緒に追加（攻撃者を混乱させるため）
        # 実際の処理には影響しない
        if random.random() < 0.5:  # 50%の確率でダミーを追加
            dummy_size = random.randint(64, 256)
            dummy_data = os.urandom(dummy_size)
            self.add_data_block(dummy_data, DATA_TYPE_DUMMY, {'purpose': 'decoy'})

    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        カプセル全体のメタデータを設定

        Args:
            metadata: メタデータ辞書
        """
        self.metadata = metadata

    def get_block_by_type(self, block_type: int) -> Optional[Dict[str, Any]]:
        """
        指定されたタイプのブロックを取得

        Args:
            block_type: ブロックタイプ

        Returns:
            ブロック情報辞書（存在しない場合はNone）
        """
        for block in self.blocks:
            if block['type'] == block_type:
                return block
        return None

    def serialize(self) -> bytes:
        """
        カプセルをバイナリ形式にシリアライズ

        Returns:
            シリアライズされたカプセルのバイト列
        """
        # メタデータをJSON形式に変換
        meta_json = json.dumps(self.metadata).encode('utf-8')

        # メタデータブロックを追加
        if meta_json:
            self.add_data_block(meta_json, DATA_TYPE_META)

        # バッファを準備
        buffer = io.BytesIO()

        # カプセルヘッダーを書き込み
        header = struct.pack(
            HEADER_FORMAT,
            self.magic,
            self.version,
            len(self.blocks),
            self.seed,
            0  # 予約フィールド
        )
        buffer.write(header)

        # データオフセットを計算するための現在位置
        current_pos = HEADER_SIZE + BLOCK_HEADER_SIZE * len(self.blocks)

        # ブロックヘッダーの位置を記録
        block_headers_pos = buffer.tell()

        # ブロックヘッダー用のダミーデータを書き込み（後で上書き）
        for _ in self.blocks:
            buffer.write(b'\x00' * BLOCK_HEADER_SIZE)

        # 各ブロックデータを書き込み
        for i, block in enumerate(self.blocks):
            # ブロックデータの位置を記録
            data_pos = buffer.tell()

            # データを書き込み
            buffer.write(block['data'])

            # ブロックヘッダーを作成
            block_header = struct.pack(
                BLOCK_HEADER_FORMAT,
                block['type'],        # ブロックタイプ
                block['size'],        # ブロックサイズ
                data_pos,             # データオフセット
                block['hash']         # ブロックハッシュ
            )

            # ファイルポインタをブロックヘッダー位置に移動
            current_pos = buffer.tell()
            buffer.seek(block_headers_pos + i * BLOCK_HEADER_SIZE)

            # ブロックヘッダーを書き込み
            buffer.write(block_header)

            # ファイルポインタを元の位置に戻す
            buffer.seek(current_pos)

        # チェックサムを計算
        buffer_value = buffer.getvalue()
        checksum = hashlib.sha256(buffer_value).digest()

        # チェックサムを追加
        buffer.write(checksum)

        return buffer.getvalue()

    @classmethod
    def deserialize(cls, data: bytes) -> 'HoneypotCapsule':
        """
        バイナリ形式からカプセルを復元

        Args:
            data: シリアライズされたカプセルのバイト列

        Returns:
            復元されたHoneypotCapsuleオブジェクト

        Raises:
            ValueError: データ形式が不正な場合
        """
        # チェックサムを分離
        capsule_data = data[:-32]
        expected_checksum = data[-32:]

        # チェックサムを検証
        actual_checksum = hashlib.sha256(capsule_data).digest()
        if actual_checksum != expected_checksum:
            raise ValueError("カプセルの整合性検証に失敗しました: チェックサムが一致しません")

        # バッファを準備
        buffer = io.BytesIO(capsule_data)

        # ヘッダーを読み込み
        header_data = buffer.read(HEADER_SIZE)
        if len(header_data) != HEADER_SIZE:
            raise ValueError("カプセル形式が不正です: ヘッダーの読み込みに失敗しました")

        magic, version, num_blocks, seed, _ = struct.unpack(HEADER_FORMAT, header_data)

        # マジックとバージョンを検証
        if magic != CAPSULE_MAGIC:
            raise ValueError(f"カプセル形式が不正です: 不明なマジックナンバー {magic}")

        if version != CAPSULE_VERSION:
            raise ValueError(f"対応していないカプセルバージョンです: {version}")

        # 新しいカプセルを作成
        capsule = cls()
        capsule.version = version
        capsule.magic = magic
        capsule.seed = seed

        # ブロックヘッダーを読み込み
        block_headers = []
        for _ in range(num_blocks):
            block_header_data = buffer.read(BLOCK_HEADER_SIZE)
            if len(block_header_data) != BLOCK_HEADER_SIZE:
                raise ValueError("カプセル形式が不正です: ブロックヘッダーの読み込みに失敗しました")

            block_type, block_size, data_offset, block_hash = struct.unpack(BLOCK_HEADER_FORMAT, block_header_data)
            block_headers.append({
                'type': block_type,
                'size': block_size,
                'offset': data_offset,
                'hash': block_hash
            })

        # 各ブロックデータを読み込み
        for header in block_headers:
            # データ位置に移動
            buffer.seek(header['offset'])

            # データを読み込み
            block_data = buffer.read(header['size'])
            if len(block_data) != header['size']:
                raise ValueError("カプセル形式が不正です: ブロックデータの読み込みに失敗しました")

            # ハッシュを検証
            actual_hash = hashlib.sha256(seed + block_data).digest()
            if actual_hash != header['hash']:
                raise ValueError("カプセルの整合性検証に失敗しました: ブロックハッシュが一致しません")

            # メタデータブロックの場合は、カプセルのメタデータとして設定
            if header['type'] == DATA_TYPE_META:
                try:
                    capsule.metadata = json.loads(block_data.decode('utf-8'))
                except json.JSONDecodeError:
                    raise ValueError("カプセル形式が不正です: メタデータの解析に失敗しました")
            # ダミーデータは無視
            elif header['type'] == DATA_TYPE_DUMMY:
                pass
            else:
                # 通常のデータブロックの場合は追加
                capsule.add_data_block(block_data, header['type'])

        return capsule


class HoneypotCapsuleFactory:
    """
    ハニーポットカプセルを生成するためのファクトリークラス

    このクラスは、トラップドアパラメータを利用して、正規データと非正規データを
    包含するハニーポットカプセルを生成します。
    """

    def __init__(self, trapdoor_params: Dict[str, Any]):
        """
        ファクトリーを初期化

        Args:
            trapdoor_params: トラップドアパラメータ
        """
        self.trapdoor_params = trapdoor_params

        # 内部状態（実際には使用されない）
        self._state = os.urandom(8)

    def create_capsule(self, true_data: bytes, false_data: bytes,
                      metadata: Optional[Dict[str, Any]] = None) -> HoneypotCapsule:
        """
        正規データと非正規データから新しいハニーポットカプセルを作成

        Args:
            true_data: 正規データ（暗号化済み）
            false_data: 非正規データ（暗号化済み）
            metadata: メタデータ（省略可）

        Returns:
            作成されたハニーポットカプセル
        """
        # 新しいカプセルを作成
        capsule = HoneypotCapsule()

        # ハニートークンを生成
        true_token = generate_honey_token(KEY_TYPE_TRUE, self.trapdoor_params)
        false_token = generate_honey_token(KEY_TYPE_FALSE, self.trapdoor_params)

        # 正規データにトークンを関連付け
        true_data_with_token = self._bind_token_to_data(true_data, true_token)

        # 非正規データにトークンを関連付け
        false_data_with_token = self._bind_token_to_data(false_data, false_token)

        # カプセルにデータを追加
        capsule.add_true_data(true_data_with_token)
        capsule.add_false_data(false_data_with_token)

        # メタデータを設定（省略可）
        if metadata:
            capsule.set_metadata(metadata)

        # 追加のダミーデータを生成（50%の確率）
        if random.random() < 0.5:
            # ダミーデータサイズはランダム（実際の処理には影響しない）
            dummy_size = random.randint(128, 512)
            dummy_data = os.urandom(dummy_size)
            capsule.add_data_block(dummy_data, DATA_TYPE_DUMMY, {'purpose': 'confusion'})

        return capsule

    def _bind_token_to_data(self, data: bytes, token: bytes) -> bytes:
        """
        トークンをデータに関連付ける

        この関数はトークンとデータを安全に結合し、
        トークンをデータから分離可能にします。

        Args:
            data: バインドするデータ
            token: バインドするトークン

        Returns:
            トークンが関連付けられたデータ
        """
        # 単純にトークンとデータを結合
        # トークンが先頭に来るようにすることで、データ抽出時に分離しやすくなる
        result = token + data

        # 追加のマスク処理はせず単純に結合
        # これにより、extract_data_from_capsule関数で正確に分離できる
        return result


def extract_data_from_capsule(capsule: HoneypotCapsule, key_type: str) -> Optional[bytes]:
    """
    カプセルから指定された鍵タイプに対応するデータを抽出

    Args:
        capsule: ハニーポットカプセル
        key_type: 鍵タイプ（"true" または "false"）

    Returns:
        抽出されたデータ（存在しない場合はNone）
    """
    # 鍵タイプに基づいてブロックタイプを決定
    block_type = DATA_TYPE_TRUE if key_type == KEY_TYPE_TRUE else DATA_TYPE_FALSE

    # 対応するブロックを取得
    block = capsule.get_block_by_type(block_type)
    if not block:
        return None

    # ブロックからデータを抽出
    data_with_token = block['data']

    # トークンとデータを分離（トークンは先頭TOKEN_SIZEバイト）
    token = data_with_token[:TOKEN_SIZE]
    data = data_with_token[TOKEN_SIZE:]

    return data


def create_honeypot_file(true_data: bytes, false_data: bytes,
                         trapdoor_params: Dict[str, Any],
                         metadata: Optional[Dict[str, Any]] = None) -> bytes:
    """
    正規データと非正規データからハニーポットファイルを作成

    Args:
        true_data: 正規データ（暗号化済み）
        false_data: 非正規データ（暗号化済み）
        trapdoor_params: トラップドアパラメータ
        metadata: メタデータ（省略可）

    Returns:
        ハニーポットファイルのバイト列
    """
    # ファクトリーを作成
    factory = HoneypotCapsuleFactory(trapdoor_params)

    # カプセルを作成
    capsule = factory.create_capsule(true_data, false_data, metadata)

    # カプセルをシリアライズ
    return capsule.serialize()


def create_large_honeypot_file(true_data: bytes, false_data: bytes,
                              trapdoor_params: Dict[str, Any],
                              metadata: Optional[Dict[str, Any]] = None,
                              chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """
    大きなデータ用のハニーポットファイルを作成（分割処理）

    大きなファイルを扱う場合に、データをチャンク単位で処理し、
    メモリ効率を向上させます。

    Args:
        true_data: 正規データ（暗号化済み）
        false_data: 非正規データ（暗号化済み）
        trapdoor_params: トラップドアパラメータ
        metadata: メタデータ（省略可）
        chunk_size: 分割チャンクのサイズ（バイト）

    Returns:
        ハニーポットファイルのバイト列
    """
    # データサイズの確認
    data_size = max(len(true_data), len(false_data))
    if data_size <= LARGE_FILE_THRESHOLD:
        # 小さいファイルは通常の方法で処理
        return create_honeypot_file(true_data, false_data, trapdoor_params, metadata)

    # メタデータを準備
    if metadata is None:
        metadata = {}

    # 分割情報をメタデータに追加
    chunk_metadata = {
        "chunked": True,
        "chunk_size": chunk_size,
        "original_true_size": len(true_data),
        "original_false_size": len(false_data),
        "num_chunks": (data_size + chunk_size - 1) // chunk_size
    }

    # ユーザーのメタデータと分割情報を統合
    combined_metadata = {**metadata, **chunk_metadata}

    # ファクトリーを作成
    factory = HoneypotCapsuleFactory(trapdoor_params)

    # 出力バッファ
    result = io.BytesIO()

    # チャンク数を計算
    num_chunks = (data_size + chunk_size - 1) // chunk_size

    for i in range(num_chunks):
        # 現在のチャンクの開始・終了位置
        start = i * chunk_size
        end = min((i + 1) * chunk_size, data_size)

        # 現在のチャンクのデータを抽出
        true_chunk = true_data[start:min(end, len(true_data))]
        false_chunk = false_data[start:min(end, len(false_data))]

        # 不足している部分はパディング
        if len(true_chunk) < (end - start):
            true_chunk += b'\x00' * ((end - start) - len(true_chunk))

        if len(false_chunk) < (end - start):
            false_chunk += b'\x00' * ((end - start) - len(false_chunk))

        # チャンク固有のメタデータ
        chunk_meta = {
            "chunk_index": i,
            "chunk_start": start,
            "chunk_end": end,
            "is_last_chunk": i == num_chunks - 1
        }

        # チャンクのメタデータを組み合わせ
        current_metadata = {**combined_metadata, **chunk_meta}

        # このチャンクのカプセルを作成
        capsule = factory.create_capsule(true_chunk, false_chunk, current_metadata)

        # カプセルをシリアライズしてバッファに追加
        serialized = capsule.serialize()
        result.write(struct.pack("!I", len(serialized)))  # チャンクサイズを先に書き込む
        result.write(serialized)

    return result.getvalue()


def read_data_from_large_honeypot_file(file_data: bytes, key_type: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    大きなハニーポットファイルからデータを読み取る（分割処理対応）

    Args:
        file_data: ハニーポットファイルのバイト列
        key_type: 鍵タイプ（"true" または "false"）

    Returns:
        (data, metadata): 読み取られたデータとメタデータのタプル

    Raises:
        ValueError: ファイル形式が不正な場合
    """
    buffer = io.BytesIO(file_data)

    try:
        # 先頭4バイトを読み込み、チャンクサイズを取得
        chunk_size_data = buffer.read(4)
        if len(chunk_size_data) != 4:
            # チャンクサイズがない場合は通常のファイルとして処理
            return read_data_from_honeypot_file(file_data, key_type)

        chunk_size = struct.unpack("!I", chunk_size_data)[0]

        # 最初のチャンクを読み込み
        chunk_data = buffer.read(chunk_size)
        if len(chunk_data) != chunk_size:
            raise ValueError("ファイル形式が不正です: チャンクデータの読み込みに失敗しました")

        # 最初のチャンクからデータとメタデータを取得
        data, metadata = read_data_from_honeypot_file(chunk_data, key_type)

        # 分割ファイルかどうかをチェック
        if not metadata.get("chunked", False):
            # 分割ファイルでない場合はここで終了
            return data, metadata

        # 分割ファイルの場合、すべてのチャンクを結合
        result = io.BytesIO()
        result.write(data)  # 最初のチャンクのデータを追加

        num_chunks = metadata.get("num_chunks", 1)

        # 残りのチャンクを処理
        for i in range(1, num_chunks):
            # チャンクサイズを読み込み
            chunk_size_data = buffer.read(4)
            if len(chunk_size_data) != 4:
                raise ValueError(f"チャンク {i} のサイズ読み込みに失敗しました")

            chunk_size = struct.unpack("!I", chunk_size_data)[0]

            # チャンクデータを読み込み
            chunk_data = buffer.read(chunk_size)
            if len(chunk_data) != chunk_size:
                raise ValueError(f"チャンク {i} のデータ読み込みに失敗しました")

            # チャンクからデータを抽出
            chunk_result, chunk_metadata = read_data_from_honeypot_file(chunk_data, key_type)

            # データを結合
            result.write(chunk_result)

        # 元のサイズに切り詰め
        original_size_key = f"original_{key_type}_size"
        if original_size_key in metadata:
            original_size = metadata[original_size_key]
            complete_data = result.getvalue()[:original_size]
        else:
            complete_data = result.getvalue()

        return complete_data, metadata

    except Exception as e:
        # 例外をキャッチして情報を限定
        raise ValueError(f"大きなハニーポットファイルの読み込みに失敗しました: {str(e)}")


def read_data_from_honeypot_file(file_data: bytes, key_type: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    ハニーポットファイルから指定された鍵タイプに対応するデータを読み取る

    Args:
        file_data: ハニーポットファイルのバイト列
        key_type: 鍵タイプ（"true" または "false"）

    Returns:
        (data, metadata): 読み取られたデータとメタデータのタプル

    Raises:
        ValueError: ファイル形式が不正な場合
    """
    try:
        # チャンク形式かどうかをチェック
        if len(file_data) >= 4:
            header = file_data[:6]  # マジックナンバーを確認
            if header != CAPSULE_MAGIC:
                # マジックナンバーがない場合、チャンク形式の可能性がある
                return read_data_from_large_honeypot_file(file_data, key_type)

        # 通常のカプセル処理
        capsule = HoneypotCapsule.deserialize(file_data)

        # データを抽出
        data = extract_data_from_capsule(capsule, key_type)
        if data is None:
            raise ValueError(f"指定された鍵タイプ '{key_type}' に対応するデータが見つかりません")

        return data, capsule.metadata

    except Exception as e:
        # 例外をキャッチして情報を限定
        # 攻撃者に有用な情報を与えないため、エラーメッセージは一般化する
        raise ValueError(f"ハニーポットファイルの読み込みに失敗しました: {str(e)}")


def test_honeypot_capsule():
    """
    ハニーポットカプセルのテスト
    """
    from .trapdoor import create_master_key, create_trapdoor_parameters

    print("ハニーポットカプセルのテスト実行中...")

    # トラップドアパラメータの生成
    master_key = create_master_key()
    trapdoor_params = create_trapdoor_parameters(master_key)

    # テストデータの作成
    true_data = b"This is the true data that should be revealed with the correct key."
    false_data = b"This is the false data that will be shown with an incorrect key."

    # メタデータの作成
    metadata = {
        "description": "Test honeypot capsule",
        "timestamp": 1234567890,
        "version": "1.0"
    }

    # カプセルの作成
    factory = HoneypotCapsuleFactory(trapdoor_params)
    capsule = factory.create_capsule(true_data, false_data, metadata)

    # カプセルのシリアライズ
    serialized = capsule.serialize()
    print(f"シリアライズされたカプセルのサイズ: {len(serialized)} バイト")

    # カプセルの復元
    restored_capsule = HoneypotCapsule.deserialize(serialized)

    # メタデータの検証
    print(f"復元されたメタデータ: {restored_capsule.metadata}")
    if restored_capsule.metadata != metadata:
        print("エラー: メタデータが一致しません")

    # 正規データの抽出と検証
    extracted_true_data = extract_data_from_capsule(restored_capsule, KEY_TYPE_TRUE)
    if extracted_true_data != true_data:
        print("エラー: 正規データが一致しません")
    else:
        print("正規データ抽出テスト: 成功")

    # 非正規データの抽出と検証
    extracted_false_data = extract_data_from_capsule(restored_capsule, KEY_TYPE_FALSE)
    if extracted_false_data != false_data:
        print("エラー: 非正規データが一致しません")
    else:
        print("非正規データ抽出テスト: 成功")

    # ファイル作成のテスト
    file_data = create_honeypot_file(true_data, false_data, trapdoor_params, metadata)

    # ファイルからのデータ読み込みテスト
    read_true_data, read_metadata = read_data_from_honeypot_file(file_data, KEY_TYPE_TRUE)
    if read_true_data != true_data or read_metadata != metadata:
        print("エラー: ファイルからの正規データ読み込みに失敗しました")
    else:
        print("ファイルからの正規データ読み込みテスト: 成功")

    read_false_data, _ = read_data_from_honeypot_file(file_data, KEY_TYPE_FALSE)
    if read_false_data != false_data:
        print("エラー: ファイルからの非正規データ読み込みに失敗しました")
    else:
        print("ファイルからの非正規データ読み込みテスト: 成功")

    # --- 大きなファイルの分割処理テスト ---
    print("\n大きなファイルの分割処理テスト実行中...")

    # 大きなテストデータを生成
    large_true_data = os.urandom(1024 * 1024)  # 1MB
    large_false_data = os.urandom(1024 * 1024)  # 1MB

    # 分割処理でファイル作成（小さなチャンクサイズで強制的に分割）
    chunk_size = 256 * 1024  # 256KB
    large_file_data = create_large_honeypot_file(
        large_true_data, large_false_data, trapdoor_params,
        {"test": "large_file"}, chunk_size
    )

    print(f"分割ファイルのサイズ: {len(large_file_data)} バイト")

    # 分割ファイルからのデータ読み込みテスト
    large_read_true_data, large_metadata = read_data_from_honeypot_file(large_file_data, KEY_TYPE_TRUE)

    if len(large_read_true_data) == len(large_true_data) and large_read_true_data == large_true_data:
        print("大きなファイルの正規データ読み込みテスト: 成功")
    else:
        print(f"エラー: 大きなファイルの正規データ読み込みに失敗しました (長さ: {len(large_read_true_data)} vs {len(large_true_data)})")

    large_read_false_data, _ = read_data_from_honeypot_file(large_file_data, KEY_TYPE_FALSE)

    if len(large_read_false_data) == len(large_false_data) and large_read_false_data == large_false_data:
        print("大きなファイルの非正規データ読み込みテスト: 成功")
    else:
        print(f"エラー: 大きなファイルの非正規データ読み込みに失敗しました (長さ: {len(large_read_false_data)} vs {len(large_false_data)})")

    print(f"分割ファイルのメタデータ: {large_metadata}")

    print("ハニーポットカプセルのテスト完了")


# メイン実行部
if __name__ == "__main__":
    test_honeypot_capsule()
