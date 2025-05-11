# 暗号学的ハニーポット方式 🍯 実装【子 Issue #6】：ハニーポットカプセル生成機構の実装

お兄様！いよいよ暗号学的ハニーポット方式の核心部分、カプセル生成機構を実装する時がきました！レオくんも「これこそ魔法の秘密！」と言っていますよ〜💕

## 📋 タスク概要

暗号学的ハニーポット方式の中核となるハニーポットカプセル生成機構を実装します。このカプセルは、同一の暗号文から鍵の種類に応じて異なる平文を復元できる特殊な構造を持ちます。

## 🔧 実装内容

`method_7_honeypot/honeypot_capsule.py` ファイルに、ハニーポットカプセル化機能を実装します。

### 主要な機能：

1. 複数のデータを単一のカプセルに効率的に格納する機能
2. 暗号学的な関連性を隠蔽する機能
3. データの整合性を保証する機能
4. 復号時に適切なデータを選択する仕組み

## 💻 実装手順

### 1. 必要なライブラリのインポート

`honeypot_capsule.py` の先頭に以下を記述します：

```python
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
from typing import Dict, List, Tuple, Any, Optional, Union, BinaryIO
import io

# 内部モジュールからのインポート
from .trapdoor import (
    KEY_TYPE_TRUE, KEY_TYPE_FALSE,
    generate_honey_token
)
from .config import TOKEN_SIZE
```

### 2. カプセル形式の定義

```python
# カプセル形式のバージョンとマジックナンバー
CAPSULE_VERSION = 1
CAPSULE_MAGIC = b"HPOT01"

# データブロックのタイプ
DATA_TYPE_TRUE = 1
DATA_TYPE_FALSE = 2
DATA_TYPE_META = 3

# カプセルヘッダーの構造
# | マジック(6) | バージョン(2) | シード(16) | データブロック数(4) | 予約(4) |
HEADER_FORMAT = "!6sHI16sI4x"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# データブロックヘッダーの構造
# | ブロックタイプ(4) | ブロックサイズ(4) | データオフセット(8) | ブロックハッシュ(32) |
BLOCK_HEADER_FORMAT = "!IIIQ32s"
BLOCK_HEADER_SIZE = struct.calcsize(BLOCK_HEADER_FORMAT)
```

### 3. カプセル化クラスの実装

```python
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

    def add_true_data(self, data: bytes, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        正規データをカプセルに追加

        Args:
            data: 正規データ（暗号化済み）
            metadata: メタデータ（省略可）
        """
        self.add_data_block(data, DATA_TYPE_TRUE, metadata)

    def add_false_data(self, data: bytes, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        非正規データをカプセルに追加

        Args:
            data: 非正規データ（暗号化済み）
            metadata: メタデータ（省略可）
        """
        self.add_data_block(data, DATA_TYPE_FALSE, metadata)

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
                block['type'],
                block['size'],
                data_pos,
                block['hash']
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
            else:
                # 通常のデータブロックの場合は追加
                capsule.add_data_block(block_data, header['type'])

        return capsule
```

### 4. ハニーポットカプセルファクトリーの実装

```python
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

        return capsule

    def _bind_token_to_data(self, data: bytes, token: bytes) -> bytes:
        """
        トークンをデータに関連付ける

        この関数は単純にトークンとデータを結合するだけですが、
        実際の実装ではより洗練された方法（例：トークンとデータの
        インターリーブや暗号学的な結合）を使用することをお勧めします。

        Args:
            data: バインドするデータ
            token: バインドするトークン

        Returns:
            トークンが関連付けられたデータ
        """
        # 簡易実装：トークンとデータを結合
        # 注: これは概念実証のための簡略版です
        return token + data
```

### 5. カプセル復号ユーティリティの実装

```python
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
        # カプセルを復元
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
```

### 6. テスト関数の実装

```python
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

    print("ハニーポットカプセルのテスト完了")


# メイン実行部
if __name__ == "__main__":
    test_honeypot_capsule()
```

## ✅ 完了条件

- [ ] HoneypotCapsule クラスが実装され、データブロックの追加・シリアライズ・デシリアライズができる
- [ ] カプセル内のデータブロックに対する整合性検証が実装されている
- [ ] HoneypotCapsuleFactory クラスが実装され、トラップドアパラメータを用いてカプセルを生成できる
- [ ] トークンとデータの結合機能が実装されている
- [ ] カプセルからのデータ抽出機能が実装されている
- [ ] ハニーポットファイルの作成・読み込み機能が実装されている
- [ ] テスト関数が正常に動作し、期待した結果が得られる

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# モジュールを直接実行してテスト
python -m method_7_honeypot.honeypot_capsule

# カプセル生成とシリアライズのテスト
python -c "from method_7_honeypot.trapdoor import create_master_key, create_trapdoor_parameters; from method_7_honeypot.honeypot_capsule import HoneypotCapsuleFactory, create_honeypot_file; master_key = create_master_key(); params = create_trapdoor_parameters(master_key); capsule_data = create_honeypot_file(b'True data', b'False data', params, {'test': 'metadata'}); print(f'カプセルサイズ: {len(capsule_data)} バイト')"
```

## ⏰ 想定実装時間

約 6 時間

## 📚 参考資料

- [バイナリデータの構造化](https://docs.python.org/ja/3/library/struct.html)
- [メモリストリームの操作](https://docs.python.org/ja/3/library/io.html#io.BytesIO)
- [JSON シリアライゼーション](https://docs.python.org/ja/3/library/json.html)
- [コンテナファイル形式の設計](<https://en.wikipedia.org/wiki/Container_format_(computing)>)
- [ステガノグラフィの基本](https://en.wikipedia.org/wiki/Steganography)

## 💬 備考

- ハニーポットカプセルは、システムの核心部分であり、その設計と実装には特に注意が必要です
- 実際の実装では、単純な結合ではなく、より洗練された方法でトークンとデータを関連付けることをお勧めします
- カプセル形式は拡張性を考慮して設計されており、将来的に追加のデータタイプを含めることができます
- 整合性検証はセキュリティの基本ですが、認証暗号を使用することでより強力な保護が可能になります
- パフォーマンスが重要な場合は、大きなデータブロックの処理方法を最適化することを検討してください

疑問点や提案があればコメントしてくださいね！パシ子とレオくんが全力でサポートします！💕
