# 問題 5: 暗号化ファイル形式の最適化（中優先度）

## 問題の詳細

現在の暗号化ファイル構造に不要なメタデータが含まれています。シェア値のみが必要ですが、現在の実装では`chunk_index`や`share_id`のような冗長な情報も含まれています。これにより：

1. ファイルサイズが不必要に増大する
2. 実装が複雑化している（余分なデータの管理が必要）
3. 設計思想と実装が一致していない

本来、パーティションキーとパスワードから生成される MAP により、シェアの位置は自動的に特定できるはずであり、余分なメタデータは不要です。

## 修正手順

### 1. 最適化された暗号化ファイル形式の設計

新しいファイル形式を設計し、`shamir/formats.py`モジュールを作成して実装します。

```python
# shamir/formats.py

import json
import base64
from typing import Dict, List, Any, Tuple, Union

class FileFormat:
    """暗号化ファイル形式を管理するクラス"""

    # 現在のファイル形式バージョン
    CURRENT_VERSION = "2.0"

    @staticmethod
    def create_encrypted_file(
        shares_data: List[Dict[str, Any]],
        salt: bytes,
        threshold: int,
        total_chunks: int,
        extra_metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        最適化された暗号化ファイル形式を作成

        Args:
            shares_data: シェアデータのリスト
            salt: ソルト値
            threshold: 閾値
            total_chunks: 総チャンク数
            extra_metadata: 追加のメタデータ

        Returns:
            暗号化ファイル構造
        """
        # 基本メタデータ
        metadata = {
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            "threshold": threshold,
            "total_chunks": total_chunks,
            "version": FileFormat.CURRENT_VERSION
        }

        # 追加メタデータがあれば統合
        if extra_metadata:
            metadata.update(extra_metadata)

        # 最適化されたシェアマップを作成
        # キー形式: "chunk_id:share_id"
        shares_map = {}

        for share in shares_data:
            chunk_idx = share["chunk_index"]
            share_id = share["share_id"]
            value = share["value"]

            # 一意のキーを作成
            map_key = f"{chunk_idx}:{share_id}"

            # 値を保存（値だけを保存し、メタデータは除外）
            shares_map[map_key] = value

        # 最終的なファイル構造
        encrypted_file = {
            "metadata": metadata,
            "shares_map": shares_map
        }

        return encrypted_file

    @staticmethod
    def extract_share_data(
        encrypted_file: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        暗号化ファイルからシェアデータとメタデータを抽出

        Args:
            encrypted_file: 暗号化ファイル構造

        Returns:
            (シェアデータのリスト, メタデータ)
        """
        metadata = encrypted_file["metadata"]

        # ファイル形式のチェック
        if "shares_map" in encrypted_file:  # 新しい形式
            shares_data = []
            shares_map = encrypted_file["shares_map"]

            # シェアマップから元の形式に戻す
            for map_key, value in shares_map.items():
                # キー "chunk_idx:share_id" を分解
                chunk_idx_str, share_id_str = map_key.split(":")

                shares_data.append({
                    "chunk_index": int(chunk_idx_str),
                    "share_id": int(share_id_str),
                    "value": value
                })

        else:  # 古い形式
            shares_data = encrypted_file["shares"]

        return shares_data, metadata

    @staticmethod
    def get_chunk_shares(
        shares_data: List[Dict[str, Any]],
        chunk_idx: int
    ) -> List[Tuple[int, str]]:
        """
        特定のチャンクに関連するシェアを取得

        Args:
            shares_data: シェアデータのリスト
            chunk_idx: チャンクインデックス

        Returns:
            [(share_id, value), ...] 形式のシェアリスト
        """
        chunk_shares = []

        for share in shares_data:
            if share["chunk_index"] == chunk_idx:
                chunk_shares.append((share["share_id"], share["value"]))

        return chunk_shares
```

### 2. 暗号化プロセスの修正

`crypto.py`の暗号化関数を修正して、新しいファイル形式を使用するようにします。

```python
# shamir/crypto.py の修正部分

from .formats import FileFormat

def encrypt_json_document(json_doc: Any, password: str, partition_key: Union[str, bytes]) -> Dict[str, Any]:
    """
    JSONドキュメントを暗号化（最適化版）

    Args:
        json_doc: 暗号化するJSONドキュメント
        password: 暗号化パスワード
        partition_key: パーティションキー

    Returns:
        encrypted_file: 暗号化されたファイル構造
    """
    # 既存の暗号化処理を実行
    # ...（前半部分は既存コードと同じ）...

    # シェア情報を収集
    shares_data = []
    for chunk_idx, chunk in enumerate(chunks):
        # バイト列を整数に変換
        secret = int.from_bytes(chunk, byteorder='big')

        # シャミア秘密分散法でシェア生成
        chunk_shares = generate_shares(secret, threshold, selected_ids, ShamirConstants.PRIME)

        # シェア情報を追加
        for share_id, value in chunk_shares:
            shares_data.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': str(value)  # mpz値を文字列に変換
            })

    # 追加メタデータを作成（パーティション情報など）
    partition_id = hashlib.md5(str(key_bytes).encode()).hexdigest()[:8]
    extra_metadata = {
        'chunks_' + partition_id: len(chunks)
    }

    # 最適化されたファイル形式を作成
    encrypted_file = FileFormat.create_encrypted_file(
        shares_data=shares_data,
        salt=salt,
        threshold=threshold,
        total_chunks=len(chunks),
        extra_metadata=extra_metadata
    )

    return encrypted_file
```

### 3. 復号プロセスの修正

`crypto.py`の復号関数も、新しいファイル形式に対応するよう修正します。

```python
# shamir/crypto.py の復号部分

from .formats import FileFormat
from .metadata import MetadataManager

def decrypt_json_document(encrypted_file: Dict[str, Any], partition_key: Union[str, bytes], password: str) -> Any:
    """
    暗号化されたファイルを復号（最適化版）

    Args:
        encrypted_file: 暗号化されたファイル構造
        partition_key: パーティションキー
        password: 復号パスワード

    Returns:
        復号されたJSONドキュメント
    """
    # ファイル形式からシェアデータとメタデータを抽出
    shares_data, metadata = FileFormat.extract_share_data(encrypted_file)

    # メタデータから基本情報を取得
    salt = base64.urlsafe_b64decode(metadata['salt'])
    threshold = metadata['threshold']

    # パーティションキーの正規化
    if isinstance(partition_key, str):
        try:
            key_bytes = key_manager.get_key(partition_key)
        except KeyError:
            key_bytes = partition_key.encode('utf-8')
    else:
        key_bytes = partition_key

    # ステップ1: パーティションキーに基づくMAP生成
    target_share_ids = stage1_map(key_bytes, ShamirConstants.SHARE_ID_SPACE, threshold * 3)

    # ステップ2: パスワードに基づくMAP生成
    id_scores = stage2_map(password, salt, target_share_ids)

    # スコアでソートして閾値分のシェアIDを選択
    sorted_ids = sorted(target_share_ids, key=lambda id: id_scores[id])
    selected_ids = sorted_ids[:threshold]

    # パーティション特有のチャンク数を取得
    chunk_count = MetadataManager.get_chunk_count(metadata, key_bytes)

    # 各チャンクの必要なシェアを収集
    shares_by_chunk = {}
    for share in shares_data:
        chunk_idx = share['chunk_index']
        share_id = share['share_id']

        # このパーティションに関連するシェアのみを集める
        if share_id in selected_ids:
            if chunk_idx not in shares_by_chunk:
                shares_by_chunk[chunk_idx] = []
            shares_by_chunk[chunk_idx].append((share_id, mpz(share['value'])))

    # 各チャンクを復元
    chunks = []
    for chunk_idx in range(chunk_count):
        # このチャンクに必要なシェアがあるか確認
        if chunk_idx not in shares_by_chunk or len(shares_by_chunk[chunk_idx]) < threshold:
            raise ValueError(f"チャンク {chunk_idx} の復元に必要なシェアが不足しています")

        # シャミア秘密分散法でチャンクを復元
        chunk_shares = shares_by_chunk[chunk_idx]
        secret = lagrange_interpolation(chunk_shares, ShamirConstants.PRIME)

        # 整数からバイト列に変換
        chunk_bytes = secret.to_bytes(ShamirConstants.CHUNK_SIZE, byteorder='big')
        chunks.append(chunk_bytes)

    # チャンクを結合してJSONに戻す
    json_bytes = b''.join(chunks).rstrip(b'\0')  # パディングを除去

    try:
        decrypted_doc = json.loads(json_bytes.decode('utf-8'))
        return decrypted_doc
    except json.JSONDecodeError as e:
        raise ValueError(f"復号に失敗しました。正しいパーティションキーとパスワードを使用していますか？ エラー: {e}")
```

### 4. 更新処理の対応

`update.py`も新しいファイル形式に対応するよう修正します。

```python
# shamir/update.py の修正部分

from .formats import FileFormat

def update_document(
    encrypted_file: Dict[str, Any],
    json_doc: Any,
    password: str,
    partition_key: Union[str, bytes]
) -> Dict[str, Any]:
    """
    暗号化ファイルにJSONドキュメントを追加更新（最適化版）

    Args:
        encrypted_file: 暗号化されたファイル構造
        json_doc: 追加するJSONドキュメント
        password: 暗号化パスワード
        partition_key: パーティションキー

    Returns:
        更新された暗号化ファイル
    """
    # ファイル形式からシェアデータとメタデータを抽出
    shares_data, metadata = FileFormat.extract_share_data(encrypted_file)

    # ...（既存の更新処理）...

    # 最後に新しい形式でファイルを作成
    updated_file = FileFormat.create_encrypted_file(
        shares_data=preserved_shares + new_shares,
        salt=salt,
        threshold=threshold,
        total_chunks=metadata['total_chunks'],
        extra_metadata=updated_metadata
    )

    return updated_file
```

### 5. ファイル形式変換ユーティリティの追加

古い形式から新しい形式への変換ユーティリティを追加します。

```python
# shamir/utils.py

from typing import Dict, Any
from .formats import FileFormat

def convert_file_format(old_file: Dict[str, Any]) -> Dict[str, Any]:
    """
    古い形式のファイルを新しい形式に変換

    Args:
        old_file: 古い形式の暗号化ファイル

    Returns:
        新しい形式の暗号化ファイル
    """
    # メタデータを取得
    metadata = old_file['metadata'].copy()

    # バージョン情報を設定
    if 'version' not in metadata:
        metadata['version'] = '1.0'  # 古い形式は1.0とマーク

    # シェアデータを抽出
    shares_data = old_file['shares']

    # 新しい形式に変換
    new_file = FileFormat.create_encrypted_file(
        shares_data=shares_data,
        salt=base64.urlsafe_b64decode(metadata['salt']),
        threshold=metadata['threshold'],
        total_chunks=metadata.get('total_chunks', 0),
        extra_metadata=metadata
    )

    return new_file

def convert_file(input_path: str, output_path: str) -> bool:
    """
    ファイルを古い形式から新しい形式に変換

    Args:
        input_path: 入力ファイルパス
        output_path: 出力ファイルパス

    Returns:
        変換が成功したかどうか
    """
    try:
        # 入力ファイルを読み込み
        with open(input_path, 'r') as f:
            old_file = json.load(f)

        # 形式を変換
        new_file = convert_file_format(old_file)

        # 出力ファイルに書き込み
        with open(output_path, 'w') as f:
            json.dump(new_file, f, indent=2)

        # ファイルサイズを比較
        old_size = os.path.getsize(input_path)
        new_size = os.path.getsize(output_path)
        size_reduction = old_size - new_size
        size_reduction_percent = (size_reduction / old_size) * 100 if old_size > 0 else 0

        print(f"ファイル形式変換完了:")
        print(f"元のサイズ: {old_size} バイト")
        print(f"新しいサイズ: {new_size} バイト")
        print(f"削減量: {size_reduction} バイト ({size_reduction_percent:.1f}%)")

        return True

    except Exception as e:
        print(f"ファイル形式変換エラー: {e}")
        return False
```

### 6. CLI インターフェイスの拡張

ファイル形式の変換のための CLI コマンドを追加します。

```python
# shamir/cli.py の修正部分

from .utils import convert_file

def setup_cli():
    """CLIセットアップ"""
    parser = argparse.ArgumentParser(
        description='シャミア秘密分散法による複数平文復号システム'
    )
    subparsers = parser.add_subparsers(help='コマンド')

    # 既存のコマンド設定...

    # 形式変換コマンドを追加
    setup_convert_parser(subparsers)

    return parser

def setup_convert_parser(subparsers):
    """形式変換コマンドの引数を設定"""
    parser = subparsers.add_parser('convert', help='暗号化ファイルの形式を変換')
    parser.add_argument('--input', required=True, help='入力ファイルパス')
    parser.add_argument('--output', required=True, help='出力ファイルパス')
    parser.set_defaults(func=convert_command)

def convert_command(args):
    """形式変換コマンド"""
    return convert_file(args.input, args.output)
```

### 7. 形式変換のテストを追加

新しいファイル形式と変換機能のテストを追加します。

```python
# tests/test_file_format.py

import pytest
import os
import json
import tempfile
from shamir.crypto import encrypt_json_document, decrypt_json_document
from shamir.utils import convert_file_format
from shamir.formats import FileFormat

def test_file_format_efficiency():
    """ファイル形式の効率性をテスト"""
    # テストデータ
    doc = {"test": "data", "nested": {"array": list(range(100))}}
    password = "test_password"
    partition_key = "test_partition_key"

    # 古い形式で暗号化
    encrypted_old = encrypt_json_document(doc, password, partition_key)

    # 形式を変換
    encrypted_new = convert_file_format(encrypted_old)

    # 両方のファイルをJSON文字列に変換
    old_json = json.dumps(encrypted_old)
    new_json = json.dumps(encrypted_new)

    # サイズを比較
    old_size = len(old_json.encode('utf-8'))
    new_size = len(new_json.encode('utf-8'))

    # 新しい形式の方が小さいことを確認
    assert new_size < old_size, "新しい形式の方がファイルサイズが大きい"

    # サイズ削減率を計算
    reduction = (old_size - new_size) / old_size * 100
    print(f"ファイルサイズ削減率: {reduction:.1f}%")

    # 一定以上の削減率があることを確認（10%以上を期待）
    assert reduction >= 10, "ファイルサイズ削減が期待より少ない"

def test_file_format_compatibility():
    """新しいファイル形式の互換性をテスト"""
    # テストデータ
    doc = {"test": "data"}
    password = "test_password"
    partition_key = "test_partition_key"

    # 古い形式で暗号化
    encrypted_old = encrypt_json_document(doc, password, partition_key)

    # 形式を変換
    encrypted_new = convert_file_format(encrypted_old)

    # 両方の形式から復号して結果を比較
    decrypted_old = decrypt_json_document(encrypted_old, partition_key, password)
    decrypted_new = decrypt_json_document(encrypted_new, partition_key, password)

    # 復号結果が同じであることを確認
    assert decrypted_old == decrypted_new == doc, "異なる形式で復号結果が一致しない"

def test_file_format_conversion_cli():
    """CLIでのファイル形式変換をテスト"""
    # 一時ディレクトリを作成
    with tempfile.TemporaryDirectory() as temp_dir:
        # テストファイルパス
        input_path = os.path.join(temp_dir, "input.json")
        output_path = os.path.join(temp_dir, "output.json")

        # テストデータ
        doc = {"test": "data"}
        password = "test_password"
        partition_key = "test_partition_key"

        # 暗号化して古い形式のファイルを作成
        encrypted = encrypt_json_document(doc, password, partition_key)
        with open(input_path, 'w') as f:
            json.dump(encrypted, f)

        # CLIで変換
        from shamir.cli import convert_command
        convert_command(type('Args', (), {
            'input': input_path,
            'output': output_path
        }))

        # 出力ファイルが作成されたことを確認
        assert os.path.exists(output_path), "出力ファイルが作成されていない"

        # 新しい形式のファイルを読み込み
        with open(output_path, 'r') as f:
            new_file = json.load(f)

        # 新しい形式のファイルから復号
        decrypted = decrypt_json_document(new_file, partition_key, password)

        # 復号結果が正しいことを確認
        assert decrypted == doc, "変換後のファイルから正しく復号できない"
```

## 検証方法

この修正が正しく実装されていることを確認するため、以下の検証を行ってください：

1. **形式変換のテスト**:

   ```bash
   # 既存のファイルを変換
   python -m shamir convert --input existing.json --output converted.json

   # 変換前後のサイズ比較
   ls -l existing.json converted.json
   ```

2. **新形式でのファイルサイズ比較**:

   ```python
   # 新旧形式のファイルサイズ比較スクリプト
   from shamir.crypto import encrypt_json_document
   from shamir.utils import convert_file_format
   import json

   # テストデータ（大きなデータを使用）
   data = {"data": ["item" * 100 for _ in range(100)]}

   # 古い形式で暗号化
   encrypted_old = encrypt_json_document(data, "password", "key")
   old_json = json.dumps(encrypted_old)

   # 新しい形式に変換
   encrypted_new = convert_file_format(encrypted_old)
   new_json = json.dumps(encrypted_new)

   # サイズ比較
   old_size = len(old_json)
   new_size = len(new_json)

   print(f"旧形式サイズ: {old_size} バイト")
   print(f"新形式サイズ: {new_size} バイト")
   print(f"削減量: {old_size - new_size} バイト ({(old_size - new_size) / old_size * 100:.1f}%)")
   ```

3. **互換性テスト**:

   ```bash
   # 暗号化（新形式）
   python -m shamir encrypt --input test.json --output encrypted.json --password test123 --partition-key test_key

   # 復号
   python -m shamir decrypt --input encrypted.json --output decrypted.json --password test123 --partition-key test_key

   # 結果比較
   diff test.json decrypted.json
   ```

## 期待される成果

この修正により、以下の成果が期待されます：

1. **ファイルサイズの削減**: 余分なメタデータが排除され、ファイルサイズが約 15〜25%削減される
2. **処理の効率化**: シェアの検索と操作が効率化され、処理速度が向上する
3. **設計の一貫性**: 実装が設計思想に沿った形になり、コードの一貫性が向上する
4. **バージョン管理**: ファイル形式にバージョン情報が含まれ、将来の拡張が容易になる

これらの改善により、システムは効率的で拡張性のあるものになり、特に大きなデータや多数のユーザーの共存ケースでパフォーマンスが向上します。
