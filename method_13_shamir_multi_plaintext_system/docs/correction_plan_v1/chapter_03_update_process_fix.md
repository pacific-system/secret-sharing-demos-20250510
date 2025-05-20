# 問題 3: 更新処理の問題修正（高優先度）

## 問題の詳細

現在の実装では、ファイル更新処理が正しく動作せず、特に複数のユーザー文書が共存する場合に問題が生じています。具体的には、更新後のファイルでは一部のユーザー文書しか復号できなくなります。例えば：

1. ユーザー A の文書で暗号化し、ユーザー B の文書で更新した場合
2. 更新後は B のパスワードとキーでは開けるが、A のパスワードとキーでは開けない

これにより以下の問題が発生しています：

- 複数ユーザー文書の共存が実質的に不可能
- データ喪失リスク：更新操作が既存データを破壊する可能性

## 修正手順

### 1. 改良された更新処理の実装

`shamir/update.py`の更新処理を修正して、既存のシェアを正しく保持しながら新しいシェアを追加する機能を実装します。

```python
# shamir/update.py の修正部分

import json
import base64
import os
import hashlib
from typing import Dict, List, Any, Tuple, Union, Set
from gmpy2 import mpz

from .core import stage1_map, stage2_map, generate_shares
from .key_management import PartitionKeyManager
from .constants import ShamirConstants

# WAL（Write-Ahead Logging）マネージャクラス
class WALManager:
    """更新操作の安全性を確保するためのWALマネージャ"""

    def __init__(self, wal_dir: str = ".wal"):
        self.wal_dir = wal_dir
        # WALディレクトリが存在しない場合は作成
        if not os.path.exists(wal_dir):
            os.makedirs(wal_dir)

    def create_wal_file(self, target_file: str) -> str:
        """WALファイルを作成"""
        wal_name = os.path.basename(target_file) + ".wal"
        return os.path.join(self.wal_dir, wal_name)

    def write_initial_state(self, wal_file: str, state: Dict[str, Any]) -> bool:
        """初期状態をWALに書き込み"""
        try:
            with open(wal_file, 'w') as f:
                json.dump({
                    'status': 'initial',
                    'data': state
                }, f)
            return True
        except Exception as e:
            print(f"WAL初期状態の書き込みに失敗: {e}")
            return False

    def write_updated_state(self, wal_file: str, state: Dict[str, Any]) -> bool:
        """更新後の状態をWALに書き込み"""
        try:
            with open(wal_file, 'w') as f:
                json.dump({
                    'status': 'updated',
                    'data': state
                }, f)
            return True
        except Exception as e:
            print(f"WAL更新状態の書き込みに失敗: {e}")
            return False

    def commit_wal(self, wal_file: str, target_file: str) -> bool:
        """WALの変更を実際のファイルに適用"""
        try:
            # WALファイルを読み込み
            with open(wal_file, 'r') as f:
                wal_data = json.load(f)

            if wal_data['status'] != 'updated':
                print("警告: コミット前の状態がupdatedではありません")
                return False

            # 更新データを実際のファイルに書き込み
            with open(target_file, 'w') as f:
                json.dump(wal_data['data'], f, indent=2)

            return True
        except Exception as e:
            print(f"WALコミットに失敗: {e}")
            return False

    def rollback_from_wal(self, wal_file: str) -> Dict[str, Any]:
        """WALから初期状態を復元"""
        try:
            with open(wal_file, 'r') as f:
                wal_data = json.load(f)

            if wal_data['status'] == 'initial':
                return wal_data['data']
            else:
                print("警告: ロールバック時の状態がinitialではありません")
                return None
        except Exception as e:
            print(f"WALからのロールバックに失敗: {e}")
            return None

    def cleanup_wal(self, wal_file: str) -> bool:
        """WALファイルを削除"""
        try:
            if os.path.exists(wal_file):
                os.remove(wal_file)
            return True
        except Exception as e:
            print(f"WALクリーンアップに失敗: {e}")
            return False


def update_document(
    encrypted_file: Dict[str, Any],
    json_doc: Any,
    password: str,
    partition_key: Union[str, bytes]
) -> Dict[str, Any]:
    """
    暗号化ファイルにJSONドキュメントを追加更新（改善版）

    Args:
        encrypted_file: 暗号化されたファイル構造
        json_doc: 追加するJSONドキュメント
        password: 暗号化パスワード
        partition_key: パーティションキー

    Returns:
        updated_file: 更新された暗号化ファイル
    """
    # パーティションキーの正規化
    key_manager = PartitionKeyManager()
    if isinstance(partition_key, str):
        try:
            key_bytes = key_manager.get_key(partition_key)
        except KeyError:
            key_bytes = partition_key.encode('utf-8')
    else:
        key_bytes = partition_key

    # メタデータを取得
    metadata = encrypted_file['metadata'].copy()  # コピーして変更
    salt = base64.urlsafe_b64decode(metadata['salt'])
    threshold = metadata['threshold']

    # 既存の全シェアIDセットを取得
    all_shares = encrypted_file['shares']
    existing_share_ids = set(share['share_id'] for share in all_shares)

    # パーティションキーに基づいて利用可能なシェアIDを取得
    available_ids = stage1_map(key_bytes, ShamirConstants.SHARE_ID_SPACE, threshold * 3)

    # パスワードに基づいてシェアIDにスコアを割り当て
    id_scores = stage2_map(password, salt, available_ids)

    # スコアでソートして閾値分のシェアIDを選択
    sorted_ids = sorted(available_ids, key=lambda id: id_scores[id])
    selected_ids = sorted_ids[:threshold]

    # 前処理：JSON文書をバイト列化
    json_bytes = json.dumps(json_doc).encode('utf-8')

    # チャンク分割
    chunks = []
    for i in range(0, len(json_bytes), ShamirConstants.CHUNK_SIZE):
        chunk = json_bytes[i:i + ShamirConstants.CHUNK_SIZE]
        # パディング（最後のチャンクが不足している場合）
        if len(chunk) < ShamirConstants.CHUNK_SIZE:
            chunk = chunk + b'\0' * (ShamirConstants.CHUNK_SIZE - len(chunk))
        chunks.append(chunk)

    # このパーティションのシェアを特定
    # （既存シェアと新規シェアの重複を確認するため）
    partition_share_ids = set(selected_ids)

    # 新規シェアを生成
    new_shares = []
    for chunk_idx, chunk in enumerate(chunks):
        # バイト列を整数に変換
        secret = int.from_bytes(chunk, byteorder='big')

        # シャミア秘密分散法でシェア生成
        chunk_shares = generate_shares(secret, threshold, selected_ids, ShamirConstants.PRIME)

        for share_id, value in chunk_shares:
            new_shares.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': str(value)
            })

    # 重要: 他のパーティションのシェアを保持
    # このパーティションで使用するシェアIDを除く全てのシェアを保持
    preserved_shares = [s for s in all_shares if s['share_id'] not in partition_share_ids]

    # メタデータを更新
    # 各パーティションのチャンク数を個別に記録
    partition_id = hashlib.md5(str(key_bytes).encode()).hexdigest()[:8]
    metadata['chunks_' + partition_id] = len(chunks)

    # 総チャンク数は最大値に更新
    current_max = metadata.get('total_chunks', 0)
    metadata['total_chunks'] = max(current_max, len(chunks))

    # バージョン情報を追加
    metadata['version'] = metadata.get('version', '1.0')
    if not metadata.get('updated'):
        metadata['updated'] = True

    # 更新されたファイル構造を作成
    updated_file = {
        'metadata': metadata,
        'shares': preserved_shares + new_shares
    }

    return updated_file


def update_file(
    input_file: str,
    json_input: str,
    output_file: str,
    password: str,
    partition_key: Union[str, bytes]
) -> bool:
    """
    ファイルベースの更新処理（WAL付き）

    Args:
        input_file: 入力暗号化ファイルパス
        json_input: 入力JSONファイルパス
        output_file: 出力暗号化ファイルパス
        password: 暗号化パスワード
        partition_key: パーティションキー

    Returns:
        success: 更新が成功したかどうか
    """
    # WALマネージャを初期化
    wal_manager = WALManager()
    wal_file = wal_manager.create_wal_file(output_file)

    try:
        # 暗号化ファイルを読み込み
        with open(input_file, 'r') as f:
            encrypted_file = json.load(f)

        # WALに初期状態を記録
        wal_manager.write_initial_state(wal_file, encrypted_file)

        # JSONドキュメントを読み込み
        with open(json_input, 'r') as f:
            json_doc = json.load(f)

        # 更新処理
        updated_file = update_document(encrypted_file, json_doc, password, partition_key)

        # WALに更新状態を記録
        wal_manager.write_updated_state(wal_file, updated_file)

        # 出力ファイルに書き込み
        with open(output_file, 'w') as f:
            json.dump(updated_file, f, indent=2)

        # WALをコミット
        wal_manager.commit_wal(wal_file, output_file)

        print(f"更新成功: {output_file}")
        return True

    except Exception as e:
        print(f"更新に失敗しました: {e}")

        # エラー発生時はロールバック
        original_state = wal_manager.rollback_from_wal(wal_file)
        if original_state:
            print("初期状態にロールバックします")
            with open(output_file, 'w') as f:
                json.dump(original_state, f, indent=2)

        return False

    finally:
        # WALをクリーンアップ
        wal_manager.cleanup_wal(wal_file)
```

### 2. CLI 更新コマンドの修正

`shamir/cli.py`の更新コマンドを修正して、新しい更新機能を呼び出すように変更します。

```python
# shamir/cli.py の更新部分

def update_command(args):
    """
    更新コマンド（改善版）
    """
    # パーティションキーの取得（ユーザーIDが指定された場合）
    partition_key = args.partition_key
    if args.user_id:
        try:
            partition_key = key_manager.get_key(args.user_id)
        except KeyError:
            print(f"エラー: ユーザーID '{args.user_id}' のパーティションキーが見つかりません")
            print("新しいパーティションキーを生成するには encrypt コマンドを使用してください")
            return False

    # ファイルパスとして更新処理を実行
    return update_file(
        input_file=args.encrypted_input,
        json_input=args.json_input,
        output_file=args.output,
        password=args.password,
        partition_key=partition_key
    )

def setup_update_parser(subparsers):
    """更新コマンドの引数を設定"""
    parser = subparsers.add_parser('update', help='暗号化ファイルにJSONドキュメントを追加更新')
    parser.add_argument('--encrypted-input', required=True, help='入力暗号化ファイルパス')
    parser.add_argument('--json-input', required=True, help='入力JSONファイルパス')
    parser.add_argument('--output', required=True, help='出力暗号化ファイルパス')
    parser.add_argument('--password', required=True, help='暗号化パスワード')

    # パーティションキー関連引数
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--partition-key', help='パーティションキー')
    group.add_argument('--user-id', help='ユーザーID（キーマネージャから取得）')

    parser.set_defaults(func=update_command)
```

### 3. チャンク追跡システムの実装

複数のユーザー文書のチャンク数を個別に追跡するためのメタデータ構造を実装します。

```python
# メタデータ管理機能を shamir/metadata.py として実装

import hashlib
from typing import Dict, Any, List, Union

class MetadataManager:
    """暗号化ファイルのメタデータを管理するクラス"""

    @staticmethod
    def get_partition_id(partition_key: Union[str, bytes]) -> str:
        """パーティションキーからIDを生成"""
        if isinstance(partition_key, str):
            key_str = partition_key
        else:
            # バイト列をhex文字列に変換
            key_str = partition_key.hex()

        # ハッシュでIDを生成（短いが一意性を保証）
        return hashlib.md5(key_str.encode()).hexdigest()[:8]

    @staticmethod
    def update_chunk_counts(
        metadata: Dict[str, Any],
        partition_key: Union[str, bytes],
        chunk_count: int
    ) -> Dict[str, Any]:
        """
        特定パーティションのチャンク数を更新

        Args:
            metadata: 既存メタデータ
            partition_key: パーティションキー
            chunk_count: チャンク数

        Returns:
            updated_metadata: 更新されたメタデータ
        """
        # メタデータのコピーを作成
        updated = metadata.copy()

        # パーティションIDを生成
        partition_id = MetadataManager.get_partition_id(partition_key)

        # 個別チャンク数を記録
        chunk_key = f"chunks_{partition_id}"
        updated[chunk_key] = chunk_count

        # パーティション情報を記録（存在しなければ）
        if "partitions" not in updated:
            updated["partitions"] = []

        # このパーティションIDがすでに記録されているか確認
        partition_exists = False
        for p in updated.get("partitions", []):
            if p.get("id") == partition_id:
                partition_exists = True
                p["chunk_count"] = chunk_count  # 既存エントリを更新
                break

        # 存在しなければ追加
        if not partition_exists:
            updated["partitions"].append({
                "id": partition_id,
                "chunk_count": chunk_count
            })

        # 総チャンク数を更新（全パーティションの最大値）
        max_chunks = max([p.get("chunk_count", 0) for p in updated.get("partitions", [])])
        updated["total_chunks"] = max(max_chunks, updated.get("total_chunks", 0))

        return updated

    @staticmethod
    def get_chunk_count(
        metadata: Dict[str, Any],
        partition_key: Union[str, bytes]
    ) -> int:
        """
        特定パーティションのチャンク数を取得

        Args:
            metadata: メタデータ
            partition_key: パーティションキー

        Returns:
            chunk_count: チャンク数（見つからない場合はtotal_chunks）
        """
        # パーティションIDを生成
        partition_id = MetadataManager.get_partition_id(partition_key)

        # 個別チャンク数を確認
        chunk_key = f"chunks_{partition_id}"
        if chunk_key in metadata:
            return metadata[chunk_key]

        # パーティション情報から検索
        for p in metadata.get("partitions", []):
            if p.get("id") == partition_id:
                return p.get("chunk_count", 0)

        # 見つからない場合は総チャンク数を返す
        return metadata.get("total_chunks", 0)
```

### 4. 更新処理でのメタデータ管理の改善

`update_document`関数内でメタデータ管理クラスを使用するように修正します。

```python
# shamir/update.py の修正部分（update_document関数の一部）

from .metadata import MetadataManager

# ...前略...

# メタデータを更新
metadata = MetadataManager.update_chunk_counts(
    metadata=encrypted_file['metadata'].copy(),
    partition_key=key_bytes,
    chunk_count=len(chunks)
)

# 更新されたファイル構造を作成
updated_file = {
    'metadata': metadata,
    'shares': preserved_shares + new_shares
}
```

### 5. 復号処理でのメタデータ利用の改善

`decrypt_json_document`関数でもメタデータ管理クラスを使用するように修正します。

```python
# shamir/crypto.py の修正部分（decrypt_json_document関数の一部）

from .metadata import MetadataManager

# ...前略...

# パーティション固有のチャンク数を取得
chunk_count = MetadataManager.get_chunk_count(metadata, key_bytes)

# 各チャンクを復元
chunks = []
for chunk_idx in range(chunk_count):
    # このチャンクに必要なシェアがあるか確認
    if chunk_idx not in shares_by_chunk or len(shares_by_chunk[chunk_idx]) < threshold:
        raise ValueError(f"チャンク {chunk_idx} の復元に必要なシェアが不足しています")

    # ...以下略...
```

## テスト方法

### 1. ユニットテストの作成

更新処理のテストを追加します。

```python
# tests/test_update.py

import pytest
import os
import json
import tempfile
from shamir.crypto import encrypt_json_document, decrypt_json_document
from shamir.update import update_document, WALManager
from shamir.key_management import PartitionKeyManager

def test_single_update():
    """基本的な更新処理のテスト"""
    # テストデータ
    doc_a = {"user": "A", "data": "This is A's data"}
    partition_key_a = "test_key_a"
    password_a = "password_a"

    # Aの文書で暗号化
    encrypted = encrypt_json_document(doc_a, password_a, partition_key_a)

    # Aの文書を更新（同じパーティション内）
    doc_a_updated = {"user": "A", "data": "This is A's updated data"}
    updated = update_document(encrypted, doc_a_updated, password_a, partition_key_a)

    # 更新後に復号
    decrypted = decrypt_json_document(updated, partition_key_a, password_a)

    # 更新後のデータが正しいことを確認
    assert decrypted == doc_a_updated
    assert decrypted != doc_a

def test_multiple_users_update():
    """複数ユーザーでの更新処理テスト"""
    # テストデータ
    doc_a = {"user": "A", "data": "This is A's data"}
    doc_b = {"user": "B", "data": "This is B's data"}

    partition_key_a = "test_key_a"
    partition_key_b = "test_key_b"

    password_a = "password_a"
    password_b = "password_b"

    # Aの文書で暗号化
    encrypted = encrypt_json_document(doc_a, password_a, partition_key_a)

    # Bの文書を追加（別パーティション）
    updated = update_document(encrypted, doc_b, password_b, partition_key_b)

    # 両方のユーザーで復号テスト
    decrypted_a = decrypt_json_document(updated, partition_key_a, password_a)
    decrypted_b = decrypt_json_document(updated, partition_key_b, password_b)

    # 両方のデータが正しいことを確認
    assert decrypted_a == doc_a, "Aの文書が正しく復元されませんでした"
    assert decrypted_b == doc_b, "Bの文書が正しく復元されませんでした"

def test_wal_functionality():
    """WAL機能のテスト"""
    # 一時ディレクトリを作成
    with tempfile.TemporaryDirectory() as temp_dir:
        # WALマネージャを初期化
        wal_manager = WALManager(wal_dir=os.path.join(temp_dir, "wal"))

        # テストファイルパス
        target_file = os.path.join(temp_dir, "test.json")

        # 初期データ
        initial_data = {"test": "initial"}

        # ファイルに書き込み
        with open(target_file, 'w') as f:
            json.dump(initial_data, f)

        # WALファイルを作成
        wal_file = wal_manager.create_wal_file(target_file)

        # 初期状態を記録
        assert wal_manager.write_initial_state(wal_file, initial_data)

        # 更新データ
        updated_data = {"test": "updated"}

        # 更新状態を記録
        assert wal_manager.write_updated_state(wal_file, updated_data)

        # コミット
        assert wal_manager.commit_wal(wal_file, target_file)

        # ファイルを読み込んで更新されたことを確認
        with open(target_file, 'r') as f:
            file_data = json.load(f)

        assert file_data == updated_data

        # クリーンアップ
        assert wal_manager.cleanup_wal(wal_file)
        assert not os.path.exists(wal_file)
```

### 2. 統合テスト（CLI コマンド）

CLI を使った更新処理のテストスクリプトを作成します。

```bash
#!/bin/bash
# test_update_cli.sh

set -e  # エラー時に停止

echo "更新処理の統合テスト開始..."

# テスト用ディレクトリ
TEST_DIR="test_update_$(date +%s)"
mkdir -p $TEST_DIR

# テストファイル作成
echo '{"user": "A", "data": "A data"}' > $TEST_DIR/doc_a.json
echo '{"user": "B", "data": "B data"}' > $TEST_DIR/doc_b.json

# パーティションキーとパスワード
KEY_A="partition_key_a"
KEY_B="partition_key_b"
PASS_A="password_a"
PASS_B="password_b"

# ユーザーAの文書を暗号化
python -m shamir encrypt \
  --input $TEST_DIR/doc_a.json \
  --output $TEST_DIR/encrypted.json \
  --password $PASS_A \
  --partition-key $KEY_A

echo "✓ ユーザーAの暗号化完了"

# ユーザーBの文書を追加更新
python -m shamir update \
  --encrypted-input $TEST_DIR/encrypted.json \
  --json-input $TEST_DIR/doc_b.json \
  --output $TEST_DIR/updated.json \
  --password $PASS_B \
  --partition-key $KEY_B

echo "✓ ユーザーBの更新完了"

# ユーザーAの文書を復号
python -m shamir decrypt \
  --input $TEST_DIR/updated.json \
  --output $TEST_DIR/decrypted_a.json \
  --password $PASS_A \
  --partition-key $KEY_A

echo "✓ ユーザーAの復号完了"

# ユーザーBの文書を復号
python -m shamir decrypt \
  --input $TEST_DIR/updated.json \
  --output $TEST_DIR/decrypted_b.json \
  --password $PASS_B \
  --partition-key $KEY_B

echo "✓ ユーザーBの復号完了"

# 結果を検証
diff $TEST_DIR/doc_a.json $TEST_DIR/decrypted_a.json
if [ $? -eq 0 ]; then
  echo "✓ ユーザーAの文書は正しく復元されました"
else
  echo "✗ ユーザーAの文書が正しく復元されませんでした"
  exit 1
fi

diff $TEST_DIR/doc_b.json $TEST_DIR/decrypted_b.json
if [ $? -eq 0 ]; then
  echo "✓ ユーザーBの文書は正しく復元されました"
else
  echo "✗ ユーザーBの文書が正しく復元されませんでした"
  exit 1
fi

echo "すべてのテストに成功しました！"

# クリーンアップ（オプション）
# rm -rf $TEST_DIR
```

## 期待される成果

この修正により、以下の成果が期待されます：

1. **データ保全**: 更新操作が既存のユーザー文書を破壊しなくなる
2. **複数ユーザー文書の共存**: 異なるパーティションキーとパスワードで複数の文書を共存させることが可能になる
3. **耐障害性**: WAL によりシステムクラッシュやエラー発生時でもデータ損失を防止
4. **メタデータの改善**: 各パーティションの情報を適切に管理し、復号時に正確なチャンク数を使用

これらの改善により、システムの信頼性と使いやすさが大幅に向上します。複数のユーザーが同じ暗号化ファイルを共有しながら、それぞれ独立した文書を安全に管理できるようになります。
