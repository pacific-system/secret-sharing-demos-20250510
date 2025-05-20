# 問題 2: MAP 生成ロジックの不整合修正（高優先度）

## 問題の詳細

`stage1_map`関数がパーティションキーに基づいてシェア ID を選択する際、選択パターンが一貫していません。そのため、同じパーティションキーとパスワードであっても、暗号化したファイルが後で復号できない場合があります。この問題により：

1. 信頼性の低下：同じキーとパスワードでも復号できない場合がある
2. 複数平文共存時の整合性問題：一方の文書の更新が他方の文書のアクセス不能を引き起こす

## 修正手順

### 1. MAP ロジックの決定論的アルゴリズムの実装

既存の`core.py`の MAP 生成ロジック（主に`stage2_map`関数）を決定論的に動作するよう修正します。

```python
# shamir/core.py の修正部分

def stage2_map(password: str, salt: bytes, share_ids: List[int]) -> Dict[int, float]:
    """
    パスワードに基づいてシェアIDにスコアを割り当てる（決定論的MAP生成）

    Args:
        password: ユーザーパスワード
        salt: 暗号用ソルト（メタデータから取得）
        share_ids: 利用可能なシェアIDのリスト（stage1_mapの出力）

    Returns:
        share_id_scores: {share_id: score, ...}形式のMAP
    """
    # パスワードとソルトからキー派生（PBKDF2）
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode('utf-8'))

    # 決定論的なスコア付けを実装
    share_id_scores = {}

    for share_id in share_ids:
        # シェアIDごとに決定論的なハッシュ値を生成
        # キーとシェアIDの組み合わせが一意のスコアを生成
        id_bytes = str(share_id).encode('utf-8')
        combined = key + id_bytes
        score_hash = hashlib.sha256(combined).digest()

        # ハッシュ値を0〜1の浮動小数点数に変換
        score = int.from_bytes(score_hash, byteorder='big') / (2**256 - 1)
        share_id_scores[share_id] = score

    return share_id_scores
```

### 2. 全体の暗号化フローを改善

暗号化プロセス全体が一貫して動作するように`encrypt_json_document`関数を修正します。

```python
# shamir/crypto.py の暗号化部分

def encrypt_json_document(json_doc: Any, password: str, partition_key: Union[str, bytes]) -> Dict[str, Any]:
    """
    JSONドキュメントを暗号化（改善版）

    Args:
        json_doc: 暗号化するJSONドキュメント
        password: 暗号化パスワード
        partition_key: パーティションキー（文字列またはバイト列）

    Returns:
        encrypted_file: 暗号化されたファイル構造
    """
    # メタデータ作成
    salt = os.urandom(16)  # ランダムなソルト値
    threshold = ShamirConstants.DEFAULT_THRESHOLD  # デフォルト閾値

    # キーマネージャから正規化されたパーティションキーを取得
    if isinstance(partition_key, str):
        try:
            key_bytes = key_manager.get_key(partition_key)
        except KeyError:
            key_bytes = partition_key.encode('utf-8')
    else:
        key_bytes = partition_key  # すでにバイト列

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

    # ステップ1: パーティションキーに基づくMAP生成
    target_share_ids = stage1_map(key_bytes, ShamirConstants.SHARE_ID_SPACE, threshold * 3)

    # ステップ2: パスワードに基づくMAP生成
    share_id_scores = stage2_map(password, salt, target_share_ids)

    # スコアでシェアIDをソート（決定論的選択）
    sorted_ids = sorted(target_share_ids, key=lambda id: share_id_scores[id])
    selected_ids = sorted_ids[:threshold]

    # 各チャンクをシェア化
    all_shares = []
    for chunk_idx, chunk in enumerate(chunks):
        # バイト列を整数に変換
        secret = int.from_bytes(chunk, byteorder='big')

        # シャミア秘密分散法でシェア生成
        shares = generate_shares(secret, threshold, selected_ids, ShamirConstants.PRIME)

        # シェア情報を追加
        for share_id, value in shares:
            all_shares.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': str(value)  # mpz値を文字列に変換
            })

    # 暗号化ファイル構造の作成
    encrypted_file = {
        'metadata': {
            'salt': base64.urlsafe_b64encode(salt).decode('ascii'),
            'threshold': threshold,
            'total_chunks': len(chunks),
            'version': '2.0',  # バージョン情報を追加
        },
        'shares': all_shares
    }

    return encrypted_file
```

### 3. 複数の平文復号に対応する暗号化機能の実装

複数の平文を同じファイルに保存できる機能を強化します。

```python
# shamir/crypto.py の復号部分

def decrypt_json_document(encrypted_file: Dict[str, Any], partition_key: Union[str, bytes], password: str) -> Any:
    """
    暗号化されたファイルを復号（改善版）

    Args:
        encrypted_file: 暗号化されたファイル構造
        partition_key: パーティションキー（文字列またはバイト列）
        password: 復号用パスワード

    Returns:
        decrypted_doc: 復号されたJSONドキュメント
    """
    # メタデータを取得
    metadata = encrypted_file['metadata']
    salt = base64.urlsafe_b64decode(metadata['salt'])
    threshold = metadata['threshold']
    total_chunks = metadata['total_chunks']

    # キーマネージャから正規化されたパーティションキーを取得
    if isinstance(partition_key, str):
        try:
            key_bytes = key_manager.get_key(partition_key)
        except KeyError:
            key_bytes = partition_key.encode('utf-8')
    else:
        key_bytes = partition_key  # すでにバイト列

    # ステップ1: パーティションキーに基づくMAP生成
    target_share_ids = stage1_map(key_bytes, ShamirConstants.SHARE_ID_SPACE, threshold * 3)

    # ステップ2: パスワードに基づくMAP生成
    share_id_scores = stage2_map(password, salt, target_share_ids)

    # スコアでシェアIDをソート（決定論的選択）
    sorted_ids = sorted(target_share_ids, key=lambda id: share_id_scores[id])
    selected_ids = sorted_ids[:threshold]

    # 全シェアから必要なシェアを抽出
    shares_by_chunk = {}
    for share in encrypted_file['shares']:
        chunk_idx = share['chunk_index']
        share_id = share['share_id']

        # 選択されたシェアIDに含まれるものだけを収集
        if share_id in selected_ids:
            if chunk_idx not in shares_by_chunk:
                shares_by_chunk[chunk_idx] = []

            # (share_id, value)のタプルとして保存
            shares_by_chunk[chunk_idx].append((share_id, mpz(share['value'])))

    # 各チャンクを復元
    chunks = []
    for chunk_idx in range(total_chunks):
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
        raise ValueError(f"正しいパーティションキーとパスワードを使用していますか？ デコードエラー: {e}")
```

### 4. デバッグとテスト機能の追加

MAP 生成ロジックのデバッグ用関数を実装します。

```python
# shamir/debug.py

import hashlib
import base64
import random
from typing import List, Dict, Set, Any

def verify_map_determinism(partition_key: str, password: str, salt: bytes = None, runs: int = 10) -> bool:
    """
    MAP生成の一貫性をテストする

    Args:
        partition_key: パーティションキー
        password: パスワード
        salt: ソルト値（Noneの場合はランダム生成）
        runs: テスト実行回数

    Returns:
        is_deterministic: すべての実行で同じMAPが生成されたか
    """
    from .core import stage1_map, stage2_map
    from .constants import ShamirConstants

    if salt is None:
        salt = os.urandom(16)

    # パーティションキーを正規化
    if isinstance(partition_key, str):
        key_bytes = partition_key.encode('utf-8')
    else:
        key_bytes = partition_key

    # 複数回実行して結果を比較
    results = []

    for i in range(runs):
        # ステージ1: パーティションキーに基づくMAP
        stage1_ids = stage1_map(key_bytes, ShamirConstants.SHARE_ID_SPACE, 10)

        # ステージ2: パスワードに基づくMAP
        stage2_scores = stage2_map(password, salt, stage1_ids)

        # 結果を保存
        sorted_ids = sorted(stage1_ids, key=lambda id: stage2_scores[id])
        results.append(sorted_ids)

    # すべての結果が一致するか確認
    is_deterministic = all(results[0] == result for result in results[1:])

    if is_deterministic:
        print("✓ MAP生成は一貫しています")
    else:
        print("✗ MAP生成が一貫していません - 異なる結果が生成されました")
        # 差分を表示
        for i, result in enumerate(results[1:], 1):
            if result != results[0]:
                print(f"  実行 {i} の差分: {set(result) - set(results[0])}")

    return is_deterministic
```

### 5. ユニットテストの追加

MAP 生成ロジックのテストを実装します。

```python
# tests/test_map_generation.py

import pytest
import os
import base64
import hashlib
from shamir.core import stage1_map, stage2_map
from shamir.crypto import encrypt_json_document, decrypt_json_document
from shamir.debug import verify_map_determinism
from shamir.constants import ShamirConstants

def test_stage2_map_deterministic():
    """stage2_map関数の決定論的な動作をテスト"""
    password = "test_password"
    salt = os.urandom(16)
    share_ids = list(range(1, 101))

    # 同じ条件で複数回実行
    scores1 = stage2_map(password, salt, share_ids)
    scores2 = stage2_map(password, salt, share_ids)

    # 結果が同一であることを確認
    assert scores1 == scores2, "同じパスワードとソルトなのに異なるスコアが生成されました"

    # スコアが0〜1の範囲内であることを確認
    for score in scores1.values():
        assert 0 <= score <= 1, f"スコアが範囲外です: {score}"

def test_encrypt_decrypt_cycle():
    """暗号化と復号の完全なサイクルテスト"""
    # テストデータ
    doc = {"test": "value", "nested": {"data": [1, 2, 3]}}
    password = "test_password"
    partition_key = "test_partition_key"

    # 暗号化
    encrypted = encrypt_json_document(doc, password, partition_key)

    # 復号
    decrypted = decrypt_json_document(encrypted, partition_key, password)

    # 元のデータと一致するか確認
    assert decrypted == doc, "復号されたドキュメントが元のデータと一致しません"

def test_multiple_encryptions_same_key():
    """同じキーとパスワードで複数回暗号化の一貫性をテスト"""
    # テストデータ
    doc = {"test": "value"}
    password = "test_password"
    partition_key = "test_partition_key"

    # 10回暗号化して復号
    for i in range(10):
        encrypted = encrypt_json_document(doc, password, partition_key)
        decrypted = decrypt_json_document(encrypted, partition_key, password)
        assert decrypted == doc, f"実行 {i} で復号に失敗しました"

    print("✓ 同じキーとパスワードで繰り返し暗号化/復号に成功しました")

def test_map_determinism():
    """MAPロジック全体の決定論的な動作を検証"""
    # 固定のパーティションキーとパスワード
    partition_key = "deterministic_test_key"
    password = "deterministic_test_password"
    salt = os.urandom(16)

    # MAP生成の一貫性をテスト
    assert verify_map_determinism(partition_key, password, salt, runs=20)
```

## 検証方法

この修正が正しく実装されていることを確認するため、以下の検証を行ってください：

1. **単純な暗号化/復号テスト**:

   ```bash
   python -m shamir encrypt --input test.json --output encrypted.json --password test123 --partition-key test_key
   python -m shamir decrypt --input encrypted.json --output decrypted.json --password test123 --partition-key test_key
   diff test.json decrypted.json  # 差分がないことを確認
   ```

2. **繰り返し暗号化/復号テスト**:

   ```bash
   # テストスクリプト
   for i in {1..10}; do
     python -m shamir encrypt --input test.json --output encrypted.json --password test123 --partition-key test_key
     python -m shamir decrypt --input encrypted.json --output decrypted.json --password test123 --partition-key test_key
     diff test.json decrypted.json || echo "Failed on iteration $i"
   done
   ```

3. **複数ユーザーでの暗号化/更新/復号テスト**:

   ```bash
   # ユーザーAで暗号化
   python -m shamir encrypt --input test_a.json --output encrypted.json --password passA --partition-key keyA

   # ユーザーBで更新
   python -m shamir update --encrypted-input encrypted.json --json-input test_b.json --output updated.json --password passB --partition-key keyB

   # 両方のユーザーで復号テスト
   python -m shamir decrypt --input updated.json --output decrypted_a.json --password passA --partition-key keyA
   python -m shamir decrypt --input updated.json --output decrypted_b.json --password passB --partition-key keyB

   # 両方のデータが正しいことを確認
   diff test_a.json decrypted_a.json
   diff test_b.json decrypted_b.json
   ```

## 期待される成果

この修正により、以下の成果が期待されます：

1. **一貫性の確保**: 同じパーティションキーとパスワードを使用した場合、常に同じ暗号化/復号結果が得られる
2. **信頼性の向上**: 複数回の暗号化/復号操作でも常に同じ結果が得られる
3. **複数ユーザーの共存**: 異なるユーザーの文書が適切に分離され、互いに干渉しない
4. **MAP 生成の透明性**: デバッグやトラブルシューティングが容易になる

これらの改善により、システムの信頼性と使いやすさが大幅に向上します。
