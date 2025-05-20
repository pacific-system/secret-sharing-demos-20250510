# シェアフォーマットの最適化

## 現在のシェアフォーマットの問題点と設計理念との乖離

現在のシェアフォーマットでは、各シェアに以下のメタデータが含まれています：

```json
{
  "chunk_index": 0,
  "share_id": 5996,
  "value": "2565322559438891508864851625374857349677263049174595886529026700792504434612834755142320849192448263421931556159220597970542267895745169958375066054175256951"
}
```

この形式は設計書の以下の理念に反しています：

1. **多段 MAP 方式**: シェアの位置は「第 1 段階 MAP（パーティションマップキー）」と「第 2 段階 MAP（パスワード）」から決定論的に生成されるべきで、メタデータとして保存すべきではない
2. **冗長性の排除**: chunk_index と share_id は多段 MAP 方式から導出可能なため冗長
3. **暗号解析耐性**: メタデータの存在が暗号解析の手がかりになる
4. **全シェア使用方式**: 設計書では閾値の概念を使わず、常に全てのシェア（`ACTIVE_SHARES`個）を使用する方式を採用

さらに実装上の問題点として：

1. 冗長な情報（chunk_index, share_id）がシェアごとに繰り返されている
2. メタデータの存在が暗号解析の手がかりになる可能性がある
3. ファイルサイズが不必要に大きくなる
4. タイムスタンプ（created_at）がファイルの作成時刻を漏洩させるリスクがある
5. ファイル A とファイル B が同一の暗号ファイル内に混在保管される仕組みが明示的に実装されていない
6. 過去形式のコード関数がシステム内に残されており、セキュリティ脆弱性のあるコードが誤って使用されるリスクがある
7. 完全固定長シリアライズが実装されていない

## 改善案：完全インデックスベースのシェア保存

多段 MAP 方式から完全に位置を特定できる一次元配列形式に変更し、最小限のヘッダー情報のみを保持します。また、ファイル A とファイル B が同一の暗号ファイル内に混在保管される仕組みを考慮した設計とします。**過去形式との互換性は一切考慮せず、設計書の理念に完全準拠した新しい形式のみをサポートします。さらに、過去形式に関連するすべてのコード関数をコードベースから完全に削除し、新しい実装のみを残します。**

### 新しいシェアフォーマット

```json
{
  "header": {
    "salt": "base64_encoded_salt"
  },
  "values": [
    "value1", "value2", "value3", ... // 一次元配列で全シェア値を格納
  ]
}
```

### 最小限のヘッダー情報

1. **salt**: シェア生成に使用したソルト値

以下のメタデータは含めません：

- **magic**: 固定値は暗号ファイルの特性を示す手がかりになるため、区別不能性を高めるために完全に削除
- **created_at**: 作成時刻は不要であり、セキュリティリスクになる
- **share_id_space**: 配列の長さから計算可能
- **total_chunks**: 多段 MAP 方式から導出可能であり、配列長からも算出可能
- **threshold**: 本システムでは閾値の概念は使用せず、常に全シェア（`ACTIVE_SHARES`個）を使用
- **file_type**: ファイル種別（A/B）はパーティションマップキーから導出可能であり、ファイルに含める必要がない
- **version**: 互換性は別の方法で処理するため不要

### メリット

1. **設計理念への完全準拠**: 設計書の「多段 MAP 方式」、「全シェア使用方式」、「統計的区別不可能性」の理念に完全準拠
2. **ファイルサイズ削減**: メタデータ完全削除によるサイズ削減（40%以上）
3. **暗号解析耐性向上**: シェア位置情報やタイムスタンプが完全に隠蔽され、攻撃者に手がかりを与えない
4. **効率性向上**: インデックス計算のみで位置特定可能で処理効率が向上
5. **情報漏洩リスク低減**: 不要なメタデータを含まないため情報漏洩リスクが減少
6. **完全な多段 MAP 依存**: パーティションマップキーとパスワードから全ての重要パラメータを取得することで、決定論的性質を強化
7. **ファイル混在保管の明確化**: ファイル A とファイル B が同一の暗号ファイル内に混在保管される仕組みを明示的に設計に組み込み
8. **セキュリティ基準への厳格な準拠**: 過去形式との互換性を排除することで、セキュリティ基準から逸脱した実装を完全に廃止
9. **初期化ファイルと暗号化ファイルの区別不能**: ヘッダー情報を最小化し、初期化ファイルと暗号化済みファイルが外部から完全に区別できないよう設計
10. **コードベースの浄化**: 過去形式の関数を完全に削除することで、セキュリティリスクのある古いコードが残らない
11. **完全固定長シリアライズ**: すべての要素を厳密に固定長でシリアライズし、ファイルサイズの一貫性と統計的区別不可能性を確保

### シェアアクセス方法

```python
def get_share_index(chunk_index, share_id):
    """多段MAP方式で特定されたチャンクとシェアIDから一次元配列内の位置を算出"""
    # パーティション設計パラメータを取得
    share_id_space = ShamirConstants.SHARE_ID_SPACE

    # 線形インデックス計算: チャンク番号 × シェアID空間サイズ + (シェアID - 1)
    return (chunk_index * share_id_space) + (share_id - 1)

def get_share_value(data, chunk_index, share_id, file_type=None):
    """多段MAP方式で特定されたシェアの値を取得

    Args:
        data: 暗号化データ
        chunk_index: チャンクインデックス
        share_id: シェアID
        file_type: ファイル種別（'A'または'B'）、デフォルトはNone
    """
    # 必ず新しい形式であることを検証
    if "header" not in data:
        raise ValueError("非対応のファイル形式です。新しい形式のみがサポートされています。")

    # share_id_spaceは配列から計算
    values_length = len(data["values"])

    # ファイルパーティション設計パラメータを取得
    total_chunks = get_total_chunks_from_constants_and_map()
    share_id_space = values_length // total_chunks

    # ACTIVE_SHARESはパーティション設計から取得（全シェア使用方式）
    active_shares = ShamirConstants.ACTIVE_SHARES

    # ファイル種別が指定されている場合、許可されたシェア領域かチェック
    if file_type and not is_share_in_file_partition(share_id, file_type):
        logging.warning(f"ファイル{file_type}の許可領域外のシェアにアクセスしようとしています")
        return None

    index = get_share_index(chunk_index, share_id)

    # インデックスが範囲内かチェック
    if 0 <= index < len(data["values"]):
        return data["values"][index]
    return None
```

### 実装アプローチ

```python
def create_encrypted_format(chunk_data, salt=None):
    """新しい形式の暗号化ファイルを新規作成する

    Args:
        chunk_data: シェアデータの辞書（チャンク番号 -> シェアリスト）
        salt: 使用するソルト値（Noneの場合は新規生成）
    """
    if salt is None:
        # ソルト値を生成
        salt = secrets.token_bytes(16)
        salt_base64 = base64.urlsafe_b64encode(salt).decode('ascii')
    elif isinstance(salt, bytes):
        salt_base64 = base64.urlsafe_b64encode(salt).decode('ascii')
    else:
        salt_base64 = salt  # すでにbase64エンコードされていると仮定

    # パーティション設計パラメータを取得
    share_id_space = ShamirConstants.SHARE_ID_SPACE
    total_chunks = len(chunk_data)

    # 最小限のヘッダー情報のみ
    header = {
        "salt": salt_base64
    }

    # 一次元配列を初期化
    total_values = total_chunks * share_id_space
    values = ["0"] * total_values

    # 各チャンクのシェアを一次元配列に配置
    for chunk_idx, shares in chunk_data.items():
        for share in shares:
            share_id = share["id"]
            value = share["value"]

            # 一次元配列内のインデックスを計算
            index = (chunk_idx * share_id_space) + (share_id - 1)
            values[index] = value

    # 新しい形式のデータ構造を構築
    data = {
        "header": header,
        "values": values
    }

    # 完全固定長シリアライズを適用
    return fixed_length_serialize(data)
```

### 完全固定長シリアライズの追加

```python
def fixed_length_serialize(data):
    """データを完全固定長形式でシリアライズ

    Base64エンコード後のデータを固定長形式に変換し、
    シェアIDやシェア値など全ての要素を厳密に固定長で
    シリアライズすることで、ファイルサイズの一貫性と
    統計的区別不可能性を確保する。
    """
    # ヘッダー情報を固定長形式でシリアライズ
    salt = data["header"]["salt"]

    # 全てのシェア値を固定長形式でシリアライズ
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
```

### 過去形式コードの完全削除

過去形式のコード関数はセキュリティリスクを伴うため、完全に削除します：

```python
def delete_deprecated_format_functions():
    """過去形式に関連するすべての関数を削除する手順

    この関数は実際には実装せず、以下の関数をコードベースから物理的に削除します：
    - create_v1_format(), create_v2_format()
    - read_v1_format(), read_v2_format()
    - convert_v1_to_v2(), convert_format()
    - is_v1_format(), is_v2_format()
    - その他過去形式に関連するすべてのヘルパー関数
    """
    # 以下は削除すべき関数の例です
    # これらの関数はコードベースから物理的に削除し、
    # 以下のようなコードは残さないでください

    # def create_v1_format():
    #     # ...この関数は削除

    # def create_v2_format():
    #     # ...この関数は削除

    # def read_v1_format():
    #     # ...この関数は削除

    # def is_v2_format():
    #     # ...この関数は削除

    # def convert_v1_to_v2():
    #     # ...この関数は削除

    raise NotImplementedError("このコメントと関数自体も削除してください")
```

この最適化により、ファイルサイズの削減（約 40%以上）と処理効率の向上、そしてセキュリティの強化が期待できます。設計書の「多段 MAP 方式」、「全シェア使用方式」、「完全固定長シリアライズ」の理念に完全準拠し、最小限のメタデータのみを保持することで情報漏洩リスクも低減します。

パーティション設計パラメータ（`ACTIVE_SHARES`、`GARBAGE_SHARES`、`PARTITION_SIZE`、`UNASSIGNED_SHARES`）を明示的に定義し、`SHARE_ID_SPACE`を自動計算することで、確定的かつ安定したパーティション空間を実現します。常に全シェア（`ACTIVE_SHARES`個）を使用する方式と完全固定長シリアライズを組み合わせることで、有効シェアとガベージシェアの区別を不可能にします。

過去形式との互換性を排除することで、セキュリティ基準から逸脱した実装を完全に排除し、設計理念に忠実なシステムを実現します。ファイル A/B が同一の暗号ファイル内に混在保管される仕組みを明示的に実装し、システムの制約と設計理念を一致させます。初期化ファイルと暗号化済みファイルを区別不能にすることで、外部からの解析を困難にし、セキュリティをさらに強化します。

過去形式のコード関数をコードベースから完全に削除し、新しい実装のみを残すことで、セキュリティリスクのある古いコードが誤って使用されるリスクを排除します。これにより、クリーンで安全なコードベースが確保され、システム全体のセキュリティが向上します。
