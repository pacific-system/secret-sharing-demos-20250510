# シャミア秘密分散法による複数平文復号システム設計書

## 3.2. 詳細設計 - 暗号書庫生成（createCryptoStorage）

### 3.2.1. 暗号書庫生成の目的と概要

- **目的**: 暗号書庫を初期状態で作成し、A/B 両分布の基盤構造を確立しその両者を復元するためのパーティションマップキーを生成する
- **責務範囲**: 初期暗号書庫ファイルの作成とパーティションマップキーの生成のみ。データの書き込みは行わない

### 3.2.2. 入出力仕様

#### 入力

- A 領域用パスワード（パーティションマップキーの暗号化に使用）
- B 領域用パスワード（パーティションマップキーの暗号化に使用）
- システムパラメータ（PARTITION_SIZE, ACTIVE_SHARES など）- 設定ファイルから読み込み直接の入力はない

#### 出力

- 暗号書庫ファイル（全シェア空間がガベージシェアで満たされた状態）
- A 用パーティションマップキー：A 用第 1 段階 MAP（単純な整数配列）を A 領域用パスワードで暗号化したキー
- B 用パーティションマップキー：B 用第 1 段階 MAP（単純な整数配列）を B 領域用パスワード暗号化したキー

### 3.2.3. 全体処理フロー

#### 3.2.3.1. 暗号書庫生成の基本ステップ

1. 全シェア空間にガベージシェアを配置し、統計的区別不可能性の基盤を確立
2. 全シェア ID 空間（`SHARE_ID_SPACE`）をランダムに 3 区画に分割
   - A 用パーティション（`PARTITION_SIZE`分の ID 領域）
   - B 用パーティション（`PARTITION_SIZE`分の ID 領域）
   - 未割当領域（`UNASSIGNED_SHARES`分の ID 領域）
3. 各パーティション領域がお互いに重複しないよう確保
4. **上記で確定した A/B 領域の分布に基づいて**パーティションマップキーを導出
   - このプロセスは重要：先に第 1 段階 MAP が決定され、後からその分布を復元するためのキーが生成される
   - 各パーティションマップキーは対応する領域の ID マッピングのみを復元可能
   - パーティションマップキーは分布を特定するための逆変換機能を持つ
5. UUID ベースの暗号書庫ファイル名を生成（タイムスタンプを含まない）し、情報漏洩を防止
6. ガベージシェアで満たされた状態の暗号書庫ファイルを作成

#### 3.2.3.2. 全体実装コード

暗号書庫生成関数の全体的な実装は以下のとおりです：

```python
def create_crypto_storage(a_password, b_password, parameters=None):
    """
    暗号書庫を生成する関数

    Args:
        a_password: A領域用のパスワード
        b_password: B領域用のパスワード
        parameters: 設定ファイルから読み込まれたシステムパラメータ設定（指定がない場合はデフォルト値を使用）
    Returns:
        storage_file: 生成された暗号書庫のファイルパス
        a_partition_map_key: A領域のパーティションマップキー
        b_partition_map_key: B領域のパーティションマップキー
    """
    # システムパラメータの確認と設定（設定ファイルからの読み込み値またはデフォルト値）
    params = parameters or DEFAULT_PARAMETERS

    # シェアID空間の設定と3区画への分割
    a_partition, b_partition, unassigned = divide_share_id_space(params)

    # ガベージシェアの生成と配置
    crypto_storage = generate_garbage_shares(params)

    # パーティションマップキーの生成
    a_partition_map_key = generate_partition_map_key(a_partition, a_password)
    b_partition_map_key = generate_partition_map_key(b_partition, b_password)

    # 暗号書庫ファイルの生成
    storage_file = save_crypto_storage(crypto_storage)

    return storage_file, a_partition_map_key, b_partition_map_key

def divide_share_id_space(params):
    """
    シェアID空間を3区画に分割する関数

    Args:
        params: 設定ファイルから読み込まれたシステムパラメータ（PARTITION_SIZE, UNASSIGNED_SHARESなど）

    Returns:
        a_partition: A用パーティション（ID配列）
        b_partition: B用パーティション（ID配列）
        unassigned: 未割当領域（ID配列）
    """
    # 全体空間サイズの計算
    share_id_space_size = params['PARTITION_SIZE'] * 2 + params['UNASSIGNED_SHARES']

    # 全IDのリスト生成（0からshare_id_space_size-1）
    all_ids = list(range(share_id_space_size))

    # セキュアなシャッフル（ランダム化）
    secure_shuffle(all_ids)

    # 3区画に分割
    a_partition = all_ids[:params['PARTITION_SIZE']]
    b_partition = all_ids[params['PARTITION_SIZE']:params['PARTITION_SIZE']*2]
    unassigned = all_ids[params['PARTITION_SIZE']*2:]

    # 各区画をソートせずにランダムな順序のまま返す
    # （意図的にパターンを形成しない）
    return a_partition, b_partition, unassigned

def secure_shuffle(array):
    """
    配列を暗号学的に安全な方法でシャッフルする関数

    Args:
        array: シャッフルする配列
    """
    for i in range(len(array) - 1, 0, -1):
        # secrets.randbelow を使用して暗号学的に安全な乱数を生成
        j = secrets.randbelow(i + 1)
        array[i], array[j] = array[j], array[i]
```

### 3.2.4. パーティションマップキーの仕組み

#### 3.2.4.1. 第 1 段階 MAP のデータ構造

第 1 段階 MAP は、特定の領域（A または B）に属する暗号化ファイル内の配列インデックスの集合を表現したデータ構造です。具体的には以下の形式を持ちます：

```python
# 第1段階MAPの基本構造（例: PARTITION_SIZE = 6000の場合）
partition_distribution = [12, 45, 67, 89, 120, 145, 167, 189, 234, 256, ... /* 合計6000個のインデックス */]
```

このデータ構造の特徴：

- シンプルな配列インデックス値の配列（整数値の配列）
- 配列の長さは常に`PARTITION_SIZE`と同じ値（例：6000 個のインデックス）
- 各インデックスは整数値で、全インデックス空間（`SHARE_ID_SPACE`）の範囲内（0 から始まる）
- 各インデックスは唯一無二であり、他の領域（A/B）のインデックスと重複しない
- `PARTITION_SIZE`分のインデックスすべてが含まれる（ACTIVE_SHARES と GARBAGE_SHARES の合計）

これらのインデックスは、以下のような暗号化ファイル内の大きな整数値の配列を指し示します：

```python
# 暗号化ファイルの内容（平文で表現した場合）
crypto_storage_content = [
    '43168234226065444066188128433421335992812488068053585868021789200038419124861',
    '39671430685010593424464720438234087121177376061253062203012873568344818805373',
    '29774227254461834571706120786392033520717356668536063492001476579431431520419',
    # ... 他の多数の大きな整数値
]
```

#### 3.2.4.2. パーティションマップキーの生成と復元

パーティションマップキーは、第 1 段階 MAP を暗号化して生成され、後で復号することで元の第 1 段階 MAP を復元できるようにします。

**パーティションマップキー生成処理：**

```python
def generate_partition_map_key(partition_distribution, password):
    """
    第1段階MAPからパーティションマップキーを生成する関数

    Args:
        partition_distribution: 領域の配列インデックス分布
        password: 暗号化に使用するパスワード（全文そのままのパスワード）

    Returns:
        formatted_key: 生成されたパーティションマップキー
    """
    # 第1段階MAPをコンパクトな表現に変換（効率的な保存と処理のため）
    compressed_distribution = compress_distribution(partition_distribution)

    # 暗号学的安全性を確保するために以下の手順を適用
    # 1. バイナリ形式に変換
    binary_data = serialize_to_binary(compressed_distribution)

    # 2. 全文そのままのパスワード（生のパスワード）から暗号化キーを導出
    encryption_key = derive_key_from_password(password)

    # 3. 暗号化（AES-GCM等の認証付き暗号化）を適用
    #    注: 認証タグも含めることで改ざん検知が可能になるが、
    #        パスワードが間違っているのか改ざんされているのかは区別できない
    encrypted_data = encrypt_with_authentication(binary_data, encryption_key)

    # 4. URL安全なBase64変種でエンコード + 追加のカスタムエンコード
    encoded_key = custom_url_safe_encoding(encrypted_data)

    # 5. 可読性向上のためにハイフンなどの区切り文字を挿入
    formatted_key = insert_separators(encoded_key)

    return formatted_key
```

**パーティションマップキーからの第 1 段階 MAP 復元処理：**

```python
def restore_partition_distribution(partition_map_key, password):
    """
    パーティションマップキーから元の第 1 段階 MAPを復元する関数

    Args:
        partition_map_key: パーティションマップキー
        password: 暗号化に使用したのと同じパスワード

    Returns:
        partition_distribution: 復元された第 1 段階 MAP

    Raises:
        DecryptionError: パスワードが正しくない場合、または改ざんが検出された場合（両者は区別できない）
    """
    # 1. 区切り文字を除去
    clean_key = remove_separators(partition_map_key)

    # 2. カスタムエンコーディングとBase64デコード
    encrypted_data = custom_url_safe_decoding(clean_key)

    # 3. 全文そのままのパスワード（生のパスワード）から暗号化キーを導出（生成時と同じ方法）
    decryption_key = derive_key_from_password(password)

    try:
        # 4. 復号と認証チェック（認証失敗時は例外発生）
        binary_data = decrypt_with_authentication(encrypted_data, decryption_key)

        # 5. バイナリからデータ構造に戻す
        compressed_distribution = deserialize_from_binary(binary_data)

        # 6. 圧縮された分布から完全な第1段階MAPを再構築
        partition_distribution = decompress_distribution(compressed_distribution)

        return partition_distribution

    except AuthenticationError:
        # 認証失敗（パスワードが異なるか、データが改ざんされている）
        # 注: 暗号学的にはパスワードが間違っているのかデータが改ざんされているのかを区別することはできない
        raise DecryptionError("パーティションマップキーの復号に失敗しました。パスワードが正しくないか、データが破損しています。")
```

#### 3.2.4.3. パーティションマップキーの例

例えば、以下のような第 1 段階 MAP（配列インデックス集合）があるとします：

```python
# 例: PARTITION_SIZE = 6000 (システム標準値)
# 以下は一部のみ表示（実際は6000個のインデックスが含まれる）
partition_distribution = [3, 27, 42, 65, 78, 91, 103, 120, 156, 231, ... /* 計6000個のインデックス */]
```

この第 1 段階 MAP に対しては、高度な圧縮技術を適用することが不可欠です。連続範囲や差分エンコードだけでなく、ビットマップ表現やランレングス符号化などの複合的な圧縮方法を組み合わせて使用します。これにより大量のインデックスデータを効率的に表現できます。

圧縮後、**全文そのままのパスワード（生のパスワード）**を使用した暗号化処理を施すと、以下のような形式のパーティションマップキーになります（例は A 領域のパスワード「A-secret-2023」を使用）：

```
p6R8-jhT3-WmV7-zD9F-yQxK-L2sN-qAa9-Um5P-nZf4-bXo8-kGv2-sIl6-dRc1-gYe0-tMw3-hBi7-
jCk9-lDs0-xNq6-oHu5-vJy8-pFz2-aEn7-rKt3-mSb4-iGc0-eTw9-uLp1-fVq5-zPr8-dXm2-yOk6-
bWs3-nUt7-cAo4-wEl9-vZp1-hRx6-uIg2-jMb5-qYv8-kQt3-gSc0-lBn7-fDo9-iHx4-tPm1-pKj6-
yGw2-rTe8-vNa5-uLs9-oFk7-xEz3-dCq0-bJi4-wPn1-sRg6-mTl8-hYc2-zVt5-aUo7-fGr3-jXs9
```

**全文そのままのパスワード（生のパスワード）**を使った暗号化が施されているため、このキーを見ただけでは元の配列インデックス情報を推測することは不可能で、正しいパスワードを入力された時だけが元の第 1 段階 MAP を取得できます。

### 3.2.5. 生成処理の特性

暗号書庫生成処理には以下の重要な特性があります：

- **初期状態** - 暗号書庫生成時点では有効データは含まれず、後続の更新操作により有効データが書き込まれます
- **キー管理** - 生成されたパーティションマップキーはシステム上に保管されず、CLI で利用者に表示されるのみです
- **ユーザー責任** - パーティションマップキーの安全な保管は利用者の責務であり、表示後システムは責務を負いません
- **メタデータ排除** - パーティションマップキーは単純な整数配列を暗号化したもので、それ自体が A 用か B 用かを示すメタデータは一切含みません
- **完全分離** - A 分布と B 分布は完全分離し、両分布は互いに不可侵で重複しません
- **非決定論的分布** - 暗号書庫の生成ごとに異なるランダムな分布が生成され、セキュリティが向上します
- **マップキー必須** - 分布がランダムなため、特定のパーティションに再度アクセスするにはマップキーが必須です
- **責務範囲** - 第 2 段階 MAP の生成は生成処理の責務範囲外です。第 2 段階 MAP は更新処理や読取処理の際にパスワードから生成されるもので、暗号書庫生成時には関与しません

### 3.2.6. 実装パターン

暗号書庫生成処理における主要な実装パターンを以下に示します。これらのパターンは具体的な実装における安全かつ効率的なコード設計を支援するためのものです。

#### 3.2.6.1. パーティションマップキーの暗号化パターン

第 1 段階 MAP を安全に暗号化してパーティションマップキーを生成するパターン：

```python
def encrypt_partition_map(partition_distribution, password):
    """
    第1段階MAPを全文そのままのパスワード（生のパスワード）で暗号化する

    Args:
        partition_distribution: 暗号化する第1段階MAP（整数配列）
        password: 暗号化に使用する生のパスワード

    Returns:
        partition_map_key: 生成されたパーティションマップキー
    """
    # 1. 第1段階MAPをシリアライズ
    serialized_data = json.dumps(partition_distribution)

    # 2. 生のパスワードから暗号化キーを導出
    salt = os.urandom(16)  # ランダムなソルト生成
    key = derive_key_from_password(password, salt)

    # 3. 認証付き暗号化（AES-GCM）
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(serialized_data.encode('utf-8'))

    # 4. ソルト、ノンス、認証タグ、暗号文を結合
    encrypted_data = salt + nonce + tag + ciphertext

    # 5. Base64エンコード
    encoded_key = base64.urlsafe_b64encode(encrypted_data).decode('ascii')

    # 6. 可読性向上のために5文字ごとにハイフンを挿入
    formatted_key = '-'.join(encoded_key[i:i+5] for i in range(0, len(encoded_key), 5))

    return formatted_key
```

このパターンの特徴：

- 全文そのままのパスワード（生のパスワード）を使用して暗号化
- ソルト、ノンス、認証タグを含めることで安全性を高める
- URL 安全な Base64 エンコーディングで可読性と移植性を確保
- ハイフン区切りで人間が読みやすい形式に整形

#### 3.2.6.2. シェア ID 空間分割の最適実装

シェア ID 空間を安全かつ効率的に分割するパターンは、3.2.3.2 で示した`divide_share_id_space`関数のとおりです。このパターンの特徴：

- 暗号学的に安全な乱数生成器（secrets）を使用
- 予測不可能な分布を確保
- 結果の配列をソートせず、ランダムな順序のまま維持
- PARTITION_SIZE と UNASSIGNED_SHARES パラメータを柔軟に適用
