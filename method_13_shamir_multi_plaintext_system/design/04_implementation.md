# シャミア秘密分散法による複数平文復号システム設計書

## 4. 実装詳細

### 4.1. 基本システム実装方針

#### 4.1.1. 一貫した用語と責務

- 暗号書庫（CryptoStorage）：システム全体が管理する暗号化データファイル
- 生成処理（createCryptoStorage）：暗号書庫の初期作成と基盤構造確立処理
- 更新処理（updateCryptoStorage）：暗号書庫への文書の暗号化と保存処理
- 読取処理（readCryptoStorage）：暗号書庫からの文書の復号と取得処理

これらの処理は独立した責務を持ち、システムの核となる 3 つの操作として実装される。

#### 4.1.2. 直交処理原則

すべての処理ステップは互いに独立した一貫性を持ち、入力データの特性に左右されることなく、常に同一の方法で実行される。これにより：

- パターン分析攻撃への耐性を確保
- 条件分岐を最小化し、サイドチャネル攻撃リスクを低減
- 入力データの特性を暗号化後のデータから推測することを困難に

#### 4.1.3. 統計的区別不可能性の確保

- すべてのシェアは外見上区別できず、同一の統計的特性を持つ
- データサイズによらず固定サイズ処理が適用され、サイズによる区別を防止
- A/B 文書やガベージシェアの区別は不可能に設計

### 4.2. 暗号書庫生成処理の実装

#### 4.2.1. 全体フロー

1. システムパラメータと入力された A/B のパスワードを取得
2. シェア ID 空間（`SHARE_ID_SPACE`）を設定パラメータに基づいて確定
3. 全シェア空間をランダムに 3 区画に分割：
   - A 用パーティション（`PARTITION_SIZE`分）
   - B 用パーティション（`PARTITION_SIZE`分）
   - 未割当領域（`UNASSIGNED_SHARES`分）
4. シェア空間全体にガベージシェアを配置
5. A/B 領域それぞれに対してパーティションマップキーを導出
   - A 用には A 用パスワードを使用
   - B 用には B 用パスワードを使用
6. UUID ベースのファイル名で暗号書庫ファイルを生成（タイムスタンプ情報なし）

この変更により、createCryptoStorage 関数の定義は以下のようになります：

```python
def create_crypto_storage(a_password, b_password, parameters=None):
    """
    暗号書庫を生成する関数

    Args:
        a_password: A領域用のパスワード
        b_password: B領域用のパスワード
        parameters: 任意のシステムパラメータ設定（指定がない場合はデフォルト値を使用）

    Returns:
        storage_file: 生成された暗号書庫のファイルパス
        a_partition_map_key: A領域のパーティションマップキー
        b_partition_map_key: B領域のパーティションマップキー
    """
    # システムパラメータの確認と設定
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
```

#### 4.2.2. 領域分布のパーティションマップキー化

##### 領域分布のデータ構造

領域分布（partition_distribution）は、特定の領域（A または B）に属する暗号化ファイル内の配列インデックスの集合を表現したデータ構造です。具体的には以下の形式を持ちます：

```python
# 領域分布の基本構造（例: PARTITION_SIZE = 120の場合）
partition_distribution = [12, 45, 67, 89, 120, 145, 167, 189, 234, 256, ... /* 合計120個のインデックス */]
```

このデータ構造の特徴：

- シンプルな配列インデックス値の配列（整数値の配列）
- 配列の長さは常に`PARTITION_SIZE`と同じ値（例：120 個のインデックス）
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

パーティションマップキー化の前に、この領域分布データは圧縮されます。圧縮方法としては、インデックスの連続範囲の表現や差分エンコードなどの手法が用いられます。

パーティションマップキー生成の関数も更新します：

```python
def generate_partition_map_key(partition_distribution, password):
    """
    領域分布からパーティションマップキーを生成する関数

    Args:
        partition_distribution: 領域の配列インデックス分布
        password: 暗号化に使用するパスワード（第2段階MAPでも使用）

    Returns:
        formatted_key: 生成されたパーティションマップキー
    """
    # 領域分布をコンパクトな表現に変換（効率的な保存と処理のため）
    compressed_distribution = compress_distribution(partition_distribution)

    # 暗号学的安全性を確保するために以下の手順を適用
    # 1. バイナリ形式に変換
    binary_data = serialize_to_binary(compressed_distribution)

    # 2. 全文そのままのパスワード（生のパスワード）から暗号化キーを導出
    #    注: 同じパスワードを第2段階MAPでも使用
    encryption_key = derive_key_from_password(password)

    # 3. 暗号化（AES-GCM等の認証付き暗号化）を適用
    #    注: 認証タグも含めることで、改ざん検知が可能に
    encrypted_data = encrypt_with_authentication(binary_data, encryption_key)

    # 4. URL安全なBase64変種でエンコード + 追加のカスタムエンコード
    encoded_key = custom_url_safe_encoding(encrypted_data)

    # 5. 可読性向上のためにハイフンなどの区切り文字を挿入
    formatted_key = insert_separators(encoded_key)

    return formatted_key
```

この処理は「分布 → キー」の変換を行いますが、単純な Base64 エンコードよりも堅牢な方法を採用しています。このアプローチでは、配列インデックスの集合である領域分布から、暗号学的に安全でかつ復元可能なキー形式を生成します。生成されたキーは、第三者が見ても元の配列インデックス情報を推測することが困難な形式になります。このキーには暗号書庫との紐付け情報、タイムスタンプ、バージョン、方式などのメタデータは一切含まれません。

同様に復元関数も更新する必要があります：

```python
def restore_partition_distribution(partition_map_key, password):
    """
    パーティションマップキーから元の領域分布を復元する関数

    Args:
        partition_map_key: パーティションマップキー
        password: 暗号化に使用したのと同じパスワード

    Returns:
        partition_distribution: 復元された領域分布

    Raises:
        DecryptionError: パスワードが正しくない場合、または改ざんが検出された場合
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

        # 6. 圧縮された分布から完全な領域分布を再構築
        partition_distribution = decompress_distribution(compressed_distribution)

        return partition_distribution

    except AuthenticationError:
        # 認証失敗（パスワードが異なるか、データが改ざんされている）
        raise DecryptionError("パーティションマップキーの復号に失敗しました。パスワードが正しくないか、データが破損しています。")
```

##### パーティションマップキーの例

例えば、以下のような領域分布（配列インデックス集合）があるとします：

```python
# 例: PARTITION_SIZE = 10000 (システム標準値)
# 以下は一部のみ表示（実際は10000個のインデックスが含まれる）
partition_distribution = [3, 27, 42, 65, 78, 91, 103, 120, 156, 231, ... /* 計10000個のインデックス */]
```

この領域分布に対しては、高度な圧縮技術を適用することが不可欠です。連続範囲や差分エンコードだけでなく、ビットマップ表現やランレングス符号化などの複合的な圧縮方法を組み合わせて使用します。これにより大量のインデックスデータを効率的に表現できます。

圧縮後、**全文そのままのパスワード（生のパスワード）**を使用した暗号化処理を施すと、以下のような形式のパーティションマップキーになります（例は A 領域のパスワード「A-secret-2023」を使用）：

```
p6R8-jhT3-WmV7-zD9F-yQxK-L2sN-qAa9-Um5P-nZf4-bXo8-kGv2-sIl6-dRc1-gYe0-tMw3-hBi7-
jCk9-lDs0-xNq6-oHu5-vJy8-pFz2-aEn7-rKt3-mSb4-iGc0-eTw9-uLp1-fVq5-zPr8-dXm2-yOk6-
bWs3-nUt7-cAo4-wEl9-vZp1-hRx6-uIg2-jMb5-qYv8-kQt3-gSc0-lBn7-fDo9-iHx4-tPm1-pKj6-
yGw2-rTe8-vNa5-uLs9-oFk7-xEz3-dCq0-bJi4-wPn1-sRg6-mTl8-hYc2-zVt5-aUo7-fGr3-jXs9
```

PARTITION_SIZE = 10000 の場合、パーティションマップキーは上記のように非常に長くなります。人間が直接取り扱うことは現実的ではないため、このようなキーはファイルとして保存するか、QR コードなどのデジタル形式で伝達するのが一般的です。ただし、区切り文字（ハイフン）によるブロック分けは維持されており、部分的な読み上げや確認が必要な場合にも対応可能です。

**全文そのままのパスワード（生のパスワード）**を使った暗号化が施されているため、このキーを見ただけでは元の配列インデックス情報を推測することは不可能で、正しいパスワードを持つシステムだけが元の領域分布を取得できます。**重要な注意点として、パーティションマップキーの暗号化には全文そのままのパスワードを使用しますが、第 2 段階 MAP の生成には必ず処理（ハッシュ化）されたパスワードを使用します**。開発者は第 2 段階 MAP 生成に生のパスワードを誤って使用してはなりません。また、圧縮アルゴリズムの選択により、10000 個ものインデックスを含む場合でも、キーの長さは一定の範囲内に収まるよう最適化されています。

なお、暗号書庫を読み取るときは、生成時と同じ**全文そのままのパスワード（生のパスワード）**を使用してパーティションマップキーを復号する必要があります：

```python
# 暗号書庫読取時
def read_crypto_storage(storage_file, partition_map_key, password):
    """暗号書庫を読み取る関数"""

    # パーティションマップキーからの領域分布復元（全文そのままのパスワードを使用）
    partition_distribution = restore_partition_distribution(partition_map_key, password)

    # 復元された領域分布から第1段階MAPを構築
    stage1_map = partition_distribution

    # 第1段階MAPと処理されたパスワードから第2段階MAPを生成
    # 注意: ここでは必ず処理されたパスワードを使用する必要がある
    processed_password = process_password(password)  # パスワードを処理（ハッシュ化）
    stage2_map = generate_stage2_map(stage1_map, processed_password)

    # 以降の処理は従来通り...
```

#### 4.2.3. パーティションマップキーの領域分布化

この処理は「キー → 分布」の変換を行う 4.2.2 の逆操作です。パーティションマップキーをパスワードで復号することで、元の領域分布（シェア ID の集合）を復元します。パスワードによって保護されているため、正しいパスワードを持つユーザーだけがパーティションマップキーから領域分布を復元できます。

この設計により、以下のセキュリティ特性が確保されます：

1. **パスワード保護**: 領域分布情報がパスワードで暗号化されるため、パーティションマップキーが漏洩しても、パスワードなしでは解読不可能
2. **改ざん検知**: 認証付き暗号化（AES-GCM 等）により、パーティションマップキーの改ざんを検知可能
3. **共通のパスワード使用**: 同じパスワードが第 2 段階 MAP の生成にも使用されるため、ユーザーは覚えるパスワードが一つで済む

以上の変更により、パーティションマップキー生成と復元のプロセスがより安全になり、パスワードによる保護レイヤーが追加されました。

### 4.3. データ暗号化処理の共通実装

#### 4.3.1. 多段エンコードプロセス

全ての入力データに対して、以下の統一的な変換処理を適用：

1. JSON 文書を UTF-8 テキストとして処理
2. 固定容量検証とパディング処理：
   - データサイズが`ACTIVE_SHARES × CHUNK_SIZE`以内か検証
   - データサイズによらず同一のパディング処理を適用
3. 多段エンコード変換：
   - UTF-8 → Latin-1 エンコード変換
   - Latin-1 → Base64 エンコード
   - Base64 → 固定長シリアライズ処理

#### 4.3.2. チャンク分割と処理

1. エンコード済みデータを 64 バイト固定サイズのチャンクに分割
2. 全チャンクに対して同一の処理を適用（最後のチャンクも含む）
3. 分割後のチャンク数が`ACTIVE_SHARES`と一致することを確認

#### 4.3.3. シャミア秘密分散法の実装

全シェア使用方式を採用し、冗長性ではなくセキュリティを優先：

       ```python

def create_shares(secret, num_shares, prime):
"""秘密値から指定数のシェアを生成"""
coefficients = [secret] # 係数[0]は秘密値

    # 多項式の次数は (num_shares-1)
    for i in range(1, num_shares):
        # 係数はランダムに生成 (1 ~ prime-1)
        coefficients.append(random.randint(1, prime-1))

    # 各シェアを計算 (x=1, 2, ..., num_shares)
    shares = []
    for x in range(1, num_shares + 1):
        # P(x) = a0 + a1*x + a2*x^2 + ... + a[n-1]*x^(n-1) mod p
        y = coefficients[0]  # a0 (秘密値)
        for i in range(1, len(coefficients)):
            term = (coefficients[i] * pow(x, i, prime)) % prime
            y = (y + term) % prime

        shares.append((x, y))  # (x座標, y座標) のペアを保存

    return shares

````

### 4.4. 暗号書庫更新処理の実装

#### 4.4.1. 全体フロー

1. **安全性前処理**：

   - 暗号書庫ファイルのバックアップを作成（UUID 付加）
   - 処理状態を示すロックファイルを生成
   - 保持期間を超過した古いバックアップを削除

2. **MAP 生成**：

   - パーティションマップキーから第 1 段階 MAP を再生成
   - パスワードと第 1 段階 MAP から第 2 段階 MAP を生成
   - 第 2 段階 MAP は暗号書庫構造と独立した相対的マッピングを適用

3. **データ処理**：

   - JSON データの容量検証と多段エンコード
   - チャンク分割（64 バイト固定長）
   - 各チャンクに対してシャミア法でシェア生成
   - 生成したシェアを第 2 段階 MAP に従って配置

4. **安全性後処理**：
   - 処理完了時：ロックファイル削除
   - 異常終了時：バックアップから復元

#### 4.4.2. 障害耐性の実装

シンプルかつ確実なエラーリカバリの実装：

    ```python
def update_crypto_storage(storage_file, json_data, partition_key, password):
    """暗号書庫の更新処理"""
    # バックアップの作成
    backup_file = create_backup(storage_file)

    try:
        # ロックファイル作成
        lock_file = create_lock_file(storage_file)

        # 更新処理のメイン部分
        # 1. MAP生成
        stage1_map = generate_stage1_map(partition_key)
        stage2_map = generate_stage2_map(stage1_map, password)

        # 2. データ処理と暗号化
        shares = process_and_encrypt_data(json_data, stage2_map)

        # 3. 暗号書庫ファイルの更新
        write_storage_file(storage_file, shares)

        # 処理完了の正常終了処理
        os.remove(lock_file)
        return True

    except Exception as e:
        # エラー発生時はバックアップから復元
        restore_from_backup(backup_file, storage_file)
        raise e
    finally:
        # クリーンアップ処理（ロックファイルの削除など）
        cleanup_resources()
````

#### 4.4.3. A/B 文書独立性の保証

更新処理における他文書の非破壊は以下の方法で保証：

1. パーティションマップキーにより、A/B 領域が完全に分離
2. 更新対象領域のシェアのみを変更し、他方の領域のシェアは保持
3. シェア配置時に領域境界チェックを実施

### 4.5. 暗号書庫読取処理の実装

#### 4.5.1. 全体フロー

1. **入力処理**：

   - 暗号書庫ファイル、パーティションマップキー、パスワードの取得

2. **MAP 生成**：

   - パーティションマップキーから第 1 段階 MAP を再生成
   - パスワードと第 1 段階 MAP から第 2 段階 MAP を生成
   - 第 2 段階 MAP は書庫独立性を持つ相対的マッピングを適用

3. **データ復号**：
   - 第 2 段階 MAP に従ってシェアを選択
   - ラグランジュ補間によるシャミア法逆適用でチャンク復元
   - チャンク結合と多段デコード処理
   - パディング除去と JSON 復元

#### 4.5.2. シェア復元アルゴリズム

```python
def recover_secret(shares, prime):
    """シェアから秘密を復元（ラグランジュ補間法）"""
    x_values = [x for x, _ in shares]
    y_values = [y for _, y in shares]

    # ラグランジュ基底多項式の計算
    secret = 0
    for i in range(len(shares)):
        xi, yi = shares[i]

        # ラグランジュ基底多項式の分子・分母を計算
        numerator = 1
        denominator = 1
        for j in range(len(shares)):
            if i == j:
                continue

            xj = shares[j][0]
            numerator = (numerator * (0 - xj)) % prime
            denominator = (denominator * (xi - xj)) % prime

        # 逆元を計算
        inverse = pow(denominator, prime-2, prime)

        # 項を加算
        secret = (secret + yi * numerator * inverse) % prime

    # 負の値の場合は正の値に変換
    if secret < 0:
        secret += prime

    return secret
```

#### 4.5.3. 多段デコードプロセス

復号データに対して暗号化と反対の処理を順に適用：

1. 固定長デシリアライズ
2. Base64 デコード
3. Latin-1 から UTF-8 へのエンコード変換
4. パディング除去
5. JSON 解析

### 4.6. セキュリティ強化と最適化

#### 4.6.1. タイミング攻撃対策

実装全体で定数時間演算を採用し、タイミング攻撃に対する耐性を確保：

1. 比較操作では`constant_time_compare`関数を使用
2. 条件分岐を最小化した直交的処理パス
3. 全データに対して同一の処理ステップを適用

#### 4.6.2. メモリ安全性

1. 機密データ処理後の確実なメモリクリア
2. 一時バッファの安全な割り当てと解放
3. ガベージコレクション前の機密データの明示的なゼロクリア

#### 4.6.3. パフォーマンス最適化

1. 大きな素数演算の効率化（gmpy2 ライブラリの活用）
2. シェア生成・復元処理の並列実行
3. キャッシュラインサイズに合わせたチャンクサイズ最適化

### 4.7. 例外処理とエラー管理

#### 4.7.1. エラー発生時の振る舞い

- 復号失敗時も例外を発生させず、得られたデータをそのまま返却
- 容量制限超過時は明確なエラーメッセージで処理中止
- ロックファイル処理のエラーは詳細なログ記録と回復手順の実行

#### 4.7.2. リソース管理とクリーンアップ

- finally 句による確実なリソース解放
- 一時ファイルとロックファイルの自動クリーンアップ
- 例外発生時の状態復元とロールバック処理
