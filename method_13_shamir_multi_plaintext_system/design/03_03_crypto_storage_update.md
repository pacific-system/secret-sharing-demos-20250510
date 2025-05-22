# シャミア秘密分散法による複数平文復号システム設計書

## 3.3. 詳細設計 - 暗号書庫更新（updateCryptoStorage）

### 3.3.1. 暗号書庫更新の目的と概要

- **目的**: 指定されたパーティションマップキーとパスワードに基づき、暗号書庫への JSON 文書の暗号化と保存を行う
- **責務範囲**: 文書の暗号化、チャンク化、シャミア法の適用、シェア配置、バックアップ管理

### 3.3.2. 入出力仕様

#### 3.3.2.1. 入力

- パーティションマップキー（A または B）
- パスワード（A または B）
- JSON 文書（暗号化対象）
- 暗号書庫ファイルパス

#### 3.3.2.2. 出力

- 更新された暗号書庫ファイル

### 3.3.3. 全体処理フロー

更新処理は以下の主要なステップで構成されています：

```python
def update_crypto_storage(storage_file, json_data, partition_map_key, password):
    """
    暗号書庫の更新処理

    Args:
        storage_file: 暗号書庫ファイルのパス
        json_data: 暗号化するJSON文書
        partition_map_key: パーティションマップキー
        password: パスワード

    Returns:
        success: 更新が成功したかどうか

    Raises:
        DataSizeError: データサイズが上限を超えている場合
        LockError: 既に別のプロセスが更新中の場合
        DecryptionError: パーティションマップキーの復号に失敗した場合
    """
    # 1. 安全性前処理
    backup_file = create_backup(storage_file)
    lock_file = create_lock_file(storage_file)

    try:
        # 2. MAP生成処理
        # 2.1 パーティションマップキーから第1段階MAPを生成
        partition_distribution = restore_partition_distribution(partition_map_key, password)
        stage1_map = partition_distribution

        # 2.2 パスワードから第2段階MAPを生成（パスワードは必ずハッシュ化）
        processed_password = process_password(password)
        stage2_map = generate_stage2_map(stage1_map, processed_password)

        # 3. データ処理
        # 3.1 JSONデータの容量検証
        validate_data_size(json_data, ACTIVE_SHARES * CHUNK_SIZE)

        # 3.2 多段エンコード処理
        encoded_data = multi_stage_encode(json_data)

        # 3.3 固定長シリアライズ
        serialized_data = fixed_length_serialize(encoded_data, partition_map_key, password)

        # 3.4 チャンク分割
        chunks = divide_into_chunks(serialized_data, CHUNK_SIZE)

        # 3.5 シャミア法適用によるシェア生成
        all_shares = []
        prime = get_prime_for_shamir()
        for chunk in chunks:
            chunk_shares = create_shares(chunk, ACTIVE_SHARES, prime)
            all_shares.append(chunk_shares)

        # 3.6 シェア配置
        update_storage_with_shares(storage_file, all_shares, stage1_map, stage2_map)

        # 4. 安全性後処理
        os.remove(lock_file)
        schedule_backup_removal(backup_file)

        return True

    except Exception as e:
        # エラー発生時はバックアップから復元
        restore_from_backup(backup_file, storage_file)
        if os.path.exists(lock_file):
            os.remove(lock_file)
        raise e
```

この実装では、安全性を最優先し、障害耐性と A/B 文書の独立性を保証しています。

#### 3.3.3.1. 安全性前処理

1. **バックアップ作成**:

   - 暗号書庫ファイル（オリジナル）を一時的にバックアップとして複製（UUID 付加）
   - 複製ファイルの完全性を検証
   - バックアップファイルへのアクセス権限設定

2. **ロックファイル処理**:

   - 更新処理状態を示すロックファイルの生成（UUID + 元ファイル情報）
   - 既存ロックファイルがある場合は競合状態を検出し、処理中断

3. **バックアップ管理**:
   - バックアップ保持期間（`BACKUP_RETENTION_DAYS`）を超過した古いバックアップの削除
   - バックアップディレクトリの容量検証

#### 3.3.3.2. MAP 生成処理

1. **パーティションマップキー処理**:

   - パーティションマップキーと**全文そのままのパスワード（生のパスワード）**を使用して第 1 段階 MAP を再生成
   - 正しい領域分布（`PARTITION_SIZE`分のシェア ID）を復元

2. **第 2 段階 MAP 生成**:

   - パスワードをハッシュ化して**処理されたパスワード**を生成
   - 第 1 段階 MAP と**処理されたパスワード**から第 2 段階 MAP を生成（`ACTIVE_SHARES`分の ID を選択）
   - **注意：第 2 段階 MAP 生成には全文そのままのパスワードではなく必ず処理されたパスワードを使用する**

3. **書庫独立性の適用**:
   - パスワードから生成される相対的マッピングパターンはどの暗号書庫でも同じだが、第 1 段階 MAP（書庫固有）に適用されることで、選択されるシェア ID は書庫ごとに完全に異なる結果となる
   - これにより、異なる暗号書庫間で相関分析が不可能になる

#### 3.3.3.3. データフロー処理

1. **入力検証と準備**:

   - JSON データのサイズが容量制限内であることを検証（`ACTIVE_SHARES × CHUNK_SIZE`以下）
   - 容量超過時はエラーを発生させ、処理中断

2. **多段エンコード処理**:

   - UTF-8 テキスト → Latin-1 へのエンコード変換（文字セット変換）
   - Latin-1 → Base64 エンコード（テキスト → バイナリ表現）
   - Base64 → 固定長シリアライズ処理（パーティションマップキーを使用した固定長化）

3. **チャンク分割と処理**:

   - 処理後のデータを厳密に 64 バイト固定サイズのチャンクに分割
   - 全てのチャンクが正確に同じサイズになるよう調整（パディング処理）
   - チャンク数が`ACTIVE_SHARES`に一致することを確認

4. **シャミア法の適用**:

   - 各チャンクに対してシャミア秘密分散法を適用
   - 多項式の次数は `n-1`（n は `ACTIVE_SHARES`）に設定
   - 各チャンクから `ACTIVE_SHARES` 個のシェアを生成

5. **シェア配置処理**:
   - 生成したシェアを第 2 段階 MAP で特定した位置に配置
   - 第 1 段階 MAP で選択されたが第 2 段階 MAP で選択されなかった位置にはガベージシェアを配置
   - 他の文書（A/B）の領域には一切触れない（独立性保証）

#### 3.3.3.4. 安全性後処理

1. **正常終了時**:

   - 処理が正常に完了した場合、ロックファイルを削除
   - 一定期間経過後にバックアップファイルを削除（即時削除はしない）

2. **異常終了時**:
   - 処理中に例外が発生した場合、バックアップから元のファイルを復元
   - ロックファイルに障害情報を記録
   - クリーンアップ処理を実行

### 3.3.4. 主要コンポーネントの実装詳細

#### 3.3.4.1. シャミア秘密分散法のシェア生成

シャミア秘密分散法によるシェア生成アルゴリズムの詳細：

```python
def create_shares(secret, num_shares, prime):
    """
    秘密値から指定数のシェアを生成

    Args:
        secret: 秘密値（暗号化するチャンク）
        num_shares: 生成するシェアの数（ACTIVE_SHARES）
        prime: 使用する素数（有限体の定義に使用）

    Returns:
        shares: 生成されたシェアの配列（(x, y)のペア）
    """
    coefficients = [secret]  # 係数[0]は秘密値

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
```

このアルゴリズムでは、次数 `n-1` の多項式（n は `ACTIVE_SHARES`）を使用して、シェアを生成します。多項式の 0 次の項（定数項）が秘密値となり、1 次以上の項の係数はランダムに生成されます。このランダム性により、生成されるシェアは予測不可能となります。

#### 3.3.4.2. 固定長シリアライズ処理

データの統計的特徴を完全に隠蔽するための固定長シリアライズ処理：

```python
def fixed_length_serialize(data, partition_map_key, password):
    """
    データを固定長形式に変換

    Args:
        data: Base64エンコードされたデータ
        partition_map_key: パーティションマップキー
        password: パスワード

    Returns:
        serialized_data: 固定長シリアライズされたデータ
    """
    # パーティションマップキーとパスワードから暗号化キーを導出
    key = derive_encryption_key(partition_map_key, password)

    # データ長を計算
    data_length = len(data)
    required_length = ACTIVE_SHARES * CHUNK_SIZE

    # データ長が不足している場合はパディング
    if data_length < required_length:
        padding_length = required_length - data_length
        data += generate_random_padding(padding_length)

    # データ長が超過している場合はエラー
    elif data_length > required_length:
        raise DataSizeError(f"データサイズが上限を超えています: {data_length} > {required_length}")

    # 固定長に調整されたデータを暗号化
    serialized_data = encrypt_data(data, key)

    return serialized_data
```

この処理により、元データの長さに関わらず、常に`ACTIVE_SHARES * CHUNK_SIZE`バイトの固定長データが生成されます。さらに、パーティションマップキーを使った暗号化により、データの統計的特徴も完全に隠蔽されます。

#### 3.3.4.3. A/B 文書独立性の保証

暗号書庫内の A/B 文書の独立性を保証するための仕組み：

1. **パーティション分離**:

   - A 用と B 用のパーティションは生成時に完全に分離され、重複しない
   - パーティションマップキーにより、それぞれの領域のみにアクセス可能

2. **更新時の書き込み制限**:

   - 更新処理は指定されたパーティションマップキーに対応する領域のみに書き込みを行う
   - 他方の領域のシェアには一切触れない

3. **実装における保証**:

```python
def write_storage_file(storage_file, shares, stage1_map):
    """
    シェアを暗号書庫ファイルに書き込む

    Args:
        storage_file: 暗号書庫ファイルのパス
        shares: 書き込むシェア
        stage1_map: 第1段階MAP（アクセス可能な領域を示す）
    """
    # 元のファイル内容を読み込み
    with open(storage_file, 'r') as f:
        storage_content = json.load(f)

    # 指定された領域のシェアのみを更新
    for i, idx in enumerate(stage1_map):
        if i < len(shares):
            storage_content[idx] = shares[i]
        else:
            # 残りの位置にはガベージシェアを配置
            storage_content[idx] = generate_garbage_share()

    # 更新内容を書き込み
    with open(storage_file, 'w') as f:
        json.dump(storage_content, f)
```

このコードでは、第 1 段階 MAP で特定した領域のシェアのみを更新し、それ以外の領域には一切触れません。これにより、A の更新が B に影響を与えることはなく、完全な独立性が保証されます。

### 3.3.5. 障害耐性と安全性機能

#### 3.3.5.1. 障害耐性の実装

暗号書庫更新処理中の障害に対応するためのバックアップ・復元メカニズムの詳細：

```python
def update_crypto_storage(storage_file, json_data, partition_key, password):
    """
    暗号書庫の更新処理（障害対応版）
    """
    # バックアップの作成
    backup_file = create_backup(storage_file)

    try:
        # ロックファイル作成
        lock_file = create_lock_file(storage_file)

        # 更新処理のメイン部分
        # (省略 - 詳細は3.3.3セクション参照)

        # 処理完了の正常終了処理
        os.remove(lock_file)
        return True

    except Exception as e:
        # エラー発生時はバックアップから復元
        restore_from_backup(backup_file, storage_file)
        # ロックファイルが存在する場合は削除
        if os.path.exists(lock_file):
            os.remove(lock_file)
        raise e
    finally:
        # クリーンアップ処理
        cleanup_resources()
```

このコードでは、try-except-finally パターンを使用して、障害発生時にも確実に元の状態に復元できるようにしています。バックアップファイルの作成と復元処理により、更新処理中の障害（停電、クラッシュなど）からも安全に回復できます。

#### 3.3.5.2. 更新処理の特性

- **障害耐性**: 書き込み中の障害に対応するバックアップ・復元メカニズムにより処理の信頼性を確保
- **独立性**: A/B 文書の独立性が保証され、一方を更新しても他方に影響が及ばない
- **一貫性**: 同じパーティションマップキーとパスワードの組み合わせで後に読み取り可能
- **上書き許容**: パスワードとパーティションマップキーのペアが一致しない場合、データの上書きが発生する可能性がある（セキュリティモデル上は「許容事象」）
- **非冪等性**: 更新処理は冪等ではなく、同じ入力で複数回実行すると、毎回異なるガベージシェアとランダム係数が生成される
- **WAL 方式**: Write-Ahead Logging 方式により、処理中断時にも一貫性を保証
- **排他制御**: 実行中の排他制御によって複数プロセスからの同時更新を防止

### 3.3.6. 実装パターン

暗号書庫更新処理における主要な実装パターンを以下に示します。これらのパターンは安全かつ効率的な実装を支援するものです。

#### 3.3.6.1. パーティションマップキーの復号パターン

パーティションマップキーから領域分布（第 1 段階 MAP）を復元するパターン：

```python
def decrypt_partition_map(partition_map_key, password):
    """
    パーティションマップキーを全文そのままのパスワード（生のパスワード）で復号する

    Args:
        partition_map_key: 復号するパーティションマップキー
        password: 復号に使用する生のパスワード

    Returns:
        partition_distribution: 復元された領域分布（整数配列）

    Raises:
        DecryptionError: 復号に失敗した場合（パスワードが誤っているなど）
    """
    try:
        # 1. ハイフンを除去してBase64デコード
        clean_key = partition_map_key.replace('-', '')
        encrypted_data = base64.urlsafe_b64decode(clean_key)

        # 2. 暗号データからソルト、ノンス、タグ、暗号文を抽出
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        tag = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]

        # 3. 生のパスワードから復号キーを導出（暗号化時と同じ方法）
        key = derive_key_from_password(password, salt)

        # 4. 復号と認証検証
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        # 5. JSONデシリアライズ
        partition_distribution = json.loads(data.decode('utf-8'))

        return partition_distribution

    except (ValueError, KeyError, json.JSONDecodeError) as e:
        # 復号失敗時は例外を送出
        raise DecryptionError(f"パーティションマップキーの復号に失敗しました: {str(e)}")
```

#### 3.3.6.2. 第 2 段階 MAP 生成パターン

処理されたパスワードを使用して第 2 段階 MAP を生成するパターン：

```python
def process_password(password):
    """
    パスワードを処理（ハッシュ化）する

    Args:
        password: 生のパスワード

    Returns:
        processed_password: ハッシュ化されたパスワード
    """
    # Argon2idを使用して安全にハッシュ化（メモリハードな関数）
    salt = b'static_salt_for_stage2_map'  # 固定ソルト（第2段階MAP生成専用）
    hash_obj = argon2.argon2_hash(
        password.encode('utf-8'),
        salt,
        time_cost=3,     # 反復回数
        memory_cost=65536,  # メモリ使用量(KiB)
        parallelism=4,   # 並列度
        hash_len=32      # 出力ハッシュ長
    )
    return hash_obj

def generate_stage2_map(stage1_map, processed_password):
    """
    処理されたパスワードを使用して第2段階MAPを生成する

    Args:
        stage1_map: 第1段階MAP（パーティション分布）
        processed_password: ハッシュ化されたパスワード

    Returns:
        stage2_map: 第2段階MAP（ACTIVE_SHARES個のインデックス）

    注意:
        必ず処理（ハッシュ化）されたパスワードを使用すること。
        生のパスワードを直接使用してはならない。
    """
    # 要素数確認
    partition_size = len(stage1_map)

    # 鍵導出関数を使用して擬似乱数生成
    prng = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'stage2_map_generation'
    ).derive(processed_password)

    # 暗号化乱数ジェネレータの初期化
    random_generator = random.Random()
    random_generator.seed(int.from_bytes(prng, 'big'))

    # インデックスのリストを作成（0からpartition_size-1まで）
    indices = list(range(partition_size))

    # リストをシャッフル（擬似乱数使用）
    random_generator.shuffle(indices)

    # ACTIVE_SHARES個の要素を選択
    selected_indices = indices[:ACTIVE_SHARES]

    return selected_indices
```

#### 3.3.6.3. ファイルロック検証パターン

更新処理中の排他制御を実装するためのロック機構：

```python
def create_lock_file(file_path):
    """
    ファイルロックを作成する

    Args:
        file_path: ロックを作成する対象ファイルのパス

    Returns:
        lock_path: 作成されたロックファイルのパス

    Raises:
        LockError: 既にロックが存在する場合
    """
    lock_path = file_path + ".lock"

    # ロックファイルの存在確認
    if os.path.exists(lock_path):
        # ロックファイルの作成時刻を取得
        lock_time = os.path.getmtime(lock_path)
        current_time = time.time()

        # ロックタイムアウトの確認（30分を超過したロックは無効と判断）
        if current_time - lock_time > 1800:  # 30分 = 1800秒
            # 古いロックを削除
            os.remove(lock_path)
        else:
            # 有効なロックが存在する場合はエラー
            raise LockError(f"ファイル {file_path} は既に別のプロセスによってロックされています")

    # 新しいロックファイルを作成
    try:
        with open(lock_path, 'w') as f:
            # プロセスIDとタイムスタンプを記録
            lock_info = {
                'pid': os.getpid(),
                'timestamp': time.time(),
                'hostname': socket.gethostname()
            }
            json.dump(lock_info, f)

        return lock_path

    except Exception as e:
        # ロックファイル作成に失敗した場合
        raise LockError(f"ロックファイルの作成に失敗しました: {str(e)}")
```

#### 3.3.6.4. 障害復旧処理パターン

WAL（Write-Ahead Logging）方式に基づくバックアップと復元メカニズム：

```python
def create_backup(file_path):
    """
    ファイルのバックアップを作成する

    Args:
        file_path: バックアップを作成する対象ファイルのパス

    Returns:
        backup_path: 作成されたバックアップファイルのパス
    """
    # バックアップディレクトリの確認と作成
    backup_dir = os.path.join(os.path.dirname(file_path), 'backups')
    os.makedirs(backup_dir, exist_ok=True)

    # タイムスタンプとUUIDを含むバックアップファイル名の生成
    timestamp = int(time.time())
    uuid_str = str(uuid.uuid4())[:8]
    filename = os.path.basename(file_path)
    backup_filename = f"{filename}.{timestamp}.{uuid_str}.bak"
    backup_path = os.path.join(backup_dir, backup_filename)

    # ファイルのコピー
    shutil.copy2(file_path, backup_path)

    # 古いバックアップの削除（BACKUP_RETENTION_DAYS日より古いもの）
    cleanup_old_backups(backup_dir, BACKUP_RETENTION_DAYS)

    return backup_path

def restore_from_backup(backup_path, target_path):
    """
    バックアップからファイルを復元する

    Args:
        backup_path: 復元元のバックアップファイルパス
        target_path: 復元先のファイルパス

    Returns:
        success: 復元が成功したかどうか
    """
    try:
        # バックアップファイルの存在確認
        if not os.path.exists(backup_path):
            return False

        # ファイルの復元
        shutil.copy2(backup_path, target_path)
        return True

    except Exception as e:
        logger.error(f"バックアップからの復元に失敗しました: {str(e)}")
        return False
```

#### 3.3.6.5. 多段エンコード処理パターン

JSON データの多段エンコード処理を行うパターン：

```python
def multi_stage_encode(json_data):
    """
    JSONデータを多段エンコードする

    Args:
        json_data: エンコードするJSON文書

    Returns:
        encoded_data: 多段エンコードされたデータ
    """
    # 1. JSON文書をUTF-8テキストに変換
    if isinstance(json_data, str):
        # 既にJSON文字列の場合は検証
        try:
            # 有効なJSONかどうか確認
            parsed = json.loads(json_data)
            utf8_text = json_data
        except json.JSONDecodeError:
            # 無効なJSONの場合は文字列として扱う
            utf8_text = json.dumps(json_data)
    else:
        # オブジェクトの場合はJSONに変換
        utf8_text = json.dumps(json_data)

    # 2. UTF-8をLatin-1にエンコード変換
    latin1_bytes = utf8_text.encode('utf-8')
    latin1_text = latin1_bytes.decode('latin-1', errors='replace')

    # 3. Base64エンコード
    base64_bytes = base64.b64encode(latin1_text.encode('latin-1'))
    base64_text = base64_bytes.decode('ascii')

    return base64_text
```
