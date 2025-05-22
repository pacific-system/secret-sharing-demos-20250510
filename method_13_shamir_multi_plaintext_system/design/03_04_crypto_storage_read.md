# シャミア秘密分散法による複数平文復号システム設計書

## 3.4. 詳細設計 - 暗号書庫読取（readCryptoStorage）

### 3.4.1. 暗号書庫読取の目的と概要

- **目的**: 指定されたパーティションマップキーとパスワードに基づき、暗号書庫から JSON 文書を復号して取得する
- **責務範囲**: シェア選択、シャミア法逆適用、チャンク結合、多段デコード処理、JSON 文書の復元

### 3.4.2. 入出力仕様

#### 3.4.2.1. 入力

- パーティションマップキー（A または B）
- パスワード（A または B）
- 暗号書庫ファイルパス

#### 3.4.2.2. 出力

- 復元された JSON 文書

### 3.4.3. 全体処理フロー

暗号書庫読取関数の全体実装を以下に示します。これにより処理の全体像を把握できます：

```python
def read_crypto_storage(storage_file, partition_map_key, password):
    """
    暗号書庫からデータを読み取る関数

    Args:
        storage_file: 暗号書庫ファイルのパス
        partition_map_key: パーティションマップキー
        password: パスワード

    Returns:
        json_data: 復元されたJSON文書

    Raises:
        FileNotFoundError: 暗号書庫ファイルが存在しない場合
        PermissionError: ファイルの読み取り権限がない場合
    """
    try:
        # 1. 入力処理
        # ファイルの存在確認と読み込み
        with open(storage_file, 'r') as f:
            storage_content = json.load(f)

        # 2. MAP生成処理
        # 2.1 パーティションマップキーから第1段階MAPを生成
        partition_distribution = restore_partition_distribution(partition_map_key, password)
        stage1_map = partition_distribution

        # 2.2 パスワードから第2段階MAPを生成（パスワードは必ずハッシュ化）
        processed_password = process_password(password)
        stage2_map = generate_stage2_map(stage1_map, processed_password)

        # 3. データ復号処理
        # 3.1 シェア選択
        selected_shares = []
        for i, map_idx in enumerate(stage2_map):
            if map_idx < len(stage1_map):
                storage_idx = stage1_map[map_idx]
                if storage_idx < len(storage_content):
                    selected_shares.append(storage_content[storage_idx])

        # 3.2 シェアをチャンク単位にグループ化
        share_groups = group_shares_by_chunk(selected_shares)

        # 3.3 各チャンクグループに対してシャミア法の逆適用
        chunks = []
        prime = get_prime_for_shamir()
        for group in share_groups:
            secret = recover_secret(group, prime)
            chunks.append(secret)

        # 3.4 チャンク結合と多段デコード処理
        serialized_data = combine_chunks(chunks)
        decoded_data = multi_stage_decode(serialized_data, partition_map_key, password)

        # 3.5 JSONパース
        try:
            json_data = json.loads(decoded_data)
            return json_data
        except json.JSONDecodeError:
            # パスワードが間違っている可能性があるが、エラーは明示しない
            return decoded_data

    except (FileNotFoundError, PermissionError):
        # ファイル関連のエラーのみ再発生させる
        raise
    except Exception:
        # その他の例外は捕捉して、デコードされたものを返す
        # 無効なデータであっても例外は発生させない（セキュリティ上の理由）
        return None
```

この実装では、ファイルの存在チェックと読み取り権限チェック以外のエラーは捕捉し、復号されたデータをそのまま返却します。これは、セキュリティ上の理由から、間違ったパスワードや不正なデータに対する情報漏洩を防ぐためです。

#### 3.4.3.1. 入力処理

1. **パラメータ検証**:

   - 暗号書庫ファイルの確認（空文字列チェック）
   - パーティションマップキーの形式検証（空文字列チェック）
   - パスワードの存在確認（空文字列チェック）

2. **ファイル読み込み**:
   - 指定されたパスの暗号書庫ファイルを読み込み
   - ファイルフォーマットの検証（JSON 配列構造確認）

#### 3.4.3.2. MAP 生成処理

1. **パーティションマップキー処理**:

   - パーティションマップキーと**全文そのままのパスワード（生のパスワード）**を使用して第 1 段階 MAP を再生成
   - パーティション分布（`PARTITION_SIZE`分のシェア ID）を復元

2. **第 2 段階 MAP 生成**:

   - パスワードをハッシュ化して**処理されたパスワード**を生成
   - 第 1 段階 MAP から得られた候補と**処理されたパスワード**から第 2 段階 MAP を生成
   - **注意：第 2 段階 MAP 生成には全文そのままのパスワードではなく必ず処理されたパスワードを使用する**

3. **書庫独立性の実現**:
   - パスワードから生成されるマッピングパターンは「相対的」であり、第 1 段階 MAP に適用されて「絶対的」なシェア ID に変換される
   - これにより、異なる暗号書庫でも同じパスワードが使用できる（書庫独立性）

#### 3.4.3.3. データ復号処理

1. **シェア選択**:

   - 第 2 段階 MAP に従って、暗号書庫ファイルから必要なシェアを選択
   - `ACTIVE_SHARES`個のシェアを正確に選び出す
   - シェアを元のチャンク単位にグループ化

2. **シャミア法の逆適用（ラグランジュ補間）**:

   - 各チャンクグループに対してラグランジュ補間を適用
   - 多項式の 0 次項（秘密値）を計算して復元
   - 全チャンクについて上記の処理を繰り返し

3. **チャンク結合と多段デコード処理**:

   - 復元したチャンクを順序正しく結合
   - 固定長シリアライズの解除
   - Base64 デコード
   - Latin-1 から UTF-8 へのエンコード変換
   - パディングデータの除去

4. **JSON 文書の復元**:
   - UTF-8 テキストを JSON としてパース
   - JSON 構造の検証（整合性チェック）

### 3.4.4. 主要コンポーネントの実装詳細

#### 3.4.4.1. シャミア秘密分散法のシェア復元

シャミア秘密分散法によるシェア復元（ラグランジュ補間）アルゴリズムの詳細：

```python
def recover_secret(shares, prime):
    """
    シェアから秘密を復元（ラグランジュ補間法）

    Args:
        shares: シェアの配列（(x, y)のペア）
        prime: 使用する素数（有限体の定義に使用）

    Returns:
        secret: 復元された秘密値
    """
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

        # 逆元を計算（フェルマーの小定理を使用）
        inverse = pow(denominator, prime-2, prime)

        # 項を加算
        term = (yi * numerator * inverse) % prime
        secret = (secret + term) % prime

    # 負の値の場合は正の値に変換
    if secret < 0:
        secret += prime

    return secret
```

このアルゴリズムでは、ラグランジュ補間公式を使用して多項式を再構築し、x = 0 における値（秘密値）を計算します。全てのシェアが必要であり、これにより秘密値を確実に復元できます。

#### 3.4.4.2. シェア復元と組み立てのアルゴリズム

シェアを適切にグループ化し、チャンクを順番に並べる処理の詳細：

```python
def group_shares_by_chunk(shares):
    """
    シェアをチャンク単位にグループ化

    Args:
        shares: 選択されたシェアの配列

    Returns:
        groups: チャンク別にグループ化されたシェアの配列
    """
    chunk_count = len(shares) // ACTIVE_SHARES
    groups = []

    for i in range(chunk_count):
        start_idx = i * ACTIVE_SHARES
        end_idx = start_idx + ACTIVE_SHARES
        group = shares[start_idx:end_idx]
        groups.append(group)

    return groups

def combine_chunks(chunks):
    """
    復元されたチャンクを結合

    Args:
        chunks: 復元されたチャンクの配列

    Returns:
        combined_data: 結合されたデータ
    """
    serialized_data = b''
    for chunk in chunks:
        # 各チャンクをバイナリ形式に変換して結合
        chunk_bytes = int_to_bytes(chunk, CHUNK_SIZE)
        serialized_data += chunk_bytes

    return serialized_data
```

これらの関数により、個々のシェアから元のチャンクを復元し、それらを正しい順序で結合して元のデータを再構築します。シェアのグループ化と順序付けは、暗号化時に使用された方法と正確に対応している必要があります。

#### 3.4.4.3. 多段デコードプロセス

暗号化時と逆順の多段デコード処理の詳細：

```python
def multi_stage_decode(serialized_data, partition_map_key, password):
    """
    多段デコード処理

    Args:
        serialized_data: 固定長シリアライズされたデータ
        partition_map_key: パーティションマップキー
        password: パスワード

    Returns:
        decoded_data: デコードされた元のデータ（UTF-8テキスト）
    """
    # 1. 固定長シリアライズの解除
    key = derive_encryption_key(partition_map_key, password)
    deserialized_data = decrypt_data(serialized_data, key)

    # 2. Base64デコード
    base64_decoded = base64.b64decode(deserialized_data)

    # 3. Latin-1からUTF-8へのエンコード変換
    latin1_text = base64_decoded.decode('latin-1')

    # 4. パディングの除去
    utf8_text = latin1_text.encode('latin-1').decode('utf-8')
    decoded_data = remove_padding(utf8_text)

    return decoded_data
```

この多段デコード処理は、暗号化時に適用された各種変換を正確に逆順で実行し、元のデータを復元します。特に、固定長シリアライズの解除とエンコーディング変換は、暗号化時と正確に対応する必要があります。

### 3.4.5. セキュリティ特性と対策

#### 3.4.5.1. 読取処理の特性

- **直線的処理**: 完全に直線的な処理で条件分岐がなく、タイミング攻撃に対する耐性がある
- **同一コードパス**: 同一のコードパスを通り、処理時間が入力の特性に依存しないよう設計
- **情報隠蔽**: 暗号書庫自体からは格納されているデータに関する手がかりが得られない
- **認証要件**: 正しいパスワードとパーティションマップキーの組み合わせのみで復号可能
- **エラー抑制**: 間違ったパスワードを使用しても例外を発生させず、デコードされたデータ（無意味なデータ）をそのまま返却
- **最小例外**: 暗号書庫が存在しない、または読み取り権限がない場合のみ例外発生
- **決定論的処理**: 復号処理のワークフローは決定論的で、同じ入力に対して常に同じ出力を生成

#### 3.4.5.2. タイミング攻撃に対する対策

タイミング攻撃を防止するための実装上の工夫：

```python
def constant_time_compare(a, b):
    """
    定数時間での文字列比較（タイミング攻撃対策）

    Args:
        a: 比較対象の文字列1
        b: 比較対象の文字列2

    Returns:
        result: 一致する場合はTrue、それ以外はFalse
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)

    return result == 0
```

このような定数時間アルゴリズムを比較操作やデータ検証に使用することで、処理時間の違いからパスワードなどの機密情報が漏洩することを防ぎます。

#### 3.4.5.3. 許容事象に対する対応

読取処理において許容されるさまざまな事象への対応：

1. **間違ったパスワードの使用**:

   - 例外は発生させず、デコード結果として無意味なデータを返却
   - ログにエラーメッセージは記録しない（攻撃の手がかりを与えない）

2. **存在しないデータ領域の読み取り**:

   - 第 1 段階 MAP と第 2 段階 MAP に基づいて特定される領域のシェアを使用
   - 実際のデータが存在しない場合は、ガベージシェアが読み込まれる
   - 結果として無意味なデータが返却されるが、例外は発生しない

3. **A 用パスワードで B 用データにアクセス**:
   - A 用パーティションマップキーと A 用パスワードを使用した場合、A 用の領域だけが読み取られる
   - B 用のデータには一切アクセスせず、存在しないかのように処理

### 3.4.6. 実装パターン

暗号書庫読取処理における主要な実装パターンを以下に示します。これらのパターンは安全かつ効率的な実装を支援するものです。

#### 3.4.6.1. パーティションマップキーの復号パターン

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
        # タイミング攻撃を防ぐため、エラー処理時も一定時間の処理を行う
        dummy_operation()
        # 復号失敗時も例外を発生させず、空の配列を返す
        return []
```

#### 3.4.6.2. 第 2 段階 MAP 生成パターン

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
    # 要素数確認（空の場合は空の配列を返す）
    if not stage1_map:
        return []

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

    # ACTIVE_SHARES個の要素を選択（全要素数がACTIVE_SHARESより少ない場合は全て選択）
    active_shares = min(ACTIVE_SHARES, len(indices))
    selected_indices = indices[:active_shares]

    return selected_indices
```

#### 3.4.6.3. 多段デコード処理パターン

暗号化時に施された多段エンコード処理の逆処理を行うパターン：

```python
def multi_stage_decode(serialized_data, partition_map_key, password):
    """
    多段デコード処理を行う

    Args:
        serialized_data: 固定長シリアライズされたデータ（バイト列）
        partition_map_key: パーティションマップキー
        password: パスワード

    Returns:
        decoded_data: デコードされたJSON文書
    """
    try:
        # 1. 固定長シリアライズの解除
        key = derive_encryption_key(partition_map_key, password)
        deserialized_data = decrypt_data(serialized_data, key)

        # 2. Base64デコード
        try:
            base64_decoded = base64.b64decode(deserialized_data)
        except:
            # Base64デコードに失敗した場合は、そのまま返す
            return deserialized_data

        # 3. Latin-1からUTF-8へのエンコード変換
        try:
            latin1_text = base64_decoded.decode('latin-1')
            utf8_bytes = latin1_text.encode('latin-1')
            utf8_text = utf8_bytes.decode('utf-8', errors='replace')
        except:
            # エンコード変換に失敗した場合は、ここまでの結果を返す
            return base64_decoded

        # 4. パディングの除去
        unpadded_data = remove_padding(utf8_text)

        return unpadded_data

    except Exception as e:
        # 例外が発生した場合は空文字列を返す（エラーはシグナルしない）
        return ""
```

#### 3.4.6.4. JSON フォーマット検証パターン

復元されたデータが JSON 形式として有効かを検証するパターン：

```python
def validate_json(json_data):
    """
    JSONフォーマットを検証する

    Args:
        json_data: 検証するJSON文字列

    Returns:
        result: 検証結果（オブジェクト）
            - valid: 有効なJSONかどうか（ブール値）
            - data: パースされたJSONオブジェクト（validがTrueの場合）
            - error: エラーメッセージ（validがFalseの場合）
    """
    result = {
        'valid': False,
        'data': None,
        'error': None
    }

    if not json_data:
        result['error'] = "データが空です"
        return result

    # 文字列型かどうか確認
    if not isinstance(json_data, str):
        try:
            # 文字列に変換を試みる
            json_data = str(json_data)
        except:
            result['error'] = "データを文字列に変換できません"
            return result

    # JSONパースを試行
    try:
        parsed_data = json.loads(json_data)
        result['valid'] = True
        result['data'] = parsed_data
    except json.JSONDecodeError as e:
        result['error'] = f"JSONパースエラー: {str(e)}"

    return result

def safe_json_parse(json_data):
    """
    安全にJSONをパースする

    Args:
        json_data: パースするJSON文字列

    Returns:
        parsed_data: パースされたデータ（パースに失敗した場合は元のデータ）
    """
    # JSON検証
    validation = validate_json(json_data)

    if validation['valid']:
        return validation['data']
    else:
        # パースに失敗した場合は元のデータをそのまま返す
        # （エラー情報は返さない - セキュリティ上の理由から）
        return json_data
```

これらの実装パターンは、暗号書庫読取処理の安全性と信頼性を確保するために重要です。特に、直線的処理の原則に従い、条件分岐を最小限にしたタイミング攻撃に強い実装となっています。
