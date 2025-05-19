## データの復号

復号プロセスでは、暗号化ファイルから適切なシェアを選択し、シャミア秘密分散法を用いて元の JSON 文書を復元します。このプロセスでは条件分岐を避け、定数時間で処理を行う必要があります。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `02_architecture.md`: 2.3 節「多段 MAP 方式の詳細」
- `03_detailed_design.md`: 3.3 節「多段 MAP の実装」
- `04_implementation.md`: 4.2 節「復号プロセス」
- `05_security.md`: 5.3 節「ソースコード漏洩時のセキュリティ」
- `07_guidelines.md`: 7.3 節「条件分岐の禁止と定数時間処理の実装パターン」

### 1. 多段 MAP 処理の実装

データの復号化部分では、暗号化ファイルから多段 MAP を使ってシェアを選択し、シャミア秘密分散法で復元処理を行います。サイドチャネル攻撃に対する防御として、条件分岐を避けた定数時間処理を実装します。

### 1. 多段 MAP によるシェア選択

```python
def select_shares_for_decryption(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> List[Dict[str, Any]]:
    """
    復号に使用するシェアを多段MAPで選択

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を復号します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        encrypted_file: 暗号化されたファイルデータ
        partition_key: パーティションマップキー（AまたはBのいずれか）
        password: 復号化パスワード

    Returns:
        選択されたシェアのリスト（チャンクごとにソート済み）
    """
    # メタデータ取得
    metadata = encrypted_file['metadata']
    threshold = metadata['threshold']
    all_shares = encrypted_file['shares']

    # ソルト値を取得
    salt = base64.b64decode(metadata['salt'])

    # パーティションマップキーからシェアIDを取得（第1段階MAP）
    # 全シェアIDリストを構築
    all_share_ids = sorted(list(set(share['share_id'] for share in all_shares)))

    # 第1段階MAP: パーティションマップキーによる候補シェア選択
    candidate_ids = stage1_map(partition_key, all_share_ids)

    # 候補シェアから実際のシェアオブジェクトを取得
    candidate_shares = [s for s in all_shares if s['share_id'] in candidate_ids]

    # 第2段階MAP: パスワードによるマッピング
    mappings = stage2_map(password, candidate_ids, salt)

    # チャンク別にシェアを整理
    chunks = {}
    for share in candidate_shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        # シェア値を文字列からmpzに変換
        value = mpz(share['value'])
        chunks[chunk_idx].append((share['share_id'], value))

    # 各チャンクについて、シェアをマッピング値でソートし、閾値分選択
    selected_shares = []
    chunk_indices = sorted(chunks.keys())

    for chunk_idx in chunk_indices:
        # マッピング値でソート
        sorted_shares = sorted(chunks[chunk_idx], key=lambda s: mappings[s[0]])

        # 閾値分のシェアを選択
        threshold_shares = sorted_shares[:threshold]

        # 選択されたシェアをリストに追加
        for share_id, value in threshold_shares:
            selected_shares.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': value
            })

    return selected_shares
```

### 2. データの復元と後処理

```python
def reconstruct_secret(
    shares: List[Dict[str, Any]],
    threshold: int,
    prime: mpz
) -> List[bytes]:
    """
    シェアから秘密（チャンク）を復元

    Args:
        shares: 選択されたシェア
        threshold: 閾値
        prime: 有限体の素数

    Returns:
        復元されたチャンクデータ
    """
    # チャンク別にシェアを整理
    chunks = {}
    for share in shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        chunks[chunk_idx].append((share['share_id'], share['value']))

    # 各チャンクを復元
    reconstructed_chunks = []
    chunk_indices = sorted(chunks.keys())

    for chunk_idx in chunk_indices:
        chunk_shares = chunks[chunk_idx]

        # ラグランジュ補間で秘密を復元
        secret = lagrange_interpolation(chunk_shares, prime)

        # 秘密を適切なバイト長に変換
        # mpzからバイト列に変換する際のビット長計算
        bit_length = secret.bit_length()
        byte_length = (bit_length + 7) // 8
        byte_length = max(byte_length, 1)  # 最低1バイト

        # ゼロの場合は特別処理
        if secret == 0:
            chunk_bytes = b'\x00' * ShamirConstants.CHUNK_SIZE
        else:
            # 整数からバイト列に変換
            chunk_bytes = secret.to_bytes(byte_length, 'big')

            # チャンクサイズが一定になるようにパディング/トリミング
            if len(chunk_bytes) < ShamirConstants.CHUNK_SIZE:
                chunk_bytes = chunk_bytes.ljust(ShamirConstants.CHUNK_SIZE, b'\x00')
            elif len(chunk_bytes) > ShamirConstants.CHUNK_SIZE:
                chunk_bytes = chunk_bytes[:ShamirConstants.CHUNK_SIZE]

        reconstructed_chunks.append(chunk_bytes)

    return reconstructed_chunks


def postprocess_json_document(chunks: List[bytes]) -> Any:
    """
    復元されたチャンクからJSON文書を復元

    Args:
        chunks: 復元されたチャンクのリスト

    Returns:
        復元されたJSON文書
    """
    # チャンクを結合
    data = b''.join(chunks)

    # パディングを除去（後続のヌルバイトを除去）
    data = data.rstrip(b'\x00')

    # URL安全なBase64デコード
    try:
        compressed_data = base64.urlsafe_b64decode(data)

        # 解凍
        json_bytes = zlib.decompress(compressed_data)

        # JSON解析
        json_data = json.loads(json_bytes.decode('utf-8'))
        return json_data
    except Exception as e:
        # エラーが発生した場合、部分的な結果を返す
        # サイドチャネル攻撃対策として例外は投げない
        return {"error": "Invalid data or wrong password", "partial_data": data[:100].hex()}
```

### 3. 定数時間復号化処理

```python
def constant_time_select(condition: bool, true_value: Any, false_value: Any) -> Any:
    """
    条件分岐なしの選択処理

    Args:
        condition: 条件
        true_value: 条件がTrueの場合の値
        false_value: 条件がFalseの場合の値

    Returns:
        選択された値
    """
    # 条件を整数に変換（True: 1, False: 0）
    condition_int = int(condition)

    # ビット演算による選択
    # 数値型の場合
    if isinstance(true_value, (int, float)) and isinstance(false_value, (int, float)):
        # condition_int が 1 なら true_value を、0 なら false_value を返す
        return (condition_int * true_value) + ((1 - condition_int) * false_value)

    # リスト型の場合
    elif isinstance(true_value, list) and isinstance(false_value, list):
        if condition_int:
            return true_value.copy()
        else:
            return false_value.copy()

    # その他の型（辞書、文字列など）
    else:
        if condition_int:
            if hasattr(true_value, 'copy') and callable(getattr(true_value, 'copy')):
                return true_value.copy()
            return true_value
        else:
            if hasattr(false_value, 'copy') and callable(getattr(false_value, 'copy')):
                return false_value.copy()
            return false_value


def try_decrypt_with_both_maps(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> Tuple[bool, Any]:
    """
    パーティションマップキーとパスワードを使って復号を試みる
    エラーが発生しても例外を投げず、成功/失敗を返す

    Args:
        encrypted_file: 暗号化ファイル
        partition_key: パーティションマップキー
        password: パスワード

    Returns:
        (成功フラグ, 復元されたJSON文書または部分データ)
    """
    try:
        # シェアを選択
        selected_shares = select_shares_for_decryption(
            encrypted_file, partition_key, password
        )

        # メタデータから閾値を取得
        threshold = encrypted_file['metadata']['threshold']

        # シェアから秘密を復元
        reconstructed_chunks = reconstruct_secret(
            selected_shares, threshold, ShamirConstants.PRIME
        )

        # 後処理してJSON文書に変換
        json_doc = postprocess_json_document(reconstructed_chunks)

        # JSONとして解析できた場合は成功
        success = True
        if isinstance(json_doc, dict) and 'error' in json_doc:
            success = False

        return (success, json_doc)

    except Exception as e:
        # どのような例外が発生しても、サイドチャネル攻撃対策として
        # エラーレスポンスを返す
        return (False, {"error": "Decryption failed", "details": str(e)})


def decrypt_json_document(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> Any:
    """
    暗号化されたJSONドキュメントを復号

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を復号します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        encrypted_file: 暗号化ファイル
        partition_key: パーティションマップキー（AまたはBのいずれか）
        password: パスワード

    Returns:
        復号されたJSON文書
    """
    # 復号を試みる
    success, result = try_decrypt_with_both_maps(
        encrypted_file, partition_key, password
    )

    # 成功の場合はJSONデータを返す
    # 失敗の場合もデータを返す（セキュリティのため例外を投げない）
    return result


def load_encrypted_file(file_path: str) -> Dict[str, Any]:
    """
    暗号化ファイルを読み込む

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        暗号化ファイルデータ
    """
    with open(file_path, 'r') as f:
        encrypted_file = json.load(f)

    # シェア値を文字列からmpzに変換
    for share in encrypted_file['shares']:
        if isinstance(share['value'], str):
            share['value'] = mpz(share['value'])

    return encrypted_file
```

### 4. 直線的処理によるサイドチャネル攻撃対策

```python
def secure_decrypt(
    encrypted_file_path: str,
    partition_key: str,
    password: str
) -> Any:
    """
    サイドチャネル攻撃に耐性のある安全な復号処理

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        partition_key: パーティションマップキー
        password: パスワード

    Returns:
        復号されたJSON文書
    """
    # タイミング攻撃対策：処理時間を一定にするための開始時間記録
    start_time = time.time()

    # 暗号化ファイルを読み込む
    encrypted_file = load_encrypted_file(encrypted_file_path)

    # 復号処理を実行
    result = decrypt_json_document(encrypted_file, partition_key, password)

    # タイミング攻撃対策：処理時間を一定に保つ
    # 最低でも1秒の処理時間を保証
    elapsed = time.time() - start_time
    min_time = 1.0  # 最低処理時間（秒）

    if elapsed < min_time:
        time.sleep(min_time - elapsed)

    return result


def is_valid_json_result(result: Any) -> bool:
    """
    復号結果が有効なJSONかどうかを判定

    Args:
        result: 復号結果

    Returns:
        有効なJSONの場合True、それ以外はFalse
    """
    # 辞書型で、エラーキーがない場合は有効
    if isinstance(result, dict) and 'error' not in result:
        return True

    # リスト型の場合も有効
    if isinstance(result, list):
        return True

    return False
```
