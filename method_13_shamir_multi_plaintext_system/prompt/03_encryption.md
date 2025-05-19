## データの暗号化

暗号化プロセスでは、JSON 文書をシャミア秘密分散法を使用して暗号化します。この部分はシステムの核心となるコンポーネントで、統計的区別不可能性や定数時間処理といった重要なセキュリティ要件を満たす必要があります。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `02_architecture.md`: 多段 MAP 方式の詳細
- `03_detailed_design.md`: シャミア秘密分散法の実装と多段 MAP の詳細
- `04_implementation.md`: 4.1 節「暗号化プロセス」の詳細手順
- `05_security.md`: セキュリティ要件と攻撃モデル
- `07_guidelines.md`: 7.3 節「条件分岐の禁止と定数時間処理の実装パターン」

### 1. シャミア秘密分散法の実装

```python
def generate_polynomial(secret: mpz, degree: int, prime: mpz) -> List[mpz]:
    """
    シャミア秘密分散法で使用する多項式を生成

    Args:
        secret: 秘密値
        degree: 多項式の次数（閾値t-1）
        prime: 有限体の素数

    Returns:
        多項式の係数リスト
    """
    # 最初の係数に秘密値を設定
    coef = [secret]

    # 残りの係数をランダムに生成（1からp-1までの範囲）
    for i in range(degree):
        random_coef = mpz(secrets.randbelow(int(prime - 1))) + 1
        coef.append(random_coef)

    return coef


def evaluate_polynomial(coef: List[mpz], x: mpz, prime: mpz) -> mpz:
    """
    多項式を評価して点(x, y)のy値を計算

    Args:
        coef: 多項式の係数リスト
        x: x座標
        prime: 有限体の素数

    Returns:
        y = P(x) mod prime
    """
    result = mpz(0)

    # 定数時間処理のため、実質的にはループ展開するのが理想的
    # しかし可変サイズの係数リストに対応するため、ループで実装
    for i in range(len(coef)):
        term = coef[i] * gmpy2.powmod(x, i, prime)
        result = (result + term) % prime

    return result


def generate_shares(secret: mpz, threshold: int, share_ids: List[int], prime: mpz) -> List[Tuple[int, mpz]]:
    """
    シークレットからシェアを生成

    Args:
        secret: 秘密値
        threshold: 閾値（復元に必要な最小シェア数）
        share_ids: シェアのID（x座標）リスト
        prime: 有限体の素数

    Returns:
        (シェアID, シェア値)のタプルリスト
    """
    # 閾値が1のときは自明なケース（多項式は定数項のみ）
    if threshold < 2:
        return [(x, secret) for x in share_ids]

    # 閾値tに対して次数(t-1)の多項式を生成
    poly_degree = threshold - 1
    coef = generate_polynomial(secret, poly_degree, prime)

    # 各シェアIDに対して多項式を評価
    shares = []
    for id in share_ids:
        x = mpz(id)
        y = evaluate_polynomial(coef, x, prime)
        shares.append((id, y))

    return shares


def lagrange_interpolation(shares: List[Tuple[int, mpz]], prime: mpz) -> mpz:
    """
    ラグランジュ補間法を使用して秘密を復元

    Args:
        shares: (シェアID, シェア値)のタプルリスト
        prime: 有限体の素数

    Returns:
        復元された秘密値
    """
    # x=0での多項式の値を計算
    secret = mpz(0)

    # 各シェアのラグランジュ係数を計算
    for i, (x_i, y_i) in enumerate(shares):
        x_i = mpz(x_i)
        numerator = mpz(1)    # 分子
        denominator = mpz(1)  # 分母

        # ラグランジュ基底多項式の計算
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                x_j = mpz(x_j)
                numerator = (numerator * (0 - x_j)) % prime
                denominator = (denominator * (x_i - x_j)) % prime

        # モジュラ逆数を計算（拡張ユークリッド互除法）
        # a * x ≡ 1 (mod p) となるxを計算
        denominator_inv = gmpy2.invert(denominator, prime)

        # ラグランジュ係数
        lagrange_coef = (numerator * denominator_inv) % prime

        # 秘密値に加算
        term = (y_i * lagrange_coef) % prime
        secret = (secret + term) % prime

    return secret
```

### 2. 多段エンコードと文書前処理

```python
def preprocess_json_document(json_doc: Any) -> bytes:
    """
    JSON文書を暗号化のために前処理する

    Args:
        json_doc: 暗号化するJSON文書（辞書またはリスト）

    Returns:
        前処理済みのバイトデータ
    """
    # JSONをUTF-8形式の文字列に変換（余分な空白を除去）
    json_str = json.dumps(json_doc, ensure_ascii=False, separators=(',', ':'))
    utf8_bytes = json_str.encode('utf-8')

    # 圧縮（条件判断なし、常に最大レベルで圧縮）
    compressed_data = zlib.compress(utf8_bytes, level=9)

    # URL安全なBase64エンコード
    base64_data = base64.urlsafe_b64encode(compressed_data)

    return base64_data


def split_into_chunks(data: bytes, chunk_size: int = ShamirConstants.CHUNK_SIZE) -> List[bytes]:
    """
    データを一定サイズのチャンクに分割

    Args:
        data: 分割対象のバイトデータ
        chunk_size: チャンクサイズ（バイト単位）

    Returns:
        バイトチャンクのリスト
    """
    chunks = []

    # データをチャンクサイズごとに分割
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]

        # 最後のチャンクが不完全な場合はパディング
        if len(chunk) < chunk_size:
            # ゼロパディング（サイドチャネル攻撃防止のため常に同じサイズに）
            chunk = chunk.ljust(chunk_size, b'\0')

        chunks.append(chunk)

    return chunks
```

### 3. 多段 MAP の実装

```python
def derive_key(password: str, salt: bytes, iterations: int = 310000, length: int = 32) -> bytes:
    """
    パスワードから鍵を導出（Argon2idまたはPBKDF2）

    Args:
        password: パスワード
        salt: ソルト値
        iterations: イテレーション回数（PBKDF2の場合）
        length: 出力キー長

    Returns:
        導出された鍵
    """
    try:
        # 可能であればArgon2idを使用（より強力）
        kdf = Argon2(
            length=length,
            salt=salt,
            time_cost=ShamirConstants.ARGON2_TIME_COST,
            memory_cost=ShamirConstants.ARGON2_MEMORY_COST,
            parallelism=ShamirConstants.ARGON2_PARALLELISM,
            type=cryptography.hazmat.primitives.kdf.argon2.Argon2Type.ID,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
    except:
        # フォールバックとしてPBKDF2-HMAC-SHA256を使用
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))

    return key


def stage1_map(partition_key: str, all_share_ids: List[int]) -> List[int]:
    """
    第1段階MAP：パーティションマップキーから候補シェアIDを取得

    Args:
        partition_key: パーティションマップキー
        all_share_ids: 全シェアIDリスト

    Returns:
        選択されたシェアIDリスト
    """
    # パーティションマップキーからシード値を生成
    key_bytes = partition_key.encode('ascii')
    seed = int.from_bytes(hashlib.sha256(key_bytes).digest(), 'big')

    # シードから擬似乱数生成器を初期化
    import random
    rng = random.Random(seed)

    # シェアIDをシャッフルし、決定論的にサブセットを選択
    # パーティションマップキーが同じなら同じIDセットが選ばれる
    shuffled_ids = list(all_share_ids)  # コピーを作成
    rng.shuffle(shuffled_ids)

    # 全シェアの約35%を選択（パーティションのサイズに近い値）
    selected_count = int(len(all_share_ids) * ShamirConstants.RATIO_A)
    selected_ids = shuffled_ids[:selected_count]

    return selected_ids


def stage2_map(password: str, candidate_ids: List[int], salt: bytes) -> Dict[int, int]:
    """
    第2段階MAP：パスワードからシェアマッピングを生成

    Args:
        password: パスワード
        candidate_ids: 候補シェアID（第1段階で選択されたID）
        salt: ソルト値

    Returns:
        {シェアID: マッピング値}の辞書
    """
    # パスワードからキーを導出
    key = derive_key(password, salt)

    # 各シェアIDに対してマッピング値を生成
    mapping = {}
    for share_id in candidate_ids:
        # HMAC-SHA256でマッピング値を決定論的に生成
        h = hmac.new(key, str(share_id).encode(), 'sha256')
        mapping_value = int.from_bytes(h.digest(), 'big')
        mapping[share_id] = mapping_value

    return mapping


def select_shares_for_encryption(partition_key: str, password: str, all_share_ids: List[int],
                                 salt: bytes, threshold: int) -> List[int]:
    """
    暗号化に使用するシェアIDを選択

    Args:
        partition_key: パーティションマップキー
        password: パスワード
        all_share_ids: 全シェアIDリスト
        salt: ソルト値
        threshold: 閾値

    Returns:
        暗号化に使用するシェアIDリスト
    """
    # 第1段階：パーティションマップキーによる候補選択
    candidate_ids = stage1_map(partition_key, all_share_ids)

    # 第2段階：パスワードによるマッピング
    mappings = stage2_map(password, candidate_ids, salt)

    # マッピング値でソート
    sorted_ids = sorted(candidate_ids, key=lambda id: mappings[id])

    # 閾値の3倍のシェアを選択（冗長性のため）
    # 最低でも閾値の数は必要
    selection_count = min(threshold * 3, len(sorted_ids))
    selection_count = max(selection_count, threshold)

    selected_ids = sorted_ids[:selection_count]
    return selected_ids
```

### 4. 暗号化プロセス

```python
def generate_garbage_shares(unassigned_ids: List[int], chunk_count: int,
                           threshold: int, prime: mpz) -> List[Dict[str, Any]]:
    """
    未割当領域用のゴミシェアを生成

    Args:
        unassigned_ids: 未割当シェアID
        chunk_count: 生成するチャンク数
        threshold: 閾値
        prime: 有限体の素数

    Returns:
        ゴミシェアのリスト
    """
    garbage_shares = []

    # 各チャンクに対してゴミシェアを生成
    for chunk_idx in range(chunk_count):
        # 各IDに対して乱数値を生成
        for id in unassigned_ids:
            # 完全なランダム値（実際のシェアと統計的に区別不可能）
            value = mpz(secrets.randbelow(int(prime - 1))) + 1

            # シェアオブジェクトを作成
            garbage_share = {
                'chunk_index': chunk_idx,
                'share_id': id,
                'value': str(value)  # 文字列として保存
            }

            garbage_shares.append(garbage_share)

    return garbage_shares


def encrypt_json_document(json_doc: Any, password: str, partition_key: str,
                         all_share_ids: List[int], threshold: int = ShamirConstants.DEFAULT_THRESHOLD) -> Dict[str, Any]:
    """
    JSON文書を暗号化

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を暗号化します。
    ただし、暗号化ファイル自体は将来的に複数文書（AとB）のシェアを含むように設計されています。

    Args:
        json_doc: 暗号化するJSON文書
        password: 暗号化パスワード
        partition_key: パーティションマップキー（AまたはBのいずれか）
        all_share_ids: 全シェアIDリスト（パーティションマネージャーから取得）
        threshold: 閾値

    Returns:
        暗号化されたファイルデータ
    """
    # ソルト値を生成
    salt = secrets.token_bytes(16)

    # JSONを前処理
    preprocessed_data = preprocess_json_document(json_doc)

    # チャンクに分割
    chunks = split_into_chunks(preprocessed_data)

    # 使用するシェアIDを選択
    selected_share_ids = select_shares_for_encryption(
        partition_key, password, all_share_ids, salt, threshold
    )

    # 各チャンクをシェア化
    all_shares = []
    for chunk_idx, chunk in enumerate(chunks):
        # チャンクをint値に変換
        secret = mpz(int.from_bytes(chunk, 'big'))

        # シェア生成
        chunk_shares = generate_shares(
            secret, threshold, selected_share_ids, ShamirConstants.PRIME
        )

        # シェアをフォーマット
        for share_id, value in chunk_shares:
            all_shares.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': str(value)  # 文字列として保存
            })

    # メタデータを作成
    metadata = {
        'salt': base64.urlsafe_b64encode(salt).decode('ascii'),
        'total_chunks': len(chunks),
        'threshold': threshold
    }

    # 暗号化ファイルフォーマット
    encrypted_file = {
        'metadata': metadata,
        'shares': all_shares
    }

    return encrypted_file


def save_encrypted_file(encrypted_file: Dict[str, Any], output_path: str) -> None:
    """
    暗号化ファイルをディスクに保存

    Args:
        encrypted_file: 暗号化ファイルデータ
        output_path: 出力先のファイルパス
    """
    with open(output_path, 'w') as f:
        json.dump(encrypted_file, f)
```
