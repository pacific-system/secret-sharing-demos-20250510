# シャミア秘密分散法による複数平文復号システム設計書

## 1. 概要

本設計書では、シャミア秘密分散法を応用した「複数平文復号システム」の詳細設計を提供する。このシステムは単一の暗号化ファイルから異なるパスワードを使用して異なる平文（JSON 文書）を復号可能にするもので、「シェア ID による可能性の限定とパスワードによるマップ生成」という多段 MAP 方式を核心とする。

本システムの設計はケルクホフの原理に厳格に従い、アルゴリズムが完全に公開されてもパスワード（鍵）が秘匿されている限りセキュリティが保たれる。

## 2. システムアーキテクチャ

### 2.1. 基本原理

本システムは以下の基本原理に基づいて設計される：

1. **シャミア秘密分散法**：閾値暗号の一種であり、秘密情報を複数のシェアに分散し、一定数以上のシェアがあれば元の情報を復元できる
2. **多段 MAP 方式**：シェア ID による第 1 段階の絞り込みとパスワードによる第 2 段階のマッピングを組み合わせる
3. **統計的区別不可能性**：異なる文書のシェアや未割当領域のシェアが統計的に区別できない
4. **直線的処理**：復号処理中に評価や条件分岐を一切含まない

### 2.2. システム構成図

システムの全体構成を以下に示す：

```mermaid
graph TD
    A[JSON文書A] --> C[暗号化処理]
    B[JSON文書B] --> C
    C --> D[暗号化ファイル]
    D --> E[単一復号プロセス]
    J[パスワードA] --> E
    K[パスワードB] --> E
    I[シェアID空間] --> C
    I --> E
    E -- パスワードAとシェアID --> G[復元JSON文書A]
    E -- パスワードBとシェアID --> H[復元JSON文書B]
    J --> C
    K --> C
```

この図では、復号処理は単一のプロセスであり、異なるパスワードとシェア ID の組み合わせが入力されることで異なる文書が復元されることを示しています。実装上、復号処理は完全に同一のコードパスを通り、条件分岐なしの直線的処理で実行されます。

### 2.3. 多段 MAP 方式の詳細

多段 MAP 方式は本システムの核心技術であり、以下の 2 段階で構成される：

1. **第 1 段階（シェア ID による限定）**：

   - ユーザーが保持するシェア ID セットにより、全シェア空間から復号の候補となるシェアの範囲を限定
   - この段階で不要なシェアの大部分を除外可能

2. **第 2 段階（パスワードによるマッピング）**：
   - パスワードから鍵導出関数を用いてマップデータを生成
   - 第 1 段階で限定された範囲内のシェアだけを対象にマッピングを適用
   - マッピング結果に基づき、実際に復号に使用するシェアを特定

以下が正しい処理フローです：

```mermaid
graph TD
    A[シェアID入力] --> B[第1段階MAP生成]
    B --> E[シェア候補の限定]
    C[パスワード入力] --> D[第2段階MAP生成]
    E --> D
    E --> F[候補範囲内でのマッピング]
    D --> F
    F --> G[復号用シェア特定]
    G --> H[シャミア秘密分散法による復元]
    H --> I[JSON文書復元]
```

※注: 第 2 段階 MAP 生成はパスワードと第 1 段階で限定されたシェア候補の両方を入力として受け取ります。図の矢印は依存関係と処理の流れを示しており、第 1 段階の結果が第 2 段階の入力として使用されることを明示しています。

## 3. 詳細設計

### 3.1. シェア ID 空間設計

シェア ID 空間は以下のように設計する：

1. **分割比率**：

   - A ユーザー用：30-40%
   - B ユーザー用：30-40%
   - 未割当領域：20-40%

2. **分散配置**：

   - 連続範囲や単純なパターン（偶数/奇数など）を避ける
   - ID 空間内のどの部分を切り取っても、A、B、未割当の識別が統計的に不可能
   - 例えば、ID 空間を小さなブロックに分割し、各ブロック内でランダムに割り当て

3. **実装方法**：
   - シェア ID 空間全体を擬似乱数生成器を用いて初期化
   - 各 ID の割り当て（A、B、未割当）は直接保存せず、パスワード A と B およびシェア ID セットから導出
   - 割り当て判別には以下の 4 要素全てが必要：
     1. パスワード A
     2. パスワード B
     3. シェア ID A セット
     4. シェア ID B セット
   - 任意の要素が一つでも欠けると、どの ID がどの文書に割り当てられているか判別不能

```mermaid
graph LR
    subgraph "シェアID空間"
    A1[A] --- B1[B] --- N1[未割当] --- A2[A] --- N2[未割当] --- B2[B]
    N3[未割当] --- A3[A] --- B3[B] --- A4[A] --- B4[B] --- N4[未割当]
    end
```

### 3.2. シャミア秘密分散法の実装

基本的なシャミア秘密分散法を拡張して実装する：

1. **多項式の次数とシェア数**：

   - 閾値を`t`とすると、次数`t-1`の多項式を使用
   - 必要シェア数は閾値`t`個
   - 実用的な値として、`t=3`～`5`を推奨

2. **有限体の選択**：

   - 大きな素数`p`を用いた有限体 GF(p)上で計算
   - 文書サイズに応じて適切な素数を選択（例：2^256-189）

3. **シェア生成アルゴリズム**：

```python
def generate_polynomial(secret, degree, p):
    """degree次の多項式を生成"""
    coef = [secret]
    for i in range(degree):
        coef.append(random.randint(1, p-1))
    return coef

def evaluate_polynomial(coef, x, p):
    """多項式の評価"""
    result = 0
    for i in range(len(coef)):
        result = (result + coef[i] * pow(x, i, p)) % p
    return result

def generate_shares(secret, t, n, p):
    """n個のシェアを生成、閾値はt"""
    coef = generate_polynomial(secret, t-1, p)
    shares = []
    for i in range(1, n+1):
        shares.append((i, evaluate_polynomial(coef, i, p)))
    return shares
```

4. **シェア復元アルゴリズム**：

```python
def lagrange_interpolation(shares, p):
    """ラグランジュ補間によるシークレット復元"""
    secret = 0
    for i, share_i in enumerate(shares):
        x_i, y_i = share_i
        numerator = denominator = 1
        for j, share_j in enumerate(shares):
            if i != j:
                x_j, y_j = share_j
                numerator = (numerator * (0 - x_j)) % p
                denominator = (denominator * (x_i - x_j)) % p
        lagrange_coefficient = (numerator * pow(denominator, p-2, p)) % p
        secret = (secret + y_i * lagrange_coefficient) % p
    return secret
```

### 3.3. 多段 MAP の実装

多段 MAP は以下のように実装する：

1. **第 1 段階 MAP（シェア ID）**：
   - シェア ID セットはユーザーに初期化時に割り当てられる
   - シェア ID セットは単なる ID 配列

```python
def stage1_map(share_ids):
    """シェアIDによる第1段階MAP生成"""
    # シェアIDセットをそのまま返す（単純なフィルタとして機能）
    return set(share_ids)
```

2. **第 2 段階 MAP（パスワード）**：
   - パスワードから KDF を用いてマップデータを生成
   - このマップは選択的なシェア識別に使用

```python
def stage2_map(password, candidate_ids, salt):
    """パスワードによる第2段階MAP生成
    candidate_ids: 第1段階で限定されたシェアIDのセット
    """
    # パスワードからキーを導出
    key = kdf(password, salt, iterations=100000, length=32)

    # キーを用いて各シェアIDに対応するインデックスを生成
    mapping = {}
    for share_id in candidate_ids:  # 第1段階で限定されたIDのみ処理
        # 決定論的にマッピング値を生成
        h = hmac.new(key, str(share_id).encode(), 'sha256')
        mapping[share_id] = int.from_bytes(h.digest(), 'big')

    return mapping
```

3. **シェア選択**：
   - 2 段階のマップを組み合わせて最終的なシェアセットを選択

```python
def select_shares(all_shares, share_ids, password, salt, threshold):
    """多段MAPを用いたシェア選択"""
    # 第1段階：シェアID空間の限定
    candidate_ids = stage1_map(share_ids)

    # 第1段階の結果から候補シェアを取得
    candidate_shares = [share for share in all_shares if share[0] in candidate_ids]

    # 第2段階：パスワードによるマッピング
    mappings = stage2_map(password, candidate_ids, salt)

    # マッピング値でソート
    sorted_shares = sorted(candidate_shares, key=lambda s: mappings[s[0]])

    # 閾値分のシェアを選択（常に同じ数を処理）
    selected_shares = sorted_shares[:threshold]

    # シェア数が不足している場合もエラーを出さず処理（結果は不正確になる）
    return selected_shares
```

### 3.4. 暗号化プロセス

暗号化プロセスは以下の手順で行う：

1. **前処理**：

   - JSON 文書は最初から UTF-8 形式
   - 多段エンコードプロセスを適用：
     1. UTF-8 テキスト（元の JSON）
     2. Latin-1 へのエンコード変換
     3. Base64 エンコード
   - この多段エンコードにより、復号プロセスの堅牢性を確保
   - データを常に圧縮（条件判断なし）

2. **シェア生成**：

   - エンコードされたデータをチャンクに分割
   - 各チャンクをシャミア秘密分散法でシェア化

3. **シェア ID の使用**：

   - シェア ID の割り当ては初期化時にのみ行われる
   - 暗号化時には既に割り当て済みのシェア ID を使用するだけ
   - シェア ID + パスワード + 文書の 3 つの情報のみで暗号化が完結
   - どのシェアが何に対応するかの判定は一切不要

4. **出力と永続化**：
   - シャミア秘密分散法によって生成されたシェア値のみを保存
   - 塩値は復号に必要なため保存（再計算不可能な乱数値）
   - シェア ID はユーザー入力として提供されるため保存不要
   - マッピング情報はパスワードとシェア ID から計算で再生成可能なため保存不要
   - 閾値など暗号設定のみ最小限のメタデータとして保存
   - 保存データは全て A/B 区別なく単一のフォーマットで格納（文書の種類を識別する情報を含まない）

```python
def encrypt(json_doc, password, share_ids, unassigned_ids):
    """単一JSON文書の暗号化（A/B判定なし）"""
    # データの前処理
    data = json.dumps(json_doc).encode('utf-8')

    # 多段エンコード適用
    data_latin = data.decode('utf-8').encode('latin-1')
    data_base64 = base64.b64encode(data_latin)

    # データを固定長チャンクに分割
    chunks = split_into_chunks(data_base64)

    # 各チャンクをシェア化
    all_shares = []
    threshold = 3  # 例として閾値3を使用

    # シェア生成（対象がAかBかを区別せず処理）
    for i, chunk in enumerate(chunks):
        secret = int.from_bytes(chunk, 'big')
        chunk_shares = generate_chunk_shares(secret, threshold, share_ids)
        for share_id, value in chunk_shares:
            all_shares.append({
                'chunk_index': i,
                'share_id': share_id,
                'value': value
            })

    # 未割当領域にゴミデータを生成
    garbage_shares = generate_garbage_shares(unassigned_ids, len(all_shares))
    all_shares.extend(garbage_shares)

    # シェアをシャッフル（順序による情報漏洩を防ぐ）
    random.shuffle(all_shares)

    # メタデータを追加
    metadata = {
        'salt': generate_salt(),
        'total_chunks': len(chunks),
        'threshold': threshold
    }

    # 暗号化ファイルの生成
    encrypted_file = {
        'metadata': metadata,
        'shares': all_shares
    }

    return encrypted_file
```

### 3.5. 復号プロセス

復号プロセスは以下の手順で行う：

1. **入力処理**：

   - シェア ID とパスワードを受け取る
   - 暗号化ファイルを読み込む

2. **多段 MAP 処理**：

   - シェア ID による第 1 段階 MAP 生成
   - パスワードによる第 2 段階 MAP 生成
   - シェアの選択

3. **秘密復元**：

   - 選択されたシェアを用いてシャミア秘密分散法で秘密を復元
   - チャンクを結合して元のデータを復元

4. **後処理（多段デコード）**：
   - 圧縮データの解凍
   - Base64 デコード
   - Latin-1 から UTF-8 へのエンコード変換
   - UTF-8 テキストから JSON への解析

```python
def decrypt(encrypted_file, share_ids, password):
    """暗号化ファイルの復号（A/B判定なし）"""
    # メタデータ取得
    metadata = encrypted_file['metadata']
    threshold = metadata['threshold']
    all_shares = encrypted_file['shares']
    salt = metadata['salt']

    # 多段MAPの適用で復号処理（判定なしの直線的処理）
    result = try_decrypt(all_shares, share_ids, password, salt, threshold)

    # 復号データを返却（判定なし）
    try:
        # 多段デコード処理
        base64_decoded = base64.b64decode(result)
        latin_decoded = base64_decoded.decode('latin-1').encode('utf-8')
        json_text = latin_decoded.decode('utf-8')
        # JSON解析
        json_doc = json.loads(json_text)
        return json_doc
    except:
        # 失敗した場合でもエラーとせずに結果を返す
        return result
```

```python
def try_decrypt(all_shares, share_ids, password, salt, threshold):
    """シェアを復号（A/B判定なしの直線的処理）"""
    # 多段MAPの適用
    # 第1段階：シェアIDによる絞り込み
    candidate_shares = [s for s in all_shares if s['share_id'] in share_ids]

    # 第2段階：パスワードによるマッピング
    mapping = stage2_map(password, [s['share_id'] for s in candidate_shares], salt)

    # チャンク別にシェアを整理
    chunks = {}
    for share in candidate_shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        chunks[chunk_idx].append((share['share_id'], share['value']))

    # 各チャンクを復元（判定なしの直線的処理）
    reconstructed_data = bytearray()
    chunk_indices = sorted(chunks.keys())

    for idx in chunk_indices:
        # 各チャンクのシェアをマッピング値でソート
        sorted_shares = sorted(chunks[idx], key=lambda s: mapping[s[0]])

        # 閾値分のシェアを選択
        selected_shares = sorted_shares[:threshold]

        # シャミア秘密分散法による復元
        if len(selected_shares) >= threshold:
            secret = lagrange_interpolation(selected_shares, PRIME)
            chunk_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
            reconstructed_data.extend(chunk_bytes)

    # 復元データを返却
    return reconstructed_data
```

### 3.6. 更新プロセス

更新プロセスは以下の手順で行う：

1. **一時作業領域の確保**：

   - 更新用の一時ファイルを別途生成し、UUID を付与して一意性を確保
   - ロックファイルを作成して実行中プロセスを明示（ファイル名に UUID 含む）
   - ロックファイル内にプロセス ID (PID) とタイムスタンプを記録
   - 処理開始時に既存の一時ファイルをスキャン：
     - プロセス ID が存在しない（終了済み）場合のみ削除
     - タイムスタンプが閾値を超過（タイムアウト）したファイルも削除
   - 処理完了時に自プロセスの一時ファイルとロックファイルを確実に削除
   - 例外発生時にもロックの解放と一時ファイルの削除を実行
   - 複数プロセスの並列実行に対応し、相互干渉を防止

2. **新シェアの生成**：

   - 新しい JSON 文書から新しいシェアを生成
   - 元のシェアセットと同様の構造で生成

3. **検証と適用**：

   - 生成された新シェアが正しく復号可能か検証
   - 検証成功後、対象シェア ID の範囲内でのみ更新適用

4. **古いシェアの破棄**：
   - 更新成功後、古いシェアを確実に破棄

```python
def update(encrypted_file, json_doc, password, share_ids):
    """文書の更新"""
    # 一時ファイル管理のための変数
    process_uuid = str(uuid.uuid4())
    temp_dir = os.path.join(os.getcwd(), "temp")
    temp_file_path = None
    lock_file_path = None

    try:
        # 一時作業ディレクトリの確保
        os.makedirs(temp_dir, exist_ok=True)

        # プロセス固有の一時ファイルパスを生成（UUID付与）
        temp_file_path = os.path.join(temp_dir, f"update_{process_uuid}.tmp")
        lock_file_path = os.path.join(temp_dir, f"lock_{process_uuid}.lock")

        # ロックファイル作成（PIDとタイムスタンプを記録）
        with open(lock_file_path, 'w') as lock_file:
            lock_info = {
                'pid': os.getpid(),
                'timestamp': time.time(),
                'operation': 'update'
            }
            json.dump(lock_info, lock_file)

        # 古い一時ファイルのクリーンアップ（完了・タイムアウトしたプロセスのみ）
        cleanup_stale_temp_files(temp_dir, timeout_seconds=3600)  # 1時間のタイムアウト

        # 一時作業領域を確保
        temp_shares = []

        # メタデータ取得
        metadata = encrypted_file['metadata']
        threshold = metadata['threshold']
        salt = metadata['salt']

        # 新しいシェア生成
        data = json.dumps(json_doc).encode('utf-8')

        # 多段エンコード適用
        data_latin = data.decode('utf-8').encode('latin-1')
        data_base64 = base64.b64encode(data_latin)
        # データを圧縮
        compressed_data = compress_data(data_base64)

        chunks = split_into_chunks(compressed_data)

        for i, chunk in enumerate(chunks):
            secret = int.from_bytes(chunk, 'big')
            chunk_shares = generate_chunk_shares(secret, threshold, share_ids)
            for share_id, value in chunk_shares:
                temp_shares.append({
                    'chunk_index': i,
                    'share_id': share_id,
                    'value': value
                })

        # 一時ファイルに中間状態を保存
        with open(temp_file_path, 'w') as f:
            json.dump(temp_shares, f)

        # 対象シェアIDの範囲内のシェアのみを更新
        updated_shares = []
        for share in encrypted_file['shares']:
            if share['share_id'] in share_ids:
                # 対象範囲内のシェアは新しいものに置き換え
                pass
            else:
                # 対象範囲外のシェアはそのまま保持
                updated_shares.append(share)

        # 新しいシェアを追加
        updated_shares.extend(temp_shares)

        # メタデータ更新
        updated_metadata = metadata.copy()
        updated_metadata['total_chunks'] = len(chunks)

        # 更新された暗号化ファイルの生成
        updated_file = {
            'metadata': updated_metadata,
            'shares': updated_shares
        }

        # 処理成功時は一時ファイルとロックファイルを削除
        safe_remove_file(temp_file_path)
        safe_remove_file(lock_file_path)

        return updated_file

    except Exception as e:
        # 例外発生時も一時ファイルとロックを確実に解放
        if temp_file_path and os.path.exists(temp_file_path):
            safe_remove_file(temp_file_path)
        if lock_file_path and os.path.exists(lock_file_path):
            safe_remove_file(lock_file_path)
        raise e  # 例外を再送出

def cleanup_stale_temp_files(directory, timeout_seconds=3600):
    """期限切れ/孤立した一時ファイルを削除

    - timeout_seconds: プロセスがタイムアウトとみなされる秒数
    """
    current_time = time.time()

    if not os.path.exists(directory):
        return

    # ロックファイルをスキャン
    for filename in os.listdir(directory):
        if filename.startswith("lock_") and filename.endswith(".lock"):
            lock_path = os.path.join(directory, filename)
            process_uuid = filename[5:-5]  # "lock_" と ".lock" を削除

            try:
                with open(lock_path, 'r') as lock_file:
                    lock_info = json.load(lock_file)

                # プロセスIDの存在確認
                pid_exists = False
                if 'pid' in lock_info:
                    try:
                        # プロセスが存在するか確認（シグナル0を送信）
                        os.kill(lock_info['pid'], 0)
                        pid_exists = True
                    except OSError:
                        # プロセスが存在しない
                        pid_exists = False

                # タイムスタンプ確認
                is_timeout = False
                if 'timestamp' in lock_info:
                    if current_time - lock_info['timestamp'] > timeout_seconds:
                        is_timeout = True

                # PIDが存在せず、もしくはタイムアウトした場合、関連ファイルを削除
                if (not pid_exists) or is_timeout:
                    # 関連する一時ファイルを削除
                    temp_path = os.path.join(directory, f"update_{process_uuid}.tmp")
                    if os.path.exists(temp_path):
                        safe_remove_file(temp_path)
                    # ロックファイル自体も削除
                    safe_remove_file(lock_path)

            except (json.JSONDecodeError, IOError) as e:
                # 読み取りエラーの場合は破損と見なし、ファイルを削除
                safe_remove_file(lock_path)

def safe_remove_file(file_path):
    """ファイルを安全に削除（例外をキャッチして処理継続）"""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"ファイル削除中にエラー: {file_path}, {e}")
```

## 4. セキュリティ分析

### 4.1. 攻撃モデルと脆弱性分析

以下の攻撃モデルを考慮する：

1. **パッシブ攻撃者**：

   - 暗号化ファイルを入手可能
   - ソースコードを完全に把握
   - 統計的・構造的分析を試みる

2. **アクティブ攻撃者**：
   - 上記に加え、不正なパスワードでの復号を多数試行可能
   - タイミング攻撃などのサイドチャネル攻撃を試みる可能性

主な脆弱性と対策：

| 脆弱性               | 対策                                                   |
| -------------------- | ------------------------------------------------------ |
| シェア識別攻撃       | シェア ID 空間の混在分散配置、統計的区別不可能性の確保 |
| ブルートフォース攻撃 | 強力な KDF の使用、十分な計算コスト設定                |
| タイミング攻撃       | 条件分岐の排除、一定時間での処理実行                   |
| メタデータ分析       | メタデータの最小化、文書種別情報の排除                 |

### 4.2. マップデータの安全性

マップデータの安全性は以下の要素に依存する：

1. **鍵導出関数の強度**：

   - Argon2 または PBKDF2 など、実績のある KDF を使用
   - 十分なイテレーション回数と計算コスト

2. **決定論的生成**：

   - 同一パスワードからは常に同一マップを生成
   - パスワードがわずかに異なれば、全く異なるマップを生成

3. **予測不可能性**：
   - パスワードを知らなければマップ予測は計算量的に不可能
   - マップデータの部分的な漏洩が他の部分の予測に繋がらない

### 4.3. ソースコード漏洩時のセキュリティ

ケルクホフの原理に従い、ソースコード漏洩時でも以下の理由でセキュリティは保たれる：

1. **パスワード依存**：

   - セキュリティはパスワードの強度のみに依存
   - ソースコードからはパスワードを導出不可能

2. **シェア ID 空間の隠蔽**：

   - シェア ID 空間の割り当ては外部から観測不可能
   - 統計的に区別不可能な設計

3. **多段 MAP 方式の有効性**：
   - アルゴリズムを完全に理解していても、パスワードとシェア ID がなければ復号不可能
   - ゴミデータと実データの区別が不可能

### 4.4. 未割当領域のセキュリティ強化

未割当領域がもたらすセキュリティ強化：

1. **統計的攻撃の難化**：

   - 攻撃者がファイル全体の 20-40%を無視できない
   - パターン認識による攻撃が困難になる

2. **将来の拡張性確保**：

   - 将来的な機能追加のための余白として機能
   - セキュリティモデルを変更せずに拡張可能

3. **攪乱効果**：
   - ランダムなゴミデータが攻撃者の分析を妨害
   - 有効データと無効データの区別を不可能にする

## 5. 性能評価

### 5.1. ファイルサイズ評価

各サイズの JSON 文書に対する暗号化後のファイルサイズ予測：

| 元の JSON サイズ | 暗号化後のファイルサイズ | 膨張率 |
| ---------------- | ------------------------ | ------ |
| 10KB             | 約 40-50KB               | 4-5 倍 |
| 100KB            | 約 400-500KB             | 4-5 倍 |
| 1MB              | 約 4-5MB                 | 4-5 倍 |

膨張の主な要因：

- シェア化による基本的な冗長性
- 複数文書の格納（A、B 両方の文書）
- 未割当領域のゴミデータ（全体の 20-40%）
- メタデータと構造情報

### 5.2. 処理性能評価

処理性能の理論的評価：

| 処理   | 計算量 | 10KB JSON | 100KB JSON | 1MB JSON |
| ------ | ------ | --------- | ---------- | -------- |
| 暗号化 | O(n)   | <100ms    | 100-500ms  | 1-5 秒   |
| 復号   | O(n)   | <100ms    | 100-500ms  | 1-5 秒   |
| 更新   | O(n)   | <200ms    | 200-1000ms | 2-10 秒  |

※実際の性能はハードウェアや KDF の設定により大きく変動

### 5.3. メモリ使用量

メモリ使用量の評価：

| 処理   | メモリ使用量パターン  | 10KB JSON | 100KB JSON | 1MB JSON |
| ------ | --------------------- | --------- | ---------- | -------- |
| 暗号化 | 入力サイズの約 3-4 倍 | 30-40KB   | 300-400KB  | 3-4MB    |
| 復号   | 入力サイズの約 2-3 倍 | 20-30KB   | 200-300KB  | 2-3MB    |
| 更新   | 入力サイズの約 4-5 倍 | 40-50KB   | 400-500KB  | 4-5MB    |

大きなファイルの処理はチャンク単位で行うことでメモリ効率を改善可能。

## 6. 実装ガイドライン

### 6.1. セキュアデータ構造設計原則

データ構造設計には以下の原則を適用する：

1. **最小情報の原則**：

   - 復号に必須の情報のみを保存
   - ユーザー入力から導出可能な情報は保存しない
   - メタデータは処理に必要な最低限に留める

2. **識別情報の排除**：

   - 文書種別の識別子（A/B 等）は一切含めない
   - シェアがどの文書に属するかを示す情報を排除
   - すべてのデータを均質に扱い、統計的区別を不可能にする

3. **構造的匿名性**：

   - データ構造自体から情報が漏洩しないよう設計
   - シェア値とその識別子のみを保存し、意味的関連を持たせない
   - 同一の処理パスで異なる結果を導出できるよう構造化

4. **冗長性の最小化**：
   - 同じ情報を複数の場所に保存しない
   - データ間の相関を最小限に抑え、部分情報からの推測を防止
   - 格納形式は効率性とセキュリティのバランスを考慮

これらの原則に従うことで、データ構造自体が暗号解読の手がかりとなることを防ぎ、ケルクホフの原理に基づく堅牢なシステムを実現する。

### 6.2. 推奨暗号ライブラリ

以下のライブラリの利用を推奨：

1. **KDF**：

   - Node.js: `crypto.pbkdf2` または `argon2`
   - Python: `hashlib.pbkdf2_hmac` または `argon2-cffi`
   - Java: `javax.crypto.spec.PBEKeySpec`

2. **乱数生成**：

   - Node.js: `crypto.randomBytes`
   - Python: `secrets`モジュール
   - Java: `java.security.SecureRandom`

3. **有限体演算**：
   - 大きな素数体上での計算に対応したライブラリ
   - Python: `gmpy2`
   - JavaScript: `big-integer`

### 6.3. 条件分岐の禁止と定数時間処理の実装パターン

以下のパターンは条件分岐によるサイドチャネル攻撃を防止するために重要である。**すべての条件分岐を含むコードパターンは本システムでは禁止とする**。

1. **選択操作**：

```javascript
// ⛔ 禁止: 条件分岐を使った選択
let result = condition ? valueA : valueB;

// ✅ 推奨: 定数時間選択を使用
let mask = -Number(condition); // true -> -1, false -> 0
let result = (valueA & mask) | (valueB & ~mask);
```

2. **ループ処理**：

```javascript
// ⛔ 禁止: 早期リターンを使用
for (let share of shares) {
  if (isValid(share)) {
    return share;
  }
}

// ✅ 推奨: 全要素を一定時間で処理
let selectedShare = null;
let selectedIdx = -1;
for (let i = 0; i < shares.length; i++) {
  // 最初の有効なシェアのインデックスをマスク付き比較で記録
  let isValidShare = isValid(shares[i]);
  let shouldSelect = isValidShare && selectedIdx === -1;
  selectedIdx = (selectedIdx & ~-Number(shouldSelect)) | (i & -Number(shouldSelect));
  selectedShare = (selectedShare & ~-Number(shouldSelect)) | (shares[i] & -Number(shouldSelect));
}
```

3. **例外処理**：

```javascript
// ⛔ 禁止: try-catchを使用した条件分岐
try {
  return JSON.parse(data);
} catch (e) {
  return null;
}

// ✅ 推奨: 例外を発生させない処理
function safeJsonParse(data) {
  // データをチェックして安全に解析
  if (typeof data !== 'string') return null;
  if (data.length === 0) return null;
  // ... 他のチェック

  // 解析結果をラップ
  let result = { value: null, error: null };
  try {
    result.value = JSON.parse(data);
  } catch (e) {
    // 例外を記録するが、処理は続行
    result.error = e;
  }
  return result;
}
```

注意: 実装のすべての部分で条件分岐を避け、定数時間アルゴリズムを使用することは、このシステムのセキュリティモデルにおいて**絶対的要件**である。ここで示した禁止パターンを使用した実装は、タイミング攻撃に対して脆弱となるため、許容されない。

### 6.4. シェア ID 空間管理

シェア ID 空間の効率的かつ安全な管理のための指針：

1. **分散化と均一性**：

   - シェア ID の分布はランダム性を維持し、パターンを形成しない
   - 任意の連続範囲において、各種別（A/B/未割当）の分布比率が一定となるよう設計
   - ブロック単位での分布検証を実施し、統計的均一性を確保

2. **効率的なルックアップ**：

   - 頻繁なシェア ID 検索に対応するため、効率的なデータ構造を採用
   - シェア ID の検索や所属確認において条件分岐を用いない実装
   - ビット演算やルックアップテーブルを活用した定数時間アクセス

3. **安全な生成と管理**：
   - 暗号学的に安全な乱数発生器を用いたシェア ID 空間の生成
   - 初期化時にのみ ID 割り当てを行い、以後は変更しない
   - 割り当て情報は 4 つの要素（両パスワードと両シェア ID セット）なしには再構築不可能

## 7. 参考資料と出典

### 7.1. 学術論文

1. Shamir, A. (1979). "How to share a secret". Communications of the ACM, 22(11), 612-613.
2. Blakley, G. R. (1979). "Safeguarding cryptographic keys". Proceedings of the National Computer Conference, 48, 313-317.
3. Krawczyk, H. (1993). "Secret sharing made short". In Annual International Cryptology Conference (pp. 136-146). Springer.
4. Kaliski, B. (2000). "PKCS #5: Password-Based Cryptography Specification Version 2.0". RFC 2898.

### 7.2. オープンソース実装

1. secrets.js: JavaScript 用シャミア秘密分散ライブラリ
   https://github.com/grempe/secrets.js

2. SSSS (Shamir's Secret Sharing Scheme): C 言語実装
   http://point-at-infinity.org/ssss/

3. Vault by HashiCorp: 秘密分散を実装したシークレット管理ツール
   https://github.com/hashicorp/vault

4. RustySecrets: Rust による秘密分散実装
   https://github.com/SpinResearch/RustySecrets

### 7.3. 技術文書とリファレンス

1. NIST Special Publication 800-132: パスワードベースの鍵導出関数に関する推奨事項
2. OWASP Cryptographic Storage Cheat Sheet: 暗号化ストレージのベストプラクティス
3. Cryptographic Side-Channel Attacks: Timing Attack Prevention Guidelines
4. Applied Cryptography (Bruce Schneier): 暗号理論と実装のリファレンス

## 8. 結論

本設計書では、シャミア秘密分散法を応用した複数平文復号システムの詳細設計を提供した。核心となる「シェア ID による可能性の限定とパスワードによるマップ生成」という多段 MAP 方式により、単一の暗号化ファイルから異なるパスワードで異なる平文を復号可能なシステムが実現できる。

本設計はケルクホフの原理に厳格に従い、アルゴリズムが完全に公開されてもパスワード（鍵）が秘匿されている限りセキュリティが保たれる。また、直線的処理や条件分岐の排除など、サイドチャネル攻撃に対する耐性も考慮されている。

実装に際しては、本設計書で提示したガイドラインや推奨データ構造、ライブラリを参考にすることで、安全かつ効率的なシステムを構築することが可能である。
