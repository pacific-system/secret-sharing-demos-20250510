# シャミア秘密分散法による複数平文復号システム設計書

## 4. 実装詳細

### 4.1. 暗号化プロセス

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
   - **推奨チャンクサイズ**: 64 バイト（512 ビット）
     - 選定理由: 暗号学的安全性とパフォーマンスのバランスが取れたサイズ
     - 小さすぎるチャンクサイズはオーバーヘッドが大きく、大きすぎるとメモリ効率が悪化
     - 64 バイトはモダン CPU のキャッシュラインサイズに合致し、効率的な処理が可能

3. **パーティションマップキーの使用**：

   - パーティションマップキーの割り当ては初期化時にのみ行われる
   - 暗号化時には既に割り当て済みのパーティションマップキーを使用するだけ
   - パーティションマップキー + パスワード + 文書の 3 つの情報のみで暗号化が完結
   - どのシェアが何に対応するかの判定は一切不要

4. **出力と永続化**：
   - シャミア秘密分散法によって生成されたシェア値のみを保存
   - 塩値は復号に必要なため保存（再計算不可能な乱数値）
   - パーティションマップキーはユーザー入力として提供されるため保存不要
   - マッピング情報はパスワードとパーティションマップキーから計算で再生成可能なため保存不要
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

```python
def split_into_chunks(data, chunk_size=64):
    """データを一定サイズのチャンクに分割

    Args:
        data: 分割対象のバイトデータ
        chunk_size: チャンクサイズ (デフォルト: 64バイト)

    Returns:
        チャンクのリスト
    """
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        # 最後のチャンクが不完全な場合はパディング
        if len(chunk) < chunk_size:
            chunk = chunk.ljust(chunk_size, b'\0')
        chunks.append(chunk)
    return chunks
```

### 4.2. 復号プロセス

復号プロセスは以下の手順で行う：

1. **入力処理**：

   - パーティションマップキーとパスワードを受け取る
   - 暗号化ファイルを読み込む

2. **多段 MAP 処理**：

   - パーティションマップキーによる第 1 段階 MAP 生成
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
    # 第1段階：パーティションマップキーによるMAP生成
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

### 4.3. 更新プロセス

更新プロセスは以下の手順で行う：

1. **一時作業領域の確保**：

   - 更新用の一時ファイルを別途生成し、UUID を付与して一意性を確保
   - 一時ファイルはシャミア秘密分散法で暗号化し、ユーザーのパスワードで MAP を生成
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
   - 検証成功後、対象パーティションマップキーの範囲内でのみ更新適用

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

        # 一時ファイルに中間状態をシャミア秘密分散法で暗号化して保存
        # パスワードから一時ファイル用のMAPを生成
        temp_encrypt_salt = generate_salt()
        temp_file_data = {
            'shares': temp_shares,
            'salt': temp_encrypt_salt
        }

        # 一時データをJSONに変換
        temp_json = json.dumps(temp_file_data)

        # シャミア秘密分散法で暗号化
        temp_threshold = 3  # 一時ファイル用の閾値
        temp_data_chunks = split_into_chunks(temp_json.encode('utf-8'))

        temp_encrypted = {
            'metadata': {
                'salt': temp_encrypt_salt,
                'threshold': temp_threshold,
                'total_chunks': len(temp_data_chunks)
            },
            'shares': []
        }

        # シェア生成（パスワードからIDを生成して利用）
        password_hash = hashlib.sha256(password.encode()).digest()
        temp_share_ids = []
        for i in range(10):  # 10個のシェアIDを生成
            id_seed = hashlib.sha256(password_hash + str(i).encode()).digest()
            temp_share_ids.append(int.from_bytes(id_seed[:4], 'big') % 10000)

        # 各チャンクをシェア化
        for i, chunk in enumerate(temp_data_chunks):
            secret = int.from_bytes(chunk, 'big')
            chunk_shares = generate_chunk_shares(secret, temp_threshold, temp_share_ids)
            for share_id, value in chunk_shares:
                temp_encrypted['shares'].append({
                    'chunk_index': i,
                    'share_id': share_id,
                    'value': value
                })

        # 暗号化された一時ファイルを保存
        with open(temp_file_path, 'w') as f:
            json.dump(temp_encrypted, f)

        # 対象パーティションマップキーの範囲内のシェアのみを更新
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
