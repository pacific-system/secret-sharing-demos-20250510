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
def encrypt(json_doc, password, share_token, unassigned_ids):
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

### 4.4. 一時ファイル暗号化強度のバランス

一時ファイルの暗号化強度は、メインファイルのセキュリティレベルと処理効率のバランスが重要な検討課題である：

1. **暗号化強度の選択肢**：

   - **最高レベル（メインファイルと同等）**: メインファイルと同じシャミア秘密分散法＋ AES-GCM
   - **中間レベル**: シャミア秘密分散法を省略し、AES-GCM のみで保護
   - **最小レベル**: メモリ内処理のみでディスク書き込みを回避

2. **トレードオフ比較**：

   | セキュリティレベル | 処理速度 | メモリ使用量 | ディスク使用量 | 実装複雑性 |
   | ------------------ | -------- | ------------ | -------------- | ---------- |
   | 最高レベル         | 低       | 中           | 大             | 高         |
   | 中間レベル         | 中       | 中           | 中             | 中         |
   | 最小レベル         | 高       | 大           | なし           | 低         |

3. **推奨アプローチ**：

   - 小～中サイズのファイル（～ 10MB）: **最小レベル**（メモリ内処理）
   - 大きいファイル（10MB ～ 100MB）: **中間レベル**（AES-GCM のみ）
   - 巨大ファイル（100MB ～）: **最高レベル**（シャミア＋ AES-GCM）

4. **適応型実装の例**：

   ```python
   def secure_temp_storage(data, password, file_size):
       """ファイルサイズに応じた適応型一時ストレージ"""
       if file_size < 10 * 1024 * 1024:  # 10MB未満
           # メモリ内処理のみ
           return MemoryTempStorage(data, password)
       elif file_size < 100 * 1024 * 1024:  # 10MB～100MB
           # AES-GCMのみで暗号化
           return AesGcmTempStorage(data, password)
       else:  # 100MB以上
           # シャミア法+AES-GCMで完全保護
           return ShamirAesGcmTempStorage(data, password)
   ```

5. **その他の考慮事項**:
   - 処理タイムアウトの実装（長時間実行による露出リスク低減）
   - 一時ファイルのバージョン管理（複数プロセスの並行実行対応）
   - エラー状態の保存（停電などでの復旧可能性）

### 4.5. WAL ログ方式と競合検出

データの整合性と安全な更新を保証するため、以下の仕組みを実装する：

1. **WAL ログ方式の採用**：

   - 原子的な更新処理を保証し、途中で処理が中断された場合のデータ整合性を確保
   - 実装例：

     ```python
     def atomic_update(encrypted_file, json_doc, password, share_ids):
         """WALログを使用した原子的な更新処理"""
         # WALログの作成
         wal_path = create_wal_file(encrypted_file)

         try:
             # ファイルの状態をWALに記録
             write_initial_state(wal_path, encrypted_file)

             # 更新処理の実行
             updated_file = update_internal(encrypted_file, json_doc, password, share_ids)

             # 更新結果をWALに記録
             write_updated_state(wal_path, updated_file)

             # WALをコミット（実際のファイル書き込み）
             commit_wal(wal_path, updated_file)

             return updated_file

         except Exception as e:
             # エラー発生時はWALを使用して復旧
             rollback_from_wal(wal_path)
             raise e

         finally:
             # 処理完了後にWALをクリーンアップ
             cleanup_wal(wal_path)
     ```

2. **競合検出と自動再試行ロジック**：

   - ファイル更新の競合を検出し、指数バックオフで自動再試行
   - 実装例：

     ```python
     def update_with_retry(encrypted_file, json_doc, password, share_ids, max_retries=5):
         """競合時に指数バックオフで再試行する更新処理"""
         retries = 0
         initial_delay = 0.1

         while retries < max_retries:
             try:
                 # ファイルロックを試行
                 with file_lock(encrypted_file):
                     return atomic_update(encrypted_file, json_doc, password, share_ids)
             except FileLockError:
                 # 競合発生時は待機して再試行
                 retries += 1
                 if retries >= max_retries:
                     raise MaxRetriesExceeded("最大再試行回数を超過しました")

                 # 指数バックオフ
                 delay = initial_delay * (2 ** retries)
                 # 少しランダム性を加えて競合確率を下げる
                 jitter = random.uniform(0, 0.1 * delay)
                 time.sleep(delay + jitter)

         # ここには到達しないはず（例外が発生するため）
         raise RuntimeError("予期せぬエラー: 再試行ロジックの異常終了")
     ```

3. **WAL ログの管理**:

   - WAL ログの形式：

     ```python
     {
         'status': 'start|ready|complete',  # 処理状態
         'timestamp': 1628675432.123,       # タイムスタンプ
         'original_file': {                 # 元ファイルのハッシュとパス
             'path': '/path/to/file.bin',
             'hash': 'sha256-hash-value'
         },
         'new_file': {                      # 更新後ファイル（readyまたはcomplete時）
             'path': '/path/to/new_file.bin',
             'hash': 'sha256-hash-value'
         }
     }
     ```

   - WAL ログの操作：
     - 書き込み: ログエントリを追加（状態の記録）
     - コミット: 最終状態を記録し、ファイル操作を完了
     - ロールバック: 中断された処理を元の状態に戻す
     - クリーンアップ: 不要になった WAL ログファイルを安全に削除

4. **起動時の WAL ログ処理**:
   - システム起動時または操作開始時に未処理の WAL ログを確認
   - 状態が「ready」のログを見つけた場合は中断された更新操作を完了
   - 状態が「start」のログを見つけた場合はロールバックを実行
   - 古い WAL ログ（タイムアウト値を超えたもの）を安全に削除
