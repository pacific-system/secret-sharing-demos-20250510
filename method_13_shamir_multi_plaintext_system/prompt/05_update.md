## データの更新

データ更新プロセスでは、既存の暗号化ファイルに対して単一文書を更新します。この処理は複数のステップと安全なトランザクション処理を必要とします。

実装にあたっては、以下の設計書ドキュメントを参照してください：

- `04_implementation.md`: 4.3 節「更新プロセス」、4.4 節「一時ファイル暗号化強度のバランス」、4.5 節「WAL ログ方式と競合検出」
- `05_security.md`: 5.1 節「攻撃モデルと脆弱性分析」
- `07_guidelines.md`: 7.1 節「セキュアデータ構造設計原則」

### 1. 安全な更新の実装

データの更新部分では、暗号化ファイルの内容を変更するための安全な処理を実装します。WAL（Write-Ahead Logging）方式を採用し、原子的更新と競合検出を行います。

### 1. 一時ファイル管理

```python
class TempFileManager:
    """安全な一時ファイル管理クラス"""

    def __init__(self, base_dir: str = None):
        """
        一時ファイル管理クラスの初期化

        Args:
            base_dir: 一時ファイルを保存するディレクトリ
        """
        self.base_dir = base_dir or os.path.join(os.path.expanduser('~'), '.shamir_temp')
        os.makedirs(self.base_dir, exist_ok=True)

        # 古い一時ファイルをクリーンアップ
        self._cleanup_old_temp_files()

    def create_temp_file(self, prefix: str = None) -> str:
        """
        新しい一時ファイルを作成

        Args:
            prefix: ファイル名のプレフィックス

        Returns:
            一時ファイルのパス
        """
        prefix = prefix or ShamirConstants.TEMP_FILE_PREFIX
        temp_file_name = f"{prefix}_{uuid.uuid4().hex}.tmp"
        temp_file_path = os.path.join(self.base_dir, temp_file_name)

        # ロックファイルも作成
        lock_path = f"{temp_file_path}.lock"
        with open(lock_path, 'w') as f:
            # PIDとタイムスタンプを記録
            f.write(f"{os.getpid()},{time.time()}")

        return temp_file_path

    def cleanup_temp_file(self, temp_file_path: str) -> None:
        """
        一時ファイルを安全に削除

        Args:
            temp_file_path: 削除する一時ファイルのパス
        """
        try:
            # 本体ファイルを削除
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            # ロックファイルも削除
            lock_path = f"{temp_file_path}.lock"
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except Exception as e:
            print(f"一時ファイルの削除中にエラーが発生しました: {e}")

    def _cleanup_old_temp_files(self) -> None:
        """古い一時ファイルを自動的にクリーンアップ"""
        current_time = time.time()

        for filename in os.listdir(self.base_dir):
            if not filename.endswith('.lock'):
                continue

            file_path = os.path.join(self.base_dir, filename)
            temp_file = file_path[:-5]  # .lockを除去

            try:
                with open(file_path, 'r') as f:
                    content = f.read().strip().split(',')
                    if len(content) == 2:
                        pid_str, timestamp_str = content
                        pid = int(pid_str)
                        timestamp = float(timestamp_str)

                        # プロセスが生きているか確認
                        process_alive = False
                        try:
                            # UNIX系OSで実行中のプロセスを確認
                            os.kill(pid, 0)
                            process_alive = True
                        except (OSError, ProcessLookupError):
                            process_alive = False

                        # タイムアウト時間を過ぎているか、プロセスが生きていない場合は削除
                        if (current_time - timestamp > ShamirConstants.WAL_TIMEOUT or
                            not process_alive):
                            self.cleanup_temp_file(temp_file)
            except Exception as e:
                # 解析エラーの場合はファイル削除
                print(f"一時ファイルの解析エラー {file_path}: {e}")
                self.cleanup_temp_file(temp_file)
```

### 2. WAL ログ方式の実装

```python
class WALManager:
    """Write-Ahead Logging (WAL) 方式によるファイル更新管理"""

    def __init__(self, base_dir: str = None):
        """
        WALマネージャーの初期化

        Args:
            base_dir: WALログを保存するディレクトリ
        """
        self.base_dir = base_dir or os.path.join(os.path.expanduser('~'), '.shamir_wal')
        os.makedirs(self.base_dir, exist_ok=True)
        self.temp_manager = TempFileManager(base_dir)

    def create_wal_file(self, original_file_path: str) -> str:
        """
        新しいWALログファイルを作成

        Args:
            original_file_path: 元のファイルパス

        Returns:
            WALログファイルのパス
        """
        wal_path = self.temp_manager.create_temp_file("shamir_wal")

        # 元ファイルのハッシュを計算
        file_hash = self._calculate_file_hash(original_file_path)

        # 初期WALログを作成
        wal_data = {
            'status': 'start',
            'timestamp': time.time(),
            'original_file': {
                'path': original_file_path,
                'hash': file_hash
            }
        }

        # WALログをディスクに保存
        with open(wal_path, 'w') as f:
            json.dump(wal_data, f)

        return wal_path

    def write_initial_state(self, wal_path: str, encrypted_file: Dict[str, Any]) -> None:
        """
        初期状態をWALに記録

        Args:
            wal_path: WALログファイルのパス
            encrypted_file: 暗号化ファイルデータ
        """
        temp_file_path = self._get_temp_data_path(wal_path)

        # 初期データを一時ファイルに保存
        with open(temp_file_path, 'w') as f:
            json.dump(encrypted_file, f)

        # WALログを更新
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        wal_data['initial_state'] = {
            'path': temp_file_path,
            'hash': self._calculate_data_hash(encrypted_file)
        }

        with open(wal_path, 'w') as f:
            json.dump(wal_data, f)

    def write_updated_state(self, wal_path: str, updated_file: Dict[str, Any]) -> None:
        """
        更新後の状態をWALに記録

        Args:
            wal_path: WALログファイルのパス
            updated_file: 更新後の暗号化ファイルデータ
        """
        temp_file_path = self._get_temp_data_path(wal_path, suffix='_updated')

        # 更新データを一時ファイルに保存
        with open(temp_file_path, 'w') as f:
            json.dump(updated_file, f)

        # WALログを更新
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        wal_data['status'] = 'ready'
        wal_data['updated_state'] = {
            'path': temp_file_path,
            'hash': self._calculate_data_hash(updated_file)
        }

        with open(wal_path, 'w') as f:
            json.dump(wal_data, f)

    def commit_wal(self, wal_path: str, target_file_path: str) -> None:
        """
        WALをコミット（実際のファイル書き込み）

        Args:
            wal_path: WALログファイルのパス
            target_file_path: 書き込み先のファイルパス
        """
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        # WALの状態を確認
        if wal_data.get('status') != 'ready':
            raise ValueError("WALが'ready'状態ではありません")

        # 更新データを読み込む
        updated_state = wal_data.get('updated_state', {})
        updated_path = updated_state.get('path')

        if not updated_path or not os.path.exists(updated_path):
            raise FileNotFoundError("更新データが見つかりません")

        with open(updated_path, 'r') as f:
            updated_data = json.load(f)

        # 先にバックアップを作成
        backup_path = f"{target_file_path}.bak"
        if os.path.exists(target_file_path):
            shutil.copy2(target_file_path, backup_path)

        try:
            # 更新データを実際のファイルに書き込み
            with open(target_file_path, 'w') as f:
                json.dump(updated_data, f)

            # WALログを「完了」状態に更新
            wal_data['status'] = 'complete'
            wal_data['completion_time'] = time.time()

            with open(wal_path, 'w') as f:
                json.dump(wal_data, f)

            # バックアップを削除
            if os.path.exists(backup_path):
                os.remove(backup_path)

        except Exception as e:
            # エラー発生時はバックアップから復元
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, target_file_path)
            raise e

    def rollback_from_wal(self, wal_path: str) -> None:
        """
        WALを使用してロールバック

        Args:
            wal_path: WALログファイルのパス
        """
        with open(wal_path, 'r') as f:
            wal_data = json.load(f)

        # 元のファイルパスを取得
        original_file = wal_data.get('original_file', {})
        original_path = original_file.get('path')

        # バックアップがあれば復元
        backup_path = f"{original_path}.bak"
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, original_path)
            os.remove(backup_path)

    def cleanup_wal(self, wal_path: str) -> None:
        """
        WALログとその関連ファイルをクリーンアップ

        Args:
            wal_path: WALログファイルのパス
        """
        try:
            with open(wal_path, 'r') as f:
                wal_data = json.load(f)

            # 関連する一時ファイルを削除
            for state_key in ['initial_state', 'updated_state']:
                state = wal_data.get(state_key, {})
                state_path = state.get('path')
                if state_path and os.path.exists(state_path):
                    os.remove(state_path)

            # バックアップファイルを削除
            original_path = wal_data.get('original_file', {}).get('path')
            if original_path:
                backup_path = f"{original_path}.bak"
                if os.path.exists(backup_path):
                    os.remove(backup_path)

        except Exception as e:
            print(f"WALログのクリーンアップ中にエラー: {e}")

        finally:
            # WALログファイル自体を削除
            if os.path.exists(wal_path):
                os.remove(wal_path)

    def _get_temp_data_path(self, wal_path: str, suffix: str = '') -> str:
        """WALログに関連する一時データファイルのパスを生成"""
        base_name = os.path.basename(wal_path)
        return os.path.join(self.base_dir, f"{base_name}_data{suffix}.json")

    def _calculate_file_hash(self, file_path: str) -> str:
        """ファイルのSHA-256ハッシュを計算"""
        if not os.path.exists(file_path):
            return ""

        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def _calculate_data_hash(self, data: Dict[str, Any]) -> str:
        """辞書データのSHA-256ハッシュを計算"""
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
```

### 3. ファイルロック機構

```python
class FileLockError(Exception):
    """ファイルロック関連のエラー"""
    pass


class FileLock:
    """ファイルレベルのロック機構"""

    def __init__(self, file_path: str, timeout: int = 10):
        """
        ファイルロックの初期化

        Args:
            file_path: ロックするファイルのパス
            timeout: ロック取得のタイムアウト（秒）
        """
        self.file_path = file_path
        self.lock_path = f"{file_path}.lock"
        self.timeout = timeout
        self.lock_file = None

    def __enter__(self):
        """コンテキストマネージャーのエントリーポイント"""
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """コンテキストマネージャーの終了処理"""
        self.release()

    def acquire(self):
        """ロックを取得"""
        start_time = time.time()

        while True:
            try:
                # ロックファイルを作成
                self.lock_file = open(self.lock_path, 'w+')

                # fcntlでロックを取得（UNIX系OS用）
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                # PIDとタイムスタンプを書き込み
                self.lock_file.write(f"{os.getpid()},{time.time()}")
                self.lock_file.flush()

                # ロック取得成功
                return

            except IOError:
                # ロック取得失敗
                if self.lock_file:
                    self.lock_file.close()
                    self.lock_file = None

                # タイムアウトチェック
                if time.time() - start_time > self.timeout:
                    raise FileLockError(f"ファイルのロック取得がタイムアウトしました: {self.file_path}")

                # 少し待ってから再試行
                time.sleep(0.1)

    def release(self):
        """ロックを解放"""
        if self.lock_file:
            # fcntlでロックを解放（UNIX系OS用）
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            self.lock_file.close()
            self.lock_file = None

            # ロックファイルを削除
            try:
                os.remove(self.lock_path)
            except OSError:
                pass


def file_lock(file_path: str, timeout: int = 10):
    """ファイルロックを取得するためのヘルパー関数"""
    return FileLock(file_path, timeout)
```

### 4. 更新処理の実装

```python
def update_encrypted_document(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str,
    max_retries: int = 5
) -> Tuple[bool, Dict[str, Any]]:
    """
    暗号化ファイル内の文書を更新

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を更新します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        file_path: 暗号化ファイルのパス
        json_doc: 新しいJSON文書
        password: パスワード
        partition_key: パーティションマップキー（AまたはBのいずれか）
        max_retries: 最大再試行回数

    Returns:
        (成功フラグ, 更新後のファイルデータまたはエラー情報)
    """
    # WALとロック管理を初期化
    wal_manager = WALManager()
    retries = 0
    initial_delay = 0.1

    while retries < max_retries:
        try:
            # ファイルロックを試行
            with file_lock(file_path):
                return _atomic_update(
                    file_path, json_doc, password, partition_key, wal_manager
                )

        except FileLockError:
            # 競合発生時は待機して再試行
            retries += 1
            if retries >= max_retries:
                return (False, {
                    "error": "更新に失敗しました",
                    "reason": "最大再試行回数を超過しました"
                })

            # 指数バックオフ
            delay = initial_delay * (2 ** retries)
            # 少しランダム性を加えて競合確率を下げる
            jitter = secrets.randbelow(int(delay * 100)) / 1000
            time.sleep(delay + jitter)

    # ここには到達しないはず
    return (False, {"error": "予期せぬエラー: 再試行ロジックの異常終了"})


def _atomic_update(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str,
    wal_manager: WALManager
) -> Tuple[bool, Dict[str, Any]]:
    """
    WALログを使用した原子的な更新処理

    Args:
        file_path: 暗号化ファイルのパス
        json_doc: 新しいJSON文書
        password: パスワード
        partition_key: パーティションマップキー
        wal_manager: WALマネージャー

    Returns:
        (成功フラグ, 更新後のファイルデータまたはエラー情報)
    """
    # WALログを作成
    wal_path = wal_manager.create_wal_file(file_path)

    try:
        # 暗号化ファイルを読み込む
        with open(file_path, 'r') as f:
            encrypted_file = json.load(f)

        # ファイルの状態をWALに記録
        wal_manager.write_initial_state(wal_path, encrypted_file)

        # 復号してJSONドキュメントを取得
        decrypted_doc = decrypt_json_document(encrypted_file, partition_key, password)

        # 復号に失敗した場合
        if isinstance(decrypted_doc, dict) and 'error' in decrypted_doc:
            return (False, {
                "error": "更新に失敗しました",
                "reason": "復号化に失敗しました",
                "details": decrypted_doc.get('error')
            })

        # メタデータを取得
        metadata = encrypted_file['metadata']
        salt = base64.urlsafe_b64decode(metadata['salt'])
        threshold = metadata['threshold']

        # 必要なシェアIDを取得
        all_share_ids = sorted(list(set(share['share_id'] for share in encrypted_file['shares'])))

        # 第1段階MAPで候補シェアを特定
        partition_share_ids = stage1_map(partition_key, all_share_ids)

        # パーティションマップキーに対応するシェアを特定し、それ以外のシェアは保持
        other_shares = [s for s in encrypted_file['shares'] if s['share_id'] not in partition_share_ids]

        # 新しい文書を暗号化
        # 前処理
        preprocessed_data = preprocess_json_document(json_doc)
        chunks = split_into_chunks(preprocessed_data)

        # 使用するシェアIDを選択
        selected_share_ids = select_shares_for_encryption(
            partition_key, password, partition_share_ids, salt, threshold
        )

        # 新しいシェアを生成
        new_shares = []
        for chunk_idx, chunk in enumerate(chunks):
            secret = mpz(int.from_bytes(chunk, 'big'))
            chunk_shares = generate_shares(
                secret, threshold, selected_share_ids, ShamirConstants.PRIME
            )
            for share_id, value in chunk_shares:
                new_shares.append({
                    'chunk_index': chunk_idx,
                    'share_id': share_id,
                    'value': str(value)
                })

        # メタデータを更新
        updated_metadata = metadata.copy()
        if 'total_chunks_a' in metadata and partition_key.endswith('_a'):
            updated_metadata['total_chunks_a'] = len(chunks)
        elif 'total_chunks_b' in metadata and partition_key.endswith('_b'):
            updated_metadata['total_chunks_b'] = len(chunks)
        else:
            updated_metadata['total_chunks'] = len(chunks)

        # 更新後のファイルを作成
        updated_file = {
            'metadata': updated_metadata,
            'shares': other_shares + new_shares
        }

        # 更新結果をWALに記録
        wal_manager.write_updated_state(wal_path, updated_file)

        # WALをコミット（実際のファイル書き込み）
        wal_manager.commit_wal(wal_path, file_path)

        return (True, updated_file)

    except Exception as e:
        # エラー発生時はWALを使用してロールバック
        wal_manager.rollback_from_wal(wal_path)
        return (False, {
            "error": "更新中にエラーが発生しました",
            "details": str(e)
        })

    finally:
        # 処理完了後にWALをクリーンアップ
        wal_manager.cleanup_wal(wal_path)
```

### 5. 更新検証機能

```python
def verify_update(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str
) -> Dict[str, Any]:
    """
    更新前に検証を行い、問題がないか確認

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を更新します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        file_path: 暗号化ファイルのパス
        json_doc: 新しいJSON文書
        password: パスワード
        partition_key: パーティションマップキー（AまたはBのいずれか）

    Returns:
        検証結果（問題がなければsuccess=True、問題があればエラー情報を含む）
    """
    try:
        # 既存ファイル読み込み
        with open(file_path, 'r') as f:
            encrypted_file = json.load(f)

        # 復号テスト
        decrypted_doc = decrypt_json_document(encrypted_file, partition_key, password)

        # 復号に失敗した場合
        if isinstance(decrypted_doc, dict) and 'error' in decrypted_doc:
            return {
                "success": False,
                "error": "検証に失敗しました",
                "reason": "既存ファイルの復号化に失敗しました",
                "details": decrypted_doc.get('error')
            }

        # 新しい文書を前処理して推定ファイルサイズを計算
        preprocessed_data = preprocess_json_document(json_doc)
        chunks = split_into_chunks(preprocessed_data)

        # 現在のチャンク数と新しいチャンク数を比較
        metadata = encrypted_file['metadata']
        current_chunks = metadata.get('total_chunks', 0)

        if 'total_chunks_a' in metadata and partition_key.endswith('_a'):
            current_chunks = metadata.get('total_chunks_a', 0)
        elif 'total_chunks_b' in metadata and partition_key.endswith('_b'):
            current_chunks = metadata.get('total_chunks_b', 0)

        size_change = len(chunks) - current_chunks
        size_change_percent = (size_change / max(1, current_chunks)) * 100

        # サイズ変更が大きすぎる場合に警告
        warnings = []
        if abs(size_change_percent) > 50:
            warnings.append(f"ファイルサイズが大幅に変更されます（{size_change_percent:.1f}%）")

        # チャンク数が増えた場合の処理時間目安
        estimated_time = 0.01 * len(chunks)  # 1チャンクあたり約0.01秒と仮定

        return {
            "success": True,
            "current_chunks": current_chunks,
            "new_chunks": len(chunks),
            "size_change": size_change,
            "size_change_percent": size_change_percent,
            "estimated_time": estimated_time,
            "warnings": warnings
        }

    except Exception as e:
        return {
            "success": False,
            "error": "検証中にエラーが発生しました",
            "details": str(e)
        }
```
