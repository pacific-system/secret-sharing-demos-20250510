"""
更新処理の実装

このモジュールでは、暗号化ファイルの更新処理を安全に行うための機能を
提供します。WALログ方式、ファイルロック機構、原子的更新などの機能を実装します。
"""

import os
import json
import time
import uuid
import fcntl
import shutil
import secrets
import hashlib
import base64
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional, Set

from .constants import ShamirConstants
from .core import (
    generate_polynomial, evaluate_polynomial, generate_shares,
    lagrange_interpolation, constant_time_select
)
from .crypto import (
    preprocess_json_document, split_into_chunks, stage1_map, stage2_map,
    select_shares_for_encryption, derive_key, encrypt_json_document,
    decrypt_json_document
)
from .formats import load_encrypted_file, save_encrypted_file, FileFormatV1, FileFormatV2
from .metadata import MetadataManager


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

        # メタデータマネージャーを初期化（メタデータパスを自動生成）
        metadata_path = os.path.join(self.base_dir, 'metadata.json')
        self.metadata_manager = MetadataManager(metadata_path)

    def create_wal_file(self, original_file_path: str, partition_key: str) -> str:
        """
        新しいWALログファイルを作成

        Args:
            original_file_path: 元のファイルパス
            partition_key: パーティションキー

        Returns:
            WALログファイルのパス
        """
        # メタデータディレクトリを確認
        os.makedirs(os.path.dirname(self.metadata_manager.metadata_file_path), exist_ok=True)

        # WALの開始をメタデータに記録
        if not self.metadata_manager.start_wal("update"):
            raise ValueError("WALの開始に失敗しました。別の操作が進行中です。")

        wal_path = self.temp_manager.create_temp_file("shamir_wal")

        # 元ファイルのハッシュを計算
        file_hash = self._calculate_file_hash(original_file_path)

        # パーティションキーのハッシュを計算（機密性のため部分的なハッシュ）
        key_hash = hashlib.sha256(partition_key.encode('utf-8')).hexdigest()[:16]

        # 初期WALログを作成
        wal_data = {
            'status': 'start',
            'timestamp': time.time(),
            'original_file': {
                'path': original_file_path,
                'hash': file_hash
            },
            'partition_key_hash': key_hash
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

            # WAL終了をメタデータに記録
            self.metadata_manager.end_wal()

            # バックアップを削除
            if os.path.exists(backup_path):
                os.remove(backup_path)

        except Exception as e:
            # エラー発生時はバックアップから復元
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, target_file_path)

            # WAL終了（エラー状態）をメタデータに記録
            self.metadata_manager.end_wal()
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

        # WAL終了（ロールバック）をメタデータに記録
        self.metadata_manager.end_wal()

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


def merge_shares(original_shares: List[Dict[str, Any]], updated_shares: List[Dict[str, Any]],
               partition_key: str, partition_share_ids: List[int]) -> List[Dict[str, Any]]:
    """
    更新前のシェアと更新後のシェアをマージ

    Args:
        original_shares: 元のシェアリスト
        updated_shares: 更新されたシェアリスト
        partition_key: パーティションキー（更新対象のパーティション）
        partition_share_ids: パーティションに属するシェアIDのリスト

    Returns:
        マージされたシェアリスト
    """
    # パーティションに属するシェアIDのセット
    partition_id_set = set(partition_share_ids)

    # 更新用のシェアをシェアIDでインデックス化 (chunk_index, share_id) -> share
    updated_share_map = {}
    for share in updated_shares:
        key = (share['chunk_index'], share['share_id'])
        updated_share_map[key] = share

    # マージされたシェアのリスト
    merged_shares = []

    # 元のシェアを処理
    for share in original_shares:
        share_id = share['share_id']
        chunk_index = share['chunk_index']
        key = (chunk_index, share_id)

        # パーティションに属するシェアなら更新されたシェアを使用
        if share_id in partition_id_set and key in updated_share_map:
            merged_shares.append(updated_share_map[key])
            # 処理済みとしてマーク
            updated_share_map.pop(key)
        else:
            # パーティションに属さないシェアはそのまま保持
            merged_shares.append(share)

    # 残りの更新シェア（新しいチャンクなど）を追加
    for key, share in updated_share_map.items():
        merged_shares.append(share)

    return merged_shares


def merge_shares_v2(original_data: Dict[str, Any], updated_data: Dict[str, Any],
                   partition_key: str, partition_share_ids: List[int]) -> Dict[str, Any]:
    """
    V2形式のファイルデータをマージ

    Args:
        original_data: 元のファイルデータ（V2形式）
        updated_data: 更新されたファイルデータ（V2形式）
        partition_key: パーティションキー
        partition_share_ids: パーティションに属するシェアIDのリスト

    Returns:
        マージされたファイルデータ（V2形式）
    """
    # ヘッダー情報をマージ
    merged_header = original_data["header"].copy()
    updated_header = updated_data["header"]

    # 更新後のメタデータを取り込む
    merged_header["total_chunks"] = max(merged_header["total_chunks"], updated_header["total_chunks"])
    merged_header["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # パーティションに属するシェアIDのセット
    partition_id_set = set(partition_share_ids)

    # オリジナルのチャンク配列
    original_chunks = original_data["chunks"]
    updated_chunks = updated_data["chunks"]

    # マージされたチャンク配列
    merged_chunks = []

    # 共通するチャンクインデックスの範囲で処理
    for i in range(min(len(original_chunks), len(updated_chunks))):
        # 現在のチャンクでのシェアをマージ
        original_chunk = original_chunks[i]
        updated_chunk = updated_chunks[i]

        # オリジナルのシェアをIDでインデックス化
        original_shares_map = {share["id"]: share for share in original_chunk}

        # マージされたシェアリスト
        merged_chunk = []

        # 更新されたシェアを処理
        for share in updated_chunk:
            share_id = share["id"]
            # パーティションに属するシェアは更新
            if share_id in partition_id_set:
                merged_chunk.append(share)
                # 処理済みとしてマーク
                if share_id in original_shares_map:
                    del original_shares_map[share_id]

        # パーティションに属さない残りのシェアをそのまま追加
        for share_id, share in original_shares_map.items():
            if share_id not in partition_id_set:
                merged_chunk.append(share)

        merged_chunks.append(merged_chunk)

    # オリジナルにない新しいチャンクを追加
    if len(updated_chunks) > len(original_chunks):
        for i in range(len(original_chunks), len(updated_chunks)):
            merged_chunks.append(updated_chunks[i])

    # マージされたデータを構築
    merged_data = {
        "header": merged_header,
        "chunks": merged_chunks
    }

    return merged_data


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
    # 新しいファイルの場合は最初に暗号化して保存
    if not os.path.exists(file_path):
        try:
            # 文書を暗号化
            encrypted_doc = encrypt_json_document(json_doc, password, partition_key)

            # 暗号化データをファイルに保存
            save_encrypted_file(encrypted_doc, file_path)

            return (True, encrypted_doc)
        except Exception as e:
            return (False, {"error": f"新規ファイルの暗号化に失敗しました: {str(e)}"})

    # 既存ファイルの更新
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
    try:
        print(f"DEBUG: _atomic_update - starting update for file {file_path}")
        # WALログファイルを作成
        wal_path = wal_manager.create_wal_file(file_path, partition_key)
        print(f"DEBUG: _atomic_update - created WAL file {wal_path}")

        # 元のファイルを読み込み
        original_data = load_encrypted_file(file_path)
        print(f"DEBUG: _atomic_update - loaded original file with {len(original_data.get('shares', []))} shares")

        # WALに初期状態を記録
        wal_manager.write_initial_state(wal_path, original_data)
        print(f"DEBUG: _atomic_update - wrote initial state to WAL")

        # ファイル形式に応じて処理を分岐
        file_format_version = original_data.get("header", {}).get("version", 1)
        print(f"DEBUG: _atomic_update - file format version: {file_format_version}")

        # V2形式の場合
        if file_format_version == 2:
            print(f"DEBUG: _atomic_update - processing V2 format file")
            # パーティションに対応するシェアIDを取得
            from .partition import generate_partition_map, normalize_partition_key
            normalized_key = normalize_partition_key(partition_key)
            share_id_space = original_data["header"].get("share_id_space", ShamirConstants.SHARE_ID_SPACE)
            threshold = original_data["header"].get("threshold", ShamirConstants.DEFAULT_THRESHOLD)
            partition_share_ids = generate_partition_map(normalized_key, share_id_space, threshold)
            print(f"DEBUG: _atomic_update - selected {len(partition_share_ids)} share IDs for partition {partition_key[:5]}...")

            # 新しい暗号化ファイルを生成
            salt_base64 = original_data["header"]["salt"]
            salt = base64.urlsafe_b64decode(salt_base64)
            print(f"DEBUG: _atomic_update - extracted salt")

            # ドキュメントを暗号化（V1形式で生成）
            encrypted_doc = encrypt_json_document(json_doc, password, partition_key, threshold)
            print(f"DEBUG: _atomic_update - encrypted new document with {len(encrypted_doc.get('shares', []))} shares")

            # V1形式からV2形式に変換
            from .formats import convert_v1_to_v2
            encrypted_doc_v2 = convert_v1_to_v2(encrypted_doc)
            print(f"DEBUG: _atomic_update - converted encrypted document from V1 to V2 format")

            # 更新後のファイルデータを作成
            updated_data = merge_shares_v2(original_data, encrypted_doc_v2, partition_key, partition_share_ids)
            print(f"DEBUG: _atomic_update - merged shares, resulting in {len(updated_data.get('chunks', []))} chunks")

            # WALに更新状態を記録
            wal_manager.write_updated_state(wal_path, updated_data)
            print(f"DEBUG: _atomic_update - wrote updated state to WAL")

            # 実際にファイルを更新
            wal_manager.commit_wal(wal_path, file_path)
            print(f"DEBUG: _atomic_update - committed WAL to file {file_path}")

            # WALをクリーンアップ
            wal_manager.cleanup_wal(wal_path)
            print(f"DEBUG: _atomic_update - cleaned up WAL")

            return (True, updated_data)

        # V1形式の場合（従来と同様の処理）
        else:
            print(f"DEBUG: _atomic_update - processing V1 format file")
            # V1形式のデータ構造
            original_metadata = original_data["metadata"]
            original_shares = original_data["shares"]
            print(f"DEBUG: _atomic_update - original file has {len(original_shares)} shares and {original_metadata.get('total_chunks', 0)} chunks")

            # メタデータから復号に必要な情報を取得
            salt_base64 = original_metadata["salt"]
            salt = base64.urlsafe_b64decode(salt_base64)
            threshold = original_metadata["threshold"]
            print(f"DEBUG: _atomic_update - extracted metadata with threshold {threshold}")

            # シェアID空間を生成 (1からSHARE_ID_SPACE)
            all_share_ids = list(range(1, ShamirConstants.SHARE_ID_SPACE + 1))
            print(f"DEBUG: _atomic_update - generated {len(all_share_ids)} share IDs")

            # パーティションに対応するシェアIDを取得
            from .partition import generate_partition_map, normalize_partition_key
            normalized_key = normalize_partition_key(partition_key)
            print(f"DEBUG: _atomic_update - normalized partition key {partition_key[:5]}...")
            partition_share_ids = generate_partition_map(
                normalized_key, ShamirConstants.SHARE_ID_SPACE, threshold
            )
            print(f"DEBUG: _atomic_update - selected {len(partition_share_ids)} share IDs for partition {partition_key[:5]}...")

            # 現在のチャンク（ブロック）数を取得
            total_chunks = original_metadata["total_chunks"]
            print(f"DEBUG: _atomic_update - original document has {total_chunks} chunks")

            # ドキュメントを暗号化
            encrypted_doc = encrypt_json_document(json_doc, password, partition_key, threshold)
            encrypted_metadata = encrypted_doc["metadata"]
            encrypted_shares = encrypted_doc["shares"]
            print(f"DEBUG: _atomic_update - encrypted new document with {len(encrypted_shares)} shares")

            # 新しいメタデータを作成（元のメタデータを基に更新）
            new_metadata = original_metadata.copy()
            new_metadata["total_chunks"] = max(total_chunks, encrypted_metadata["total_chunks"])
            print(f"DEBUG: _atomic_update - created new metadata with {new_metadata['total_chunks']} chunks")

            # シェアをマージ
            merged_shares = merge_shares(original_shares, encrypted_shares, partition_key, partition_share_ids)
            print(f"DEBUG: _atomic_update - merged shares, resulting in {len(merged_shares)} shares")

            # 更新後のファイルデータを作成
            updated_data = {
                "metadata": new_metadata,
                "shares": merged_shares
            }
            print(f"DEBUG: _atomic_update - created updated file data")

            # WALに更新状態を記録
            wal_manager.write_updated_state(wal_path, updated_data)
            print(f"DEBUG: _atomic_update - wrote updated state to WAL")

            # 実際にファイルを更新
            wal_manager.commit_wal(wal_path, file_path)
            print(f"DEBUG: _atomic_update - committed WAL to file {file_path}")

            # WALをクリーンアップ
            wal_manager.cleanup_wal(wal_path)
            print(f"DEBUG: _atomic_update - cleaned up WAL")

            return (True, updated_data)

    except Exception as e:
        # エラーが発生した場合はロールバック
        print(f"ERROR: _atomic_update - update failed with error: {str(e)}")
        import traceback
        traceback.print_exc()

        try:
            wal_manager.rollback_from_wal(wal_path)
            wal_manager.cleanup_wal(wal_path)
            print(f"DEBUG: _atomic_update - rolled back and cleaned up WAL after error")
        except Exception as rollback_error:
            # ロールバックエラーも記録
            print(f"ERROR: _atomic_update - rollback failed with error: {str(rollback_error)}")

        # 元のエラーを返す
        return (False, {
            "error": "更新処理中にエラーが発生しました",
            "exception": str(e)
        })


def verify_update(
    file_path: str,
    json_doc: Any,
    password: str,
    partition_key: str
) -> Dict[str, Any]:
    """
    更新を検証（実際に更新せずに結果を確認）

    Args:
        file_path: 暗号化ファイルのパス
        json_doc: 新しいJSON文書
        password: パスワード
        partition_key: パーティションマップキー

    Returns:
        検証結果の辞書
    """
    try:
        # 暗号化ファイルを読み込み
        file_data = load_encrypted_file(file_path)

        # ファイル形式に応じて処理を分岐
        file_format_version = file_data.get("header", {}).get("version", 1)

        if file_format_version == 2:
            # V2形式の場合
            header = file_data["header"]
            threshold = header["threshold"]

            # 新しい暗号化ファイルを生成（実際には保存しない）
            encrypted_doc = encrypt_json_document(json_doc, password, partition_key, threshold)

            # パーティションに対応するシェアIDを取得
            from .partition import generate_partition_map, normalize_partition_key
            normalized_key = normalize_partition_key(partition_key)
            share_id_space = header.get("share_id_space", ShamirConstants.SHARE_ID_SPACE)
            partition_share_ids = generate_partition_map(normalized_key, share_id_space, threshold)

            # シェア数の変化を確認
            original_share_count = sum(len(chunk) for chunk in file_data["chunks"])

            # 更新シミュレーション
            updated_data = merge_shares_v2(file_data, encrypted_doc, partition_key, partition_share_ids)
            updated_share_count = sum(len(chunk) for chunk in updated_data["chunks"])

            return {
                "valid": True,
                "file_format": "V2",
                "original_chunks": len(file_data["chunks"]),
                "updated_chunks": len(updated_data["chunks"]),
                "original_share_count": original_share_count,
                "updated_share_count": updated_share_count,
                "change": updated_share_count - original_share_count,
                "partition_share_count": len(partition_share_ids)
            }
        else:
            # V1形式の場合
            original_metadata = file_data["metadata"]
            original_shares = file_data["shares"]
            threshold = original_metadata["threshold"]

            # シェアID空間を生成 (1からSHARE_ID_SPACE)
            all_share_ids = list(range(1, ShamirConstants.SHARE_ID_SPACE + 1))

            # パーティションに対応するシェアIDを取得
            from .partition import generate_partition_map, normalize_partition_key
            normalized_key = normalize_partition_key(partition_key)
            partition_share_ids = generate_partition_map(
                normalized_key, ShamirConstants.SHARE_ID_SPACE, threshold
            )

            # ドキュメントを暗号化（実際には保存しない）
            encrypted_doc = encrypt_json_document(json_doc, password, partition_key, threshold)
            encrypted_shares = encrypted_doc["shares"]

            # シェアをマージ（シミュレーション）
            merged_shares = merge_shares(original_shares, encrypted_shares, partition_key, partition_share_ids)

            return {
                "valid": True,
                "file_format": "V1",
                "original_chunks": original_metadata["total_chunks"],
                "updated_chunks": max(original_metadata["total_chunks"], encrypted_doc["metadata"]["total_chunks"]),
                "original_share_count": len(original_shares),
                "updated_share_count": len(merged_shares),
                "change": len(merged_shares) - len(original_shares),
                "partition_share_count": len(partition_share_ids)
            }

    except Exception as e:
        return {
            "valid": False,
            "error": f"検証中にエラーが発生しました: {str(e)}"
        }