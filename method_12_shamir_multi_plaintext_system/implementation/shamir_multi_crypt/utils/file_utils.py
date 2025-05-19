#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ファイル操作のためのユーティリティ関数モジュール

このモジュールは、安全なファイル読み書きや一時ファイル処理のための関数を提供します。
"""

import os
import json
import time
import uuid
import shutil
import tempfile
from pathlib import Path


def safe_read_json(file_path):
    """
    JSONファイルを安全に読み込む

    Args:
        file_path (str): 読み込むJSONファイルのパス

    Returns:
        dict: 読み込まれたJSONデータ

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        json.JSONDecodeError: JSONの解析に失敗した場合
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def safe_write_json(data, file_path, backup=False):
    """
    JSONデータを安全にファイルに書き込む

    原子的な書き込みを確保するため、一時ファイルに書き込んでから
    目的のファイルにリネームします。

    Args:
        data (dict): 書き込むJSONデータ
        file_path (str): 書き込み先ファイルパス
        backup (bool): 既存ファイルのバックアップを作成するかどうか

    Returns:
        bool: 成功した場合はTrue
    """
    file_path = Path(file_path)
    temp_file = file_path.with_suffix('.tmp')

    # バックアップファイルのパス
    backup_file = None
    if backup and file_path.exists():
        backup_file = file_path.with_suffix(f'.bak.{int(time.time())}')

    try:
        # 一時ファイルにデータを書き込み
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        # バックアップ作成
        if backup_file:
            shutil.copy2(file_path, backup_file)

        # 原子的リネーム
        os.replace(temp_file, file_path)
        return True
    except Exception as e:
        # エラー時に一時ファイルをクリーンアップ
        if temp_file.exists():
            try:
                os.remove(temp_file)
            except:
                pass
        raise e


def create_temp_resources(base_dir=None, prefix="update_", suffix=".tmp"):
    """
    一時リソース（ファイルとロックファイル）を作成

    Args:
        base_dir (str, optional): 一時ファイルを作成するディレクトリ
        prefix (str, optional): 一時ファイル名のプレフィックス
        suffix (str, optional): 一時ファイル名の拡張子

    Returns:
        tuple: (process_uuid, temp_file_path, lock_file_path)
    """
    if base_dir is None:
        base_dir = os.path.join(tempfile.gettempdir(), "shamir_multi_crypt")

    # 一時ディレクトリの確保
    os.makedirs(base_dir, exist_ok=True)

    # プロセス固有のUUID生成
    process_uuid = str(uuid.uuid4())

    # 一時ファイルとロックファイルのパス生成
    temp_file_path = os.path.join(base_dir, f"{prefix}{process_uuid}{suffix}")
    lock_file_path = os.path.join(base_dir, f"lock_{process_uuid}.lock")

    # ロックファイル作成
    with open(lock_file_path, 'w', encoding='utf-8') as lock_file:
        lock_info = {
            'pid': os.getpid(),
            'timestamp': time.time(),
            'operation': prefix.rstrip('_')
        }
        json.dump(lock_info, lock_file)

    return process_uuid, temp_file_path, lock_file_path


def cleanup_stale_temp_files(directory, timeout_seconds=3600):
    """
    期限切れ/孤立した一時ファイルを削除

    Args:
        directory (str): 一時ファイルが格納されているディレクトリ
        timeout_seconds (int, optional): プロセスがタイムアウトとみなされる秒数

    Returns:
        int: 削除されたファイルの数
    """
    if not os.path.exists(directory):
        return 0

    current_time = time.time()
    cleaned_count = 0

    # ロックファイルをスキャン
    for filename in os.listdir(directory):
        if filename.startswith("lock_") and filename.endswith(".lock"):
            lock_path = os.path.join(directory, filename)
            process_uuid = filename[5:-5]  # "lock_" と ".lock" を削除

            try:
                with open(lock_path, 'r', encoding='utf-8') as lock_file:
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
                    operation = lock_info.get('operation', 'update')
                    temp_path = os.path.join(directory, f"{operation}_{process_uuid}.tmp")
                    if os.path.exists(temp_path):
                        safe_remove_file(temp_path)
                        cleaned_count += 1

                    # ロックファイル自体も削除
                    safe_remove_file(lock_path)
                    cleaned_count += 1

            except (json.JSONDecodeError, IOError) as e:
                # 読み取りエラーの場合は破損と見なし、ファイルを削除
                safe_remove_file(lock_path)
                cleaned_count += 1

    return cleaned_count


def safe_remove_file(file_path):
    """
    ファイルを安全に削除（例外をキャッチして処理継続）

    Args:
        file_path (str): 削除するファイルのパス

    Returns:
        bool: 成功した場合はTrue、失敗した場合はFalse
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
    except Exception as e:
        print(f"ファイル削除中にエラー: {file_path}, {e}")
    return False
