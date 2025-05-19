#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
更新モジュール

このモジュールは、既存の暗号化ファイルの特定文書部分のみを
安全に更新する機能を提供します。
一時作業領域の管理やトランザクション的な処理を含みます。
"""

import os
import json
import time
import uuid
import tempfile
from copy import deepcopy
from typing import List, Dict, Any, Tuple, Set, Union

from .encryption import preprocess_data, split_into_chunks, bytes_to_int, generate_share_for_ids
from .decryption import decrypt
from ..utils.file_utils import create_temp_resources, cleanup_stale_temp_files, safe_remove_file, safe_write_json


def generate_new_shares(json_doc, threshold, share_ids, prime):
    """
    新しいJSON文書からシェアを生成

    Args:
        json_doc (dict): 新しいJSON文書
        threshold (int): 閾値
        share_ids (list): 更新対象のシェアIDセット
        prime (int): 有限体の素数

    Returns:
        tuple: (生成されたシェアのリスト, チャンク数)
    """
    # データの前処理
    data = preprocess_data(json_doc)

    # データをチャンクに分割
    chunks = split_into_chunks(data)

    # 各チャンクをシェア化
    new_shares = []

    for i, chunk in enumerate(chunks):
        secret_int = bytes_to_int(chunk)

        # 素数より大きい場合は処理
        if secret_int >= prime:
            secret_int %= prime

        # チャンクのシェアを生成
        chunk_shares = generate_share_for_ids(secret_int, threshold, share_ids, prime)

        # シェアを追加
        for share_id, value in chunk_shares:
            new_shares.append({
                'chunk_index': i,
                'share_id': share_id,
                'value': value
            })

    return new_shares, len(chunks)


def update_shares(encrypted_file, new_shares, share_ids):
    """
    暗号化ファイル内の特定シェアを更新

    Args:
        encrypted_file (dict): 既存の暗号化ファイル構造
        new_shares (list): 新しいシェアのリスト
        share_ids (list): 更新対象のシェアIDセット

    Returns:
        dict: 更新された暗号化ファイル構造
    """
    # 既存ファイルのディープコピーを作成
    updated_file = deepcopy(encrypted_file)
    share_id_set = set(share_ids)

    # 更新対象外のシェアだけを抽出
    updated_shares = [s for s in updated_file['shares'] if s['share_id'] not in share_id_set]

    # 新しいシェアを追加
    updated_shares.extend(new_shares)

    # 更新されたシェアを設定
    updated_file['shares'] = updated_shares

    return updated_file


def update(encrypted_file, json_doc, password, share_ids, temp_dir=None):
    """
    暗号化ファイルの特定文書部分を更新

    Args:
        encrypted_file (dict): 既存の暗号化ファイル構造
        json_doc (dict): 新しいJSON文書
        password (str): 文書に対応するパスワード
        share_ids (list): 文書に対応するシェアIDセット
        temp_dir (str, optional): 一時ファイルディレクトリ

    Returns:
        dict: 更新された暗号化ファイル構造

    Raises:
        ValueError: 更新処理中にエラーが発生した場合
    """
    if temp_dir is None:
        temp_dir = os.path.join(tempfile.gettempdir(), "shamir_multi_crypt")

    # 一時リソースの確保
    process_uuid, temp_file_path, lock_file_path = create_temp_resources(temp_dir, "update_", ".tmp")

    try:
        # 古い一時ファイルのクリーンアップ
        cleanup_stale_temp_files(temp_dir)

        # メタデータ取得
        metadata = encrypted_file['metadata']
        threshold = metadata['threshold']
        prime = int(metadata.get('prime', '0'))

        # 新しいシェア生成
        new_shares, num_chunks = generate_new_shares(json_doc, threshold, share_ids, prime)

        # 一時ファイルに中間状態を保存
        try:
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                json.dump(new_shares, f)
        except Exception as e:
            raise ValueError(f"一時ファイルへの書き込みに失敗しました: {e}")

        # 対象シェアIDの範囲内のシェアのみを更新
        updated_file = update_shares(encrypted_file, new_shares, share_ids)

        # メタデータ更新（チャンク数は最大値を保持）
        updated_metadata = updated_file['metadata']
        updated_metadata['total_chunks'] = max(updated_metadata.get('total_chunks', 0), num_chunks)

        # 検証: 新しく生成したシェアを使用して復号できるか確認
        try:
            test_decrypt = decrypt(updated_file, share_ids, password)
            if test_decrypt is None:
                raise ValueError("更新後のデータの検証に失敗しました")
        except Exception as e:
            raise ValueError(f"更新後のデータ検証中にエラー発生: {e}")

        # 処理成功時は一時ファイルとロックファイルを削除
        safe_remove_file(temp_file_path)
        safe_remove_file(lock_file_path)

        return updated_file

    except Exception as e:
        # 例外発生時も一時ファイルとロックを確実に解放
        if os.path.exists(temp_file_path):
            safe_remove_file(temp_file_path)
        if os.path.exists(lock_file_path):
            safe_remove_file(lock_file_path)

        # 例外を再送出
        raise ValueError(f"更新処理中にエラーが発生しました: {e}")


def update_file(input_path, output_path, json_doc, password, share_ids, backup=True):
    """
    ファイルに対する更新処理

    Args:
        input_path (str): 入力ファイルパス
        output_path (str): 出力ファイルパス（Noneの場合は上書き）
        json_doc (dict): 新しいJSON文書
        password (str): 文書に対応するパスワード
        share_ids (list): 文書に対応するシェアIDセット
        backup (bool, optional): 既存ファイルのバックアップを作成するか

    Returns:
        bool: 成功した場合はTrue

    Raises:
        FileNotFoundError: 入力ファイルが存在しない場合
        ValueError: 更新処理中にエラーが発生した場合
    """
    # ファイルパスの設定
    if output_path is None:
        output_path = input_path

    # 入力ファイル読み込み
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            encrypted_file = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"ファイルが見つかりません: {input_path}")
    except json.JSONDecodeError:
        raise ValueError(f"JSONの解析に失敗しました: {input_path}")

    # 更新処理
    updated_file = update(encrypted_file, json_doc, password, share_ids)

    # 更新された暗号化ファイルを保存
    return safe_write_json(updated_file, output_path, backup)
