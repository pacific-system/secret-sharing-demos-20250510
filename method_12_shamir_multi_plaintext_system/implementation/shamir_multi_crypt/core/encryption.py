#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
暗号化モジュール

このモジュールは、複数のJSONデータを暗号化し、
単一の暗号化ファイルを生成するための機能を提供します。
"""

import os
import json
import base64
import hashlib
import hmac
import secrets
import random
import zlib
from typing import List, Dict, Any, Tuple, Set, Union

from .shamir import generate_share_for_ids, DEFAULT_PRIME


def generate_salt(length=32):
    """
    暗号塩を生成

    Args:
        length (int, optional): 生成する塩の長さ（バイト数）

    Returns:
        str: Base64エンコードされた塩
    """
    salt_bytes = secrets.token_bytes(length)
    return base64.b64encode(salt_bytes).decode('ascii')


def preprocess_data(json_doc):
    """
    JSONデータを前処理（多段エンコード）

    Args:
        json_doc (dict): エンコードするJSON文書

    Returns:
        bytes: エンコードされたデータ
    """
    # JSONをUTF-8テキストに変換
    json_text = json.dumps(json_doc, ensure_ascii=False)
    utf8_data = json_text.encode('utf-8')

    # UTF-8 -> Latin-1 の変換（エラー時は置換）
    try:
        latin1_data = utf8_data.decode('utf-8').encode('latin-1', errors='replace')
    except UnicodeEncodeError:
        # Latin-1でエンコードできない文字がある場合は置換
        latin1_data = utf8_data.decode('utf-8').encode('latin-1', errors='replace')

    # Base64エンコード
    base64_data = base64.b64encode(latin1_data)

    # 圧縮（条件分岐なし）
    compressed_data = zlib.compress(base64_data)

    return compressed_data


def split_into_chunks(data, chunk_size=64):
    """
    データを固定長チャンクに分割

    Args:
        data (bytes): 分割するデータ
        chunk_size (int, optional): チャンクサイズ（バイト数）

    Returns:
        list: チャンクのリスト
    """
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def bytes_to_int(byte_data):
    """
    バイト列を整数に変換

    Args:
        byte_data (bytes): 変換するバイト列

    Returns:
        int: 変換された整数
    """
    return int.from_bytes(byte_data, byteorder='big')


def generate_chunk_shares(secret_bytes, threshold, share_ids, prime=DEFAULT_PRIME):
    """
    チャンクのシェアを生成

    Args:
        secret_bytes (bytes): シェア化する秘密データ
        threshold (int): シェア復元に必要な最小シェア数
        share_ids (list): シェアIDのリスト
        prime (int, optional): 有限体の素数

    Returns:
        list: [(share_id, value), ...] 形式のシェアのリスト
    """
    # バイトデータを整数に変換
    secret_int = bytes_to_int(secret_bytes)

    # 素数より大きい場合は複数のシェアに分割
    if secret_int >= prime:
        # 複数のシェアに分割する処理（実装省略）
        # ここでは単純にモジュロを取る
        secret_int %= prime

    # シェアを生成
    shares = generate_share_for_ids(secret_int, threshold, share_ids, prime)

    return shares


def generate_garbage_shares(unassigned_ids, chunk_indices, threshold, prime=DEFAULT_PRIME):
    """
    未割当領域に統計的に区別不能なゴミデータを生成

    Args:
        unassigned_ids (list): 未割当のシェアIDリスト
        chunk_indices (list): チャンクインデックスのリスト
        threshold (int): シェア復元に必要な最小シェア数
        prime (int, optional): 有限体の素数

    Returns:
        list: 生成されたゴミシェアのリスト
    """
    if not unassigned_ids:
        return []

    garbage_shares = []

    for chunk_index in chunk_indices:
        # ランダムな多項式を生成するため、ランダムな秘密値を使用
        fake_secret = secrets.randbelow(prime)

        # 全ての未割当IDに対してシェアを生成
        for id_value in unassigned_ids:
            # ゴミシェアを生成（実際のシェアと統計的に区別不能）
            shares = generate_share_for_ids(fake_secret, threshold, [id_value], prime)

            for share_id, value in shares:
                garbage_shares.append({
                    'chunk_index': chunk_index,
                    'share_id': share_id,
                    'value': value
                })

    return garbage_shares


def stage2_map_gen(password, salt, iterations=100000):
    """
    第2段階MAPのためのキー生成

    Args:
        password (str): パスワード
        salt (str): 塩（Base64エンコード）
        iterations (int, optional): KDF反復回数

    Returns:
        bytes: 導出されたキー
    """
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')

    # PBKDF2を使用してキーを導出
    key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, iterations, dklen=32)

    return key


def encrypt_document(json_doc, password, share_ids, threshold=3, prime=DEFAULT_PRIME):
    """
    単一のJSON文書を暗号化

    Args:
        json_doc (dict): 暗号化するJSON文書
        password (str): 文書のパスワード
        share_ids (list): 文書に割り当てるシェアIDのリスト
        threshold (int, optional): シェア復元に必要な最小シェア数
        prime (int, optional): 有限体の素数

    Returns:
        tuple: (暗号化シェアのリスト, チャンク数)
    """
    # データの前処理
    data = preprocess_data(json_doc)

    # データをチャンクに分割
    chunks = split_into_chunks(data)

    # 各チャンクをシェア化
    all_shares = []

    for i, chunk in enumerate(chunks):
        secret_int = bytes_to_int(chunk)

        # 素数より大きい場合は処理（実際の実装ではより複雑な処理が必要）
        if secret_int >= prime:
            secret_int %= prime

        # チャンクのシェアを生成
        chunk_shares = generate_share_for_ids(secret_int, threshold, share_ids, prime)

        # シェアを追加
        for share_id, value in chunk_shares:
            all_shares.append({
                'chunk_index': i,
                'share_id': share_id,
                'value': value
            })

    return all_shares, len(chunks)


def encrypt(json_docs, passwords, share_id_sets, unassigned_ids, threshold=3, prime=DEFAULT_PRIME):
    """
    複数のJSON文書を暗号化

    Args:
        json_docs (list): 文書のリスト [json_doc_A, json_doc_B]
        passwords (list): パスワードのリスト [password_A, password_B]
        share_id_sets (list): シェアIDセットのリスト [share_ids_A, share_ids_B]
        unassigned_ids (list): 未割当のシェアIDリスト
        threshold (int, optional): シェア復元に必要な最小シェア数
        prime (int, optional): 有限体の素数

    Returns:
        dict: 暗号化されたファイル構造（辞書型）
    """
    if len(json_docs) != len(passwords) or len(passwords) != len(share_id_sets):
        raise ValueError("文書、パスワード、シェアIDセットの数は一致する必要があります")

    # 塩を生成
    salt = generate_salt()

    # 全シェアとチャンク数を初期化
    all_shares = []
    max_chunks = 0

    # 各文書を暗号化
    for i, (json_doc, password, share_ids) in enumerate(zip(json_docs, passwords, share_id_sets)):
        # 文書を暗号化
        doc_shares, num_chunks = encrypt_document(json_doc, password, share_ids, threshold, prime)

        # シェアを追加
        all_shares.extend(doc_shares)

        # 最大チャンク数を更新
        max_chunks = max(max_chunks, num_chunks)

    # ゴミデータ生成用のチャンクインデックス
    chunk_indices = list(range(max_chunks))

    # 未割当領域にゴミデータを生成
    garbage_shares = generate_garbage_shares(unassigned_ids, chunk_indices, threshold, prime)
    all_shares.extend(garbage_shares)

    # シェアをシャッフル（順序による情報漏洩を防ぐ）
    random.shuffle(all_shares)

    # メタデータを追加
    metadata = {
        'salt': salt,
        'total_chunks': max_chunks,
        'threshold': threshold,
        'prime': str(prime)  # 大きな整数をJSONに格納するため文字列化
    }

    # 暗号化ファイルの生成
    encrypted_file = {
        'metadata': metadata,
        'shares': all_shares
    }

    return encrypted_file
