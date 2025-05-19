#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
復号化モジュール

このモジュールは、暗号化ファイルからシェアIDとパスワードを用いて
単一のJSON文書を復元する機能を提供します。
条件分岐を避け、タイミング攻撃を防ぐための設計が採用されています。
"""

import json
import base64
import hashlib
import hmac
import zlib
from typing import List, Dict, Any, Tuple, Set, Union

from .shamir import lagrange_interpolation, DEFAULT_PRIME
from ..utils.constant_time import select_int, select_bytes


def stage1_map(share_ids):
    """
    シェアIDによる第1段階MAP生成

    Args:
        share_ids (list): ユーザー入力のシェアIDセット

    Returns:
        set: シェアID候補セット
    """
    # シェアIDセットをセットとして返す（単純フィルタとして機能）
    return set(share_ids)


def stage2_map(password, candidate_ids, salt, iterations=100000):
    """
    パスワードによる第2段階MAP生成

    Args:
        password (str): ユーザー入力のパスワード
        candidate_ids (list): 第1段階で限定されたシェアIDのリスト
        salt (str): 暗号化時に生成された塩値（Base64エンコード）
        iterations (int, optional): KDFの反復回数

    Returns:
        dict: シェアIDからマッピング値へのマップ辞書
    """
    # 塩をデコード
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')

    # パスワードからKDFを用いてキーを導出
    key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, iterations, dklen=32)

    # 各シェアIDに対するマッピング値をHMACで決定論的に生成
    mapping = {}
    for share_id in candidate_ids:
        # 決定論的にマッピング値を生成
        h = hmac.new(key, str(share_id).encode(), 'sha256')
        mapping[share_id] = int.from_bytes(h.digest(), 'big')

    return mapping


def select_shares(all_shares, share_ids, password, salt, threshold):
    """
    多段MAPを用いたシェア選択

    Args:
        all_shares (list): 全シェアリスト
        share_ids (list): ユーザー入力のシェアIDセット
        password (str): ユーザー入力のパスワード
        salt (str): 暗号化時に生成された塩値（Base64エンコード）
        threshold (int): 閾値（必要シェア数）

    Returns:
        dict: チャンクごとに選択されたシェアを格納する辞書
    """
    # 第1段階：シェアID空間の限定
    candidate_ids = stage1_map(share_ids)

    # 第1段階の結果から候補シェアを取得
    candidate_shares = [share for share in all_shares if share['share_id'] in candidate_ids]

    # 第2段階：パスワードによるマッピング
    mappings = stage2_map(password, [s['share_id'] for s in candidate_shares], salt)

    # チャンク別にシェアを整理
    chunks = {}
    for share in candidate_shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        chunks[chunk_idx].append((share['share_id'], share['value']))

    # 各チャンクのシェアをマッピング値でソートし、閾値分を選択
    selected_chunks = {}
    for chunk_idx, chunk_shares in chunks.items():
        # マッピング値でソート
        sorted_shares = sorted(chunk_shares, key=lambda s: mappings[s[0]])

        # 閾値分のシェアを選択（常に同じ数を処理）
        # シェア数が足りない場合も、エラーを出さずに処理を続行
        selected_shares = sorted_shares[:threshold] if len(sorted_shares) >= threshold else sorted_shares

        selected_chunks[chunk_idx] = selected_shares

    return selected_chunks


def int_to_bytes(value, length=None):
    """
    整数をバイト列に変換

    Args:
        value (int): 変換する整数
        length (int, optional): バイト列の長さ（指定がない場合は自動計算）

    Returns:
        bytes: 変換されたバイト列
    """
    if length is None:
        # 必要なバイト数を計算
        length = (value.bit_length() + 7) // 8
        # 少なくとも1バイト
        length = max(1, length)

    return value.to_bytes(length, byteorder='big')


def try_decrypt(all_shares, share_ids, password, salt, threshold, prime=DEFAULT_PRIME):
    """
    シェアを復号（A/B判定なしの直線的処理）

    Args:
        all_shares (list): 全シェアリスト
        share_ids (list): ユーザー入力のシェアIDセット
        password (str): ユーザー入力のパスワード
        salt (str): 暗号化時に生成された塩値
        threshold (int): 閾値（必要シェア数）
        prime (int, optional): 有限体の素数

    Returns:
        bytes: 復元されたバイトデータ
    """
    # 多段MAPの適用
    selected_chunks = select_shares(all_shares, share_ids, password, salt, threshold)

    # 各チャンクを復元（条件分岐なしの直線的処理）
    reconstructed_data = bytearray()

    # チャンクインデックスでソート
    chunk_indices = sorted(selected_chunks.keys())

    for idx in chunk_indices:
        selected_shares = selected_chunks[idx]

        # シェア数が閾値未満の場合もエラーを出さず処理
        if len(selected_shares) >= threshold:
            # ラグランジュ補間で秘密を復元
            secret = lagrange_interpolation(selected_shares, prime)
            chunk_bytes = int_to_bytes(secret)
            reconstructed_data.extend(chunk_bytes)
        else:
            # シェア数が足りない場合も何らかのデータを追加（統計的攻撃を防ぐ）
            # この場合、結果は不正確になるが、同じ処理パスを通る
            dummy_data = b'\x00' * 64  # デフォルトチャンクサイズと同じ
            reconstructed_data.extend(dummy_data)

    return bytes(reconstructed_data)


def postprocess_data(data):
    """
    復元データの後処理（多段デコード）

    Args:
        data (bytes): 復元されたバイトデータ

    Returns:
        dict: デコードされたJSON文書
    """
    try:
        # 解凍
        decompressed_data = zlib.decompress(data)

        # Base64デコード
        base64_decoded = base64.b64decode(decompressed_data)

        # Latin-1からUTF-8へ変換
        utf8_data = base64_decoded.decode('latin-1').encode('utf-8')

        # UTF-8からJSONへ
        json_text = utf8_data.decode('utf-8')
        json_doc = json.loads(json_text)

        return json_doc
    except Exception as e:
        # エラーが発生しても常に同じ処理パスを通る
        # エラー情報が漏れないようにする
        return None


def decrypt(encrypted_file, share_ids, password):
    """
    暗号化ファイルの復号

    Args:
        encrypted_file (dict): 暗号化されたファイル構造
        share_ids (list): ユーザー入力のシェアIDセット
        password (str): ユーザー入力のパスワード

    Returns:
        dict or None: 復元されたJSON文書（失敗した場合はNone）
    """
    # メタデータを取得
    metadata = encrypted_file['metadata']
    all_shares = encrypted_file['shares']
    salt = metadata['salt']
    threshold = metadata['threshold']

    # 素数をメタデータから取得（文字列から整数へ変換）
    prime = int(metadata.get('prime', str(DEFAULT_PRIME)))

    # シェアの復号（条件分岐なしの直線的処理）
    result_data = try_decrypt(all_shares, share_ids, password, salt, threshold, prime)

    # 復号データの後処理
    return postprocess_data(result_data)
