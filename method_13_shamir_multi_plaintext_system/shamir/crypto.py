"""
暗号化と復号の機能

このモジュールでは、シャミア秘密分散法を使用してJSON文書を暗号化および
復号するための機能を提供します。
"""

import os
import json
import base64
import zlib
import secrets
import hmac
import hashlib
import time
from typing import Any, Dict, List, Tuple, Optional, Set, Union
from gmpy2 import mpz

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from .constants import ShamirConstants
from .core import (
    generate_polynomial, evaluate_polynomial, generate_shares,
    lagrange_interpolation, constant_time_select
)


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
        if ARGON2_AVAILABLE:
            # Argon2idを使用（より強力）
            kdf = Argon2(
                length=length,
                salt=salt,
                time_cost=ShamirConstants.ARGON2_TIME_COST,
                memory_cost=ShamirConstants.ARGON2_MEMORY_COST,
                parallelism=ShamirConstants.ARGON2_PARALLELISM,
                type=Argon2Type.ID,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
        else:
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
    except Exception as e:
        # エラーが発生してもPBKDF2を使用
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return key


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


def stage1_map(partition_key: str, all_share_ids: List[int]) -> List[int]:
    """
    第1段階MAP：パーティションマップキーから候補シェアIDを取得

    決定論的に同じパーティションキーからは常に同じシェアID群を生成します。

    Args:
        partition_key: パーティションマップキー
        all_share_ids: 全シェアIDリスト

    Returns:
        選択されたシェアIDリスト
    """
    print(f"DEBUG: stage1_map - starting with partition_key={partition_key[:5]}... and {len(all_share_ids)} share IDs")

    # パーティションキーを正規化
    from .partition import normalize_partition_key, generate_partition_map

    normalized_key = normalize_partition_key(partition_key)

    # パーティションキーから決定論的に割り当てシェアID空間を生成
    selected_ids = generate_partition_map(
        normalized_key,
        ShamirConstants.SHARE_ID_SPACE,
        ShamirConstants.DEFAULT_THRESHOLD
    )

    print(f"DEBUG: stage1_map - seed generated: {selected_ids[0] if selected_ids else 0}...")
    print(f"DEBUG: stage1_map - selected {len(selected_ids)} share IDs")

    # 選択されたIDが全IDリストに存在することを確認（安全対策）
    valid_ids = [id for id in selected_ids if id in all_share_ids]

    # 最低限必要なシェア数が確保できない場合はエラー
    if len(valid_ids) < ShamirConstants.DEFAULT_THRESHOLD:
        raise ValueError(f"有効なシェアIDが不足しています。必要数: {ShamirConstants.DEFAULT_THRESHOLD}, 実際: {len(valid_ids)}")

    return valid_ids


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
                         threshold: int = ShamirConstants.DEFAULT_THRESHOLD) -> Dict[str, Any]:
    """
    JSON文書を暗号化

    Args:
        json_doc: 暗号化するJSON文書
        password: 暗号化パスワード
        partition_key: パーティションマップキー
        threshold: 閾値

    Returns:
        暗号化されたファイルデータ
    """
    print(f"DEBUG: encrypt_json_document - starting with threshold={threshold}")
    # ソルト値を生成
    salt = secrets.token_bytes(16)
    print(f"DEBUG: encrypt_json_document - salt generated")

    # JSONを前処理
    preprocessed_data = preprocess_json_document(json_doc)
    print(f"DEBUG: encrypt_json_document - preprocessed data size: {len(preprocessed_data)} bytes")

    # チャンクに分割
    chunks = split_into_chunks(preprocessed_data)
    print(f"DEBUG: encrypt_json_document - split into {len(chunks)} chunks")

    # シェアID空間を生成 (1からSHARE_ID_SPACE)
    all_share_ids = list(range(1, ShamirConstants.SHARE_ID_SPACE + 1))
    print(f"DEBUG: encrypt_json_document - generated {len(all_share_ids)} share IDs")

    # 使用するシェアIDを選択
    selected_share_ids = select_shares_for_encryption(
        partition_key, password, all_share_ids, salt, threshold
    )
    print(f"DEBUG: encrypt_json_document - selected {len(selected_share_ids)} share IDs for encryption")

    # 各チャンクをシェア化
    all_shares = []
    for chunk_idx, chunk in enumerate(chunks):
        print(f"DEBUG: encrypt_json_document - processing chunk {chunk_idx+1}/{len(chunks)}")
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

    print(f"DEBUG: encrypt_json_document - generated {len(all_shares)} total shares")

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

    print(f"DEBUG: encrypt_json_document - encryption completed")
    return encrypted_file


def select_shares_for_decryption(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> List[Dict[str, Any]]:
    """
    復号に使用するシェアを多段MAPで選択

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を復号します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        encrypted_file: 暗号化されたファイルデータ
        partition_key: パーティションマップキー（AまたはBのいずれか）
        password: 復号化パスワード

    Returns:
        選択されたシェアのリスト（チャンクごとにソート済み）または空のリスト（パスワード誤り）
    """
    # メタデータ取得
    metadata = encrypted_file['metadata']
    threshold = metadata['threshold']
    all_shares = encrypted_file['shares']

    # ソルト値を取得
    salt = base64.urlsafe_b64decode(metadata['salt'])

    # 全シェアIDリストを構築
    all_share_ids = sorted(list(set(share['share_id'] for share in all_shares)))

    # 第1段階MAP: パーティションマップキーによる候補シェア選択
    candidate_ids = stage1_map(partition_key, all_share_ids)

    # 候補シェアから実際のシェアオブジェクトを取得
    candidate_shares = [s for s in all_shares if s['share_id'] in candidate_ids]

    # 第2段階MAP: パスワードによるマッピング
    mappings = stage2_map(password, candidate_ids, salt)

    # チャンク別にシェアを整理
    chunks = {}
    for share in candidate_shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        # シェア値を文字列からmpzに変換
        value = mpz(share['value'])
        chunks[chunk_idx].append((share['share_id'], value))

    # 各チャンクについて、シェアをマッピング値でソートし、閾値分選択
    selected_shares = []
    chunk_indices = sorted(chunks.keys())

    # チャンク数がメタデータの合計チャンク数より少ない場合はパスワードが誤っている可能性が高い
    if not chunks or len(chunk_indices) < metadata['total_chunks']:
        # 空のリストを返すと後続の処理で失敗する
        return []

    # 誤ったパスワードは、ランダムなシェア選択に似た結果になるのでチェック
    # 少なくとも1つのチャンクでシェアが閾値分ないと復号できない
    for chunk_idx in chunk_indices:
        # マッピング値でソート
        sorted_shares = sorted(chunks[chunk_idx], key=lambda s: mappings[s[0]])

        # 閾値分のシェアがあるか確認
        if len(sorted_shares) < threshold:
            # シェアが不足している場合は誤ったパスワードと判断
            return []

        # 閾値分のシェアを選択
        threshold_shares = sorted_shares[:threshold]

        # 選択されたシェアをリストに追加
        for share_id, value in threshold_shares:
            selected_shares.append({
                'chunk_index': chunk_idx,
                'share_id': share_id,
                'value': value
            })

    return selected_shares


def reconstruct_secret(
    shares: List[Dict[str, Any]],
    threshold: int,
    prime: mpz
) -> List[bytes]:
    """
    シェアから秘密（チャンク）を復元

    Args:
        shares: 選択されたシェア
        threshold: 閾値
        prime: 有限体の素数

    Returns:
        復元されたチャンクデータ
    """
    # 共有が空の場合、空のリストを返す
    if not shares:
        return []

    # チャンク別にシェアを整理
    chunks = {}
    for share in shares:
        chunk_idx = share['chunk_index']
        if chunk_idx not in chunks:
            chunks[chunk_idx] = []
        chunks[chunk_idx].append((share['share_id'], share['value']))

    # 各チャンクを復元
    reconstructed_chunks = []
    chunk_indices = sorted(chunks.keys())

    for chunk_idx in chunk_indices:
        chunk_shares = chunks[chunk_idx]

        # シェアが閾値未満の場合は復元できない
        if len(chunk_shares) < threshold:
            # 空のリストを返すと後続の処理でエラーメッセージが生成される
            return []

        # ラグランジュ補間で秘密を復元
        secret = lagrange_interpolation(chunk_shares, prime)

        # 秘密を適切なバイト長に変換
        # mpzからバイト列に変換する際のビット長計算
        bit_length = secret.bit_length()
        byte_length = (bit_length + 7) // 8
        byte_length = max(byte_length, 1)  # 最低1バイト

        # ゼロの場合は特別処理
        if secret == 0:
            chunk_bytes = b'\x00' * ShamirConstants.CHUNK_SIZE
        else:
            # 整数からバイト列に変換
            chunk_bytes = secret.to_bytes(byte_length, 'big')

            # チャンクサイズが一定になるようにパディング/トリミング
            if len(chunk_bytes) < ShamirConstants.CHUNK_SIZE:
                chunk_bytes = chunk_bytes.ljust(ShamirConstants.CHUNK_SIZE, b'\x00')
            elif len(chunk_bytes) > ShamirConstants.CHUNK_SIZE:
                chunk_bytes = chunk_bytes[:ShamirConstants.CHUNK_SIZE]

        reconstructed_chunks.append(chunk_bytes)

    return reconstructed_chunks


def postprocess_json_document(chunks: List[bytes]) -> Any:
    """
    復元されたチャンクからJSON文書を復元

    Args:
        chunks: 復元されたチャンクのリスト

    Returns:
        復元されたJSON文書またはエラー情報を含む辞書
    """
    # チャンクを結合
    data = b''.join(chunks)

    # パディングを除去（後続のヌルバイトを除去）
    data = data.rstrip(b'\x00')

    try:
        # データが空または短すぎる場合はエラー
        if not data or len(data) < 4:
            return {"error": "復号されたデータが無効です", "details": "データが短すぎるか空です"}

        # 一般的なBase64文字以外が含まれている場合、パスワードが誤っている可能性が高い
        # Base64(URL-safe)の文字セット: A-Za-z0-9_-=
        if not all(c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=' for c in data):
            return {"error": "復号されたデータが無効です", "details": "パスワードが誤っている可能性があります"}

        # URL安全なBase64デコード
        try:
            compressed_data = base64.urlsafe_b64decode(data)
        except Exception:
            return {"error": "復号されたデータがBase64形式ではありません", "details": "パスワードが誤っている可能性があります"}

        # 解凍
        try:
            json_bytes = zlib.decompress(compressed_data)
        except zlib.error:
            return {"error": "圧縮データの解凍に失敗しました", "details": "パスワードが誤っている可能性があります"}

        # JSON解析
        try:
            json_data = json.loads(json_bytes.decode('utf-8'))
            return json_data
        except json.JSONDecodeError:
            return {"error": "JSONデータの解析に失敗しました", "details": "パスワードが誤っている可能性があります"}
        except UnicodeDecodeError:
            return {"error": "UTF-8でのデコードに失敗しました", "details": "パスワードが誤っている可能性があります"}

    except Exception as e:
        # エラーが発生した場合、部分的な結果を返す
        # サイドチャネル攻撃対策として例外は投げない
        return {"error": "無効なデータまたはパスワードが誤っています", "details": str(e)}


def try_decrypt_with_both_maps(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> Tuple[bool, Any]:
    """
    パーティションマップキーとパスワードを使って復号を試みる
    エラーが発生しても例外を投げず、成功/失敗を返す

    Args:
        encrypted_file: 暗号化ファイル
        partition_key: パーティションマップキー
        password: パスワード

    Returns:
        (成功フラグ, 復元されたJSON文書または部分データ)
    """
    try:
        # シェアを選択
        selected_shares = select_shares_for_decryption(
            encrypted_file, partition_key, password
        )

        # シェアが空（パスワードが誤っている）場合は失敗
        if not selected_shares:
            return (False, {"error": "パスワードが誤っている可能性があります", "details": "シェアを選択できませんでした"})

        # メタデータから閾値を取得
        threshold = encrypted_file['metadata']['threshold']

        # チャンク別にシェアを集計して閾値を満たしているか確認
        chunk_shares = {}
        for share in selected_shares:
            chunk_idx = share['chunk_index']
            if chunk_idx not in chunk_shares:
                chunk_shares[chunk_idx] = 0
            chunk_shares[chunk_idx] += 1

        # いずれかのチャンクでシェアが閾値未満なら失敗
        for chunk_idx, count in chunk_shares.items():
            if count < threshold:
                return (False, {"error": f"チャンク {chunk_idx} のシェア数が不足しています", "available": count, "required": threshold})

        # シェアから秘密を復元
        reconstructed_chunks = reconstruct_secret(
            selected_shares, threshold, ShamirConstants.PRIME
        )

        # 復元されたチャンクが空の場合は失敗
        if not reconstructed_chunks:
            return (False, {"error": "データの復元に失敗しました", "details": "パスワードが誤っている可能性があります"})

        # 後処理してJSON文書に変換
        json_doc = postprocess_json_document(reconstructed_chunks)

        # 復号結果が有効なJSONかどうかを検証
        if isinstance(json_doc, dict) and 'error' in json_doc:
            # すでにエラー情報が含まれている場合は失敗
            return (False, json_doc)

        # 復号されたデータが有効なJSONかを確認
        try:
            # JSONとして再シリアライズして検証
            json.dumps(json_doc)
            return (True, json_doc)
        except (TypeError, ValueError):
            # JSON変換エラーは無効なデータを示す（おそらく誤ったパスワード）
            return (False, {"error": "復号されたデータが有効なJSONではありません", "details": "パスワードが誤っている可能性があります"})

    except Exception as e:
        # どのような例外が発生しても、サイドチャネル攻撃対策として
        # エラーレスポンスを返す
        return (False, {"error": "復号化に失敗しました", "details": str(e)})


def decrypt_json_document(
    encrypted_file: Dict[str, Any],
    partition_key: str,
    password: str
) -> Any:
    """
    暗号化されたJSONドキュメントを復号

    注意: このシステムは一度に一つの文書のみを処理します。パーティションA用または
    B用のいずれかのパーティションキーを使用して一つの文書を復号します。
    暗号化ファイル自体は複数文書（AとB）のシェアを含んでいる可能性があります。

    Args:
        encrypted_file: 暗号化ファイル
        partition_key: パーティションマップキー（AまたはBのいずれか）
        password: パスワード

    Returns:
        復号されたJSON文書またはエラー情報を含む辞書
    """
    # パスワードが提供されているか確認
    if not password or not isinstance(password, str):
        return {"error": "有効なパスワードが必要です"}

    # パーティションキーが提供されているか確認
    if not partition_key or not isinstance(partition_key, str):
        return {"error": "有効なパーティションキーが必要です"}

    # パスワードが短すぎないか確認（最低限のセキュリティ）
    if len(password) < 4:
        return {"error": "パスワードが短すぎます"}

    # ファイル形式バージョンを確認
    if "header" in encrypted_file and "chunks" in encrypted_file:
        # V2形式の場合
        header = encrypted_file["header"]
        threshold = header["threshold"]
        salt_base64 = header["salt"]
        salt = base64.urlsafe_b64decode(salt_base64)

        # V2形式用のシェア選択処理
        try:
            # シェアID空間を取得
            share_id_space = header.get("share_id_space", ShamirConstants.SHARE_ID_SPACE)

            # 全IDリストを生成 (1からshare_id_space)
            all_share_ids = list(range(1, share_id_space + 1))

            # パーティションに対応するシェアIDを取得
            from .partition import generate_partition_map, normalize_partition_key
            normalized_key = normalize_partition_key(partition_key)
            partition_share_ids = generate_partition_map(
                normalized_key, share_id_space, threshold
            )

            # 第2段階MAP: パスワードによるマッピング
            mappings = stage2_map(password, partition_share_ids, salt)

            # チャンク別にシェアを選択して復元
            reconstructed_chunks = []

            # パスワードバリデーションフラグ
            valid_password = True

            for chunk_idx, chunk_shares in enumerate(encrypted_file["chunks"]):
                # このチャンクに対応するパーティションのシェアを取得
                chunk_partition_shares = []
                for share in chunk_shares:
                    if share["id"] in partition_share_ids:
                        # mpz形式に変換
                        value = mpz(share["value"])
                        chunk_partition_shares.append((share["id"], value))

                # マッピング値でソート
                sorted_shares = sorted(chunk_partition_shares, key=lambda s: mappings[s[0]])

                # 閾値分のシェアを選択
                threshold_shares = sorted_shares[:threshold]

                # シェアが閾値未満の場合は復号失敗
                if len(threshold_shares) < threshold:
                    valid_password = False
                    return {"error": "シェア数が閾値未満です", "available": len(threshold_shares), "required": threshold}

                # ラグランジュ補間で秘密を復元
                secret = lagrange_interpolation(threshold_shares, ShamirConstants.PRIME)

                # 秘密を適切なバイト長に変換
                bit_length = secret.bit_length()
                byte_length = (bit_length + 7) // 8
                byte_length = max(byte_length, 1)  # 最低1バイト

                # ゼロの場合は特別処理
                if secret == 0:
                    chunk_bytes = b'\x00' * ShamirConstants.CHUNK_SIZE
                else:
                    # 整数からバイト列に変換
                    chunk_bytes = secret.to_bytes(byte_length, 'big')

                    # チャンクサイズが一定になるようにパディング/トリミング
                    if len(chunk_bytes) < ShamirConstants.CHUNK_SIZE:
                        chunk_bytes = chunk_bytes.ljust(ShamirConstants.CHUNK_SIZE, b'\x00')
                    elif len(chunk_bytes) > ShamirConstants.CHUNK_SIZE:
                        chunk_bytes = chunk_bytes[:ShamirConstants.CHUNK_SIZE]

                reconstructed_chunks.append(chunk_bytes)

            # チャンクを後処理してJSON文書に変換
            json_doc = postprocess_json_document(reconstructed_chunks)

            # 復号結果が有効なJSONかどうかを確認
            if isinstance(json_doc, dict) and "error" in json_doc:
                # すでにエラー情報が含まれている場合はそのまま返す
                return json_doc

            # 復号結果のバリデーション試行
            try:
                # JSONとして再シリアライズして検証（デコード・エンコード可能か）
                json.dumps(json_doc)
                return json_doc
            except (TypeError, ValueError):
                # JSON変換エラーは無効なデータを示す（おそらく誤ったパスワード）
                return {"error": "復号されたデータが有効なJSONではありません。パスワードが誤っている可能性があります。"}

        except Exception as e:
            # どのような例外が発生しても、サイドチャネル攻撃対策として
            # エラーレスポンスを返す
            return {"error": "復号化に失敗しました", "details": str(e)}
    else:
        # V1形式の場合は既存の関数を利用
        try:
            # まずパスワードとパーティションキーが正しいか検証
            # シェアを選択
            selected_shares = select_shares_for_decryption(
                encrypted_file, partition_key, password
            )

            # シェアが空（選択できない）場合はパスワードが誤っている
            if not selected_shares:
                return {"error": "パスワードまたはパーティションキーが誤っています", "details": "有効なシェアを選択できませんでした"}

            # シェア数を確認
            threshold = encrypted_file['metadata']['threshold']
            chunk_counts = {}
            for share in selected_shares:
                chunk_idx = share['chunk_index']
                if chunk_idx not in chunk_counts:
                    chunk_counts[chunk_idx] = 0
                chunk_counts[chunk_idx] += 1

            # チャンクごとにシェア数が閾値以上あるか確認
            for chunk_idx, count in chunk_counts.items():
                if count < threshold:
                    return {"error": f"チャンク {chunk_idx} のシェア数が閾値未満です", "available": count, "required": threshold}

            # 通常の復号処理
            success, result = try_decrypt_with_both_maps(
                encrypted_file, partition_key, password
            )

            # 成功の場合はJSONデータを返す
            if success:
                # 復号結果のバリデーション試行
                try:
                    # JSONとして再シリアライズして検証（デコード・エンコード可能か）
                    json.dumps(result)
                    return result
                except (TypeError, ValueError):
                    # JSON変換エラーは無効なデータを示す（おそらく誤ったパスワード）
                    return {"error": "復号されたデータが有効なJSONではありません。パスワードが誤っている可能性があります。"}

            # 失敗の場合はエラー情報を返す
            return {"error": "パスワードまたはパーティションキーが誤っています", "details": "復号化に失敗しました"}
        except Exception as e:
            # 例外発生時もエラー情報を返す
            return {"error": "復号化に失敗しました", "details": str(e)}


def load_encrypted_file(file_path: str) -> Dict[str, Any]:
    """
    暗号化ファイルを読み込む

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        暗号化ファイルデータ
    """
    with open(file_path, 'r') as f:
        encrypted_file = json.load(f)

    # シェア値を文字列からmpzに変換
    for share in encrypted_file['shares']:
        if isinstance(share['value'], str):
            share['value'] = mpz(share['value'])

    return encrypted_file


def save_encrypted_file(encrypted_file: Dict[str, Any], output_path: str) -> None:
    """
    暗号化ファイルをディスクに保存

    Args:
        encrypted_file: 暗号化ファイルデータ
        output_path: 出力先のファイルパス
    """
    # mpz値を文字列に変換（JSONシリアライズ可能にするため）
    serializable_file = encrypted_file.copy()
    serializable_shares = []

    for share in encrypted_file['shares']:
        share_copy = share.copy()
        if not isinstance(share_copy['value'], str):
            share_copy['value'] = str(share_copy['value'])
        serializable_shares.append(share_copy)

    serializable_file['shares'] = serializable_shares

    with open(output_path, 'w') as f:
        json.dump(serializable_file, f, ensure_ascii=False)


def secure_decrypt(
    encrypted_file_path: str,
    partition_key: str,
    password: str
) -> Any:
    """
    サイドチャネル攻撃に耐性のある安全な復号処理

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        partition_key: パーティションマップキー
        password: パスワード

    Returns:
        復号されたJSON文書
    """
    # タイミング攻撃対策：処理時間を一定にするための開始時間記録
    start_time = time.time()

    # 暗号化ファイルを読み込む
    encrypted_file = load_encrypted_file(encrypted_file_path)

    # 復号処理を実行
    result = decrypt_json_document(encrypted_file, partition_key, password)

    # タイミング攻撃対策：処理時間を一定に保つ
    # 最低でも1秒の処理時間を保証
    elapsed = time.time() - start_time
    min_time = 1.0  # 最低処理時間（秒）

    if elapsed < min_time:
        time.sleep(min_time - elapsed)

    return result


def is_valid_json_result(result: Any) -> bool:
    """
    復号結果が有効なJSONかどうかを判定

    Args:
        result: 復号結果

    Returns:
        有効なJSONの場合True、それ以外はFalse
    """
    # エラーキーがある場合は無効
    if isinstance(result, dict) and 'error' in result:
        return False

    try:
        # JSONとして再シリアライズ可能か確認
        json.dumps(result)
        return True
    except (TypeError, ValueError):
        return False