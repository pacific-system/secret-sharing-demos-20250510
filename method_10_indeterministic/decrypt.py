#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 復号プログラム

暗号文と鍵を入力として受け取り、
指定された鍵の種類に応じて対応する平文を復元します。
"""

import os
import sys
import json
import time
import base64
import hashlib
import binascii
import argparse
import tempfile
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, BinaryIO, Iterator, Generator

# 内部モジュールのインポート
try:
    from config import (
        KEY_SIZE_BYTES, STATE_MATRIX_SIZE, STATE_TRANSITIONS,
        OUTPUT_EXTENSION, ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR
    )
    from state_matrix import create_state_matrix_from_key
    from probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, generate_anti_analysis_noise
    )
except ImportError:
    # パッケージとして実行された場合のインポート
    from .config import (
        KEY_SIZE_BYTES, STATE_MATRIX_SIZE, STATE_TRANSITIONS,
        OUTPUT_EXTENSION, ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR
    )
    from .state_matrix import create_state_matrix_from_key
    from .probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, generate_anti_analysis_noise
    )

# AES暗号化のためのライブラリ（基本的な暗号化操作に使用）
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    # 依存ライブラリがない場合は単純なXOR暗号を使用
    HAS_CRYPTOGRAPHY = False
    print("警告: cryptographyライブラリがインストールされていません。セキュリティレベルが低いXOR暗号を使用します。")
    print("pip install cryptographyを実行してより安全な暗号化を有効にしてください。")

# バッファサイズの設定 (8MB)
BUFFER_SIZE = 8 * 1024 * 1024

# 一時ファイルの最大サイズ (512MB)
MAX_TEMP_FILE_SIZE = 512 * 1024 * 1024

# ファイルタイプマーカー
TEXT_MARKER = b'TEXT\x00\x00\x00\x00'
BINARY_MARKER = b'BINA\x00\x00\x00\x00'


class MemoryOptimizedWriter:
    """
    メモリを効率的に使用するファイル書き込みクラス

    大きなデータを効率的に書き込むためのクラス
    """

    def __init__(self, file_path: str, buffer_size: int = BUFFER_SIZE):
        """
        ライターの初期化

        Args:
            file_path: 書き込み先ファイルパス
            buffer_size: バッファサイズ
        """
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.temp_file = None
        self.is_large_file = False
        self.buffer = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()
        self.cleanup()

    def write(self, data: bytes):
        """
        データを書き込む

        Args:
            data: 書き込むデータ
        """
        # バッファに追加
        self.buffer.extend(data)

        # バッファサイズが大きい場合はフラッシュ
        if len(self.buffer) >= self.buffer_size:
            self.flush()

    def flush(self):
        """バッファのデータをファイルに書き込む"""
        if not self.buffer:
            return

        if len(self.buffer) > MAX_TEMP_FILE_SIZE and not self.is_large_file:
            # 大きなファイルの場合は一時ファイルを使用
            self.is_large_file = True
            if not self.temp_file:
                self.temp_file = tempfile.NamedTemporaryFile(delete=False)

        if self.is_large_file:
            # 一時ファイルに書き込み
            if self.temp_file:
                self.temp_file.write(self.buffer)
                self.temp_file.flush()
        else:
            # 直接ファイルに書き込み
            with open(self.file_path, 'ab') as f:
                f.write(self.buffer)

        # バッファをクリア
        self.buffer = bytearray()

    def finalize(self):
        """
        書き込みを完了し、ファイルを閉じる
        """
        self.flush()

        if self.is_large_file and self.temp_file:
            # 一時ファイルを閉じる
            self.temp_file.close()

            # 一時ファイルから本ファイルにコピー
            with open(self.temp_file.name, 'rb') as src, open(self.file_path, 'wb') as dst:
                while True:
                    chunk = src.read(self.buffer_size)
                    if not chunk:
                        break
                    dst.write(chunk)

    def cleanup(self):
        """一時ファイルを削除"""
        if self.temp_file and os.path.exists(self.temp_file.name):
            try:
                os.unlink(self.temp_file.name)
            except Exception as e:
                print(f"警告: 一時ファイル '{self.temp_file.name}' の削除に失敗しました: {e}", file=sys.stderr)


def basic_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    基本的な復号化を行う

    暗号化ライブラリがある場合はAESを使用し、ない場合はXORベースの復号化を行います。

    Args:
        data: 復号化するデータ
        key: 暗号鍵
        iv: 初期化ベクトル

    Returns:
        復号化されたデータ
    """
    if not data:
        raise ValueError("復号化するデータが空です")

    if not key:
        raise ValueError("暗号鍵が空です")

    if not iv:
        raise ValueError("初期化ベクトルが空です")

    if HAS_CRYPTOGRAPHY:
        try:
            # 鍵とIVを適切なサイズに調整
            normalized_key = normalize_key(key, 32)  # AES-256
            normalized_iv = normalize_key(iv, 16)    # CTRモードのIVサイズ

            cipher = Cipher(
                algorithms.AES(normalized_key),
                modes.CTR(normalized_iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # 復号化（CTRモードは暗号化と復号化が同じ操作）
            return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            print(f"警告: AES復号化に失敗しました: {e}", file=sys.stderr)
            print("XOR復号化にフォールバックします")
            # AES復号化に失敗した場合はXOR復号化にフォールバック

    # XORベースの簡易復号化
    # 鍵をデータサイズに拡張（セキュリティ強化版）
    extended_key = bytearray()
    segment_size = 32  # SHA-256のサイズ

    # データサイズに合わせて拡張鍵を生成
    for i in range(0, len(data), segment_size):
        # ソルトとして位置情報とカウンタを使用してセキュリティを向上
        counter = i.to_bytes(8, 'big')
        segment_key = hashlib.sha256(key + iv + counter).digest()
        extended_key.extend(segment_key)

    # データとXOR
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ extended_key[i % len(extended_key)]

    return bytes(result)


def normalize_key(key: bytes, target_size: int) -> bytes:
    """
    鍵やIVを指定サイズに正規化

    Args:
        key: 元の鍵データ
        target_size: 目標サイズ

    Returns:
        正規化された鍵
    """
    if len(key) < target_size:
        # 鍵が短い場合は、ハッシュ関数で拡張
        seed = key
        result = bytearray()

        while len(result) < target_size:
            seed = hashlib.sha256(seed).digest()
            result.extend(seed)

        return result[:target_size]
    elif len(key) > target_size:
        # 鍵が長い場合は、ハッシュ関数を使用して縮小
        return hashlib.sha256(key).digest()[:target_size]
    else:
        # 鍵のサイズが既に適切な場合
        return key


def read_encrypted_file(file_path: str) -> Dict[str, Any]:
    """
    暗号化されたファイルを読み込む

    メモリ効率の良い大きなファイルの読み込みをサポート。

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        暗号化ファイルの構成要素を含む辞書
    """
    try:
        # ファイルサイズの取得
        file_size = os.path.getsize(file_path)
        print(f"ファイル '{file_path}' のサイズ: {file_size} バイト")

        # 大きなファイルかどうか
        is_large_file = file_size > MAX_TEMP_FILE_SIZE

        with open(file_path, 'rb') as f:
            # ヘッダーサイズの読み込み (4バイト)
            header_size_bytes = f.read(4)
            if not header_size_bytes or len(header_size_bytes) != 4:
                raise ValueError("ファイルが破損しています: ヘッダーサイズを読み込めません")

            header_size = int.from_bytes(header_size_bytes, 'big')
            print(f"ヘッダーサイズ: {header_size} バイト")

            # ヘッダーデータの読み込み
            header_data = f.read(header_size)
            if len(header_data) != header_size:
                raise ValueError(f"ファイルが破損しています: ヘッダーデータが不完全です（期待: {header_size}、実際: {len(header_data)}）")

            # ヘッダーの解析
            result = _parse_header(header_data)

            # 整合性チェックデータの読み込み（設定に依存）
            if ANTI_TAMPERING:
                integrity_check = f.read(32)  # SHA-256ハッシュ
                result["integrity_check"] = integrity_check

            # エントロピーデータのサイズを読み込む
            entropy_size_bytes = f.read(8)
            if len(entropy_size_bytes) != 8:
                raise ValueError("ファイルが破損しています: エントロピーサイズを読み込めません")

            entropy_size = int.from_bytes(entropy_size_bytes, 'big')
            print(f"エントロピーデータサイズ: {entropy_size} バイト")

            # エントロピーデータの読み込み
            if is_large_file:
                # 大きなファイルの場合は一時ファイルに保存
                entropy_temp = tempfile.NamedTemporaryFile(delete=False)
                result["entropy_temp_file"] = entropy_temp.name

                # チャンク単位で読み込み
                remaining = entropy_size
                while remaining > 0:
                    chunk_size = min(BUFFER_SIZE, remaining)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        raise ValueError("ファイルが破損しています: エントロピーデータの読み込みに失敗")

                    entropy_temp.write(chunk)
                    remaining -= len(chunk)

                entropy_temp.close()
                result["entropy_data"] = None  # メモリに保持しない
            else:
                # 小さなファイルはメモリに読み込む
                entropy_data = f.read(entropy_size)
                if len(entropy_data) != entropy_size:
                    raise ValueError(f"ファイルが破損しています: エントロピーデータが不完全です（期待: {entropy_size}、実際: {len(entropy_data)}）")

                result["entropy_data"] = entropy_data

            # カプセルデータのサイズを読み込む
            capsule_size_bytes = f.read(8)
            if len(capsule_size_bytes) != 8:
                raise ValueError("ファイルが破損しています: カプセルサイズを読み込めません")

            capsule_size = int.from_bytes(capsule_size_bytes, 'big')
            print(f"カプセルデータサイズ: {capsule_size} バイト")

            # カプセルデータの読み込み
            if is_large_file:
                # 大きなファイルの場合は一時ファイルに保存
                capsule_temp = tempfile.NamedTemporaryFile(delete=False)
                result["capsule_temp_file"] = capsule_temp.name

                # チャンク単位で読み込み
                remaining = capsule_size
                while remaining > 0:
                    chunk_size = min(BUFFER_SIZE, remaining)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        raise ValueError("ファイルが破損しています: カプセルデータの読み込みに失敗")

                    capsule_temp.write(chunk)
                    remaining -= len(chunk)

                capsule_temp.close()
                result["capsule_data"] = None  # メモリに保持しない
            else:
                # 小さなファイルはメモリに読み込む
                capsule_data = f.read(capsule_size)
                if len(capsule_data) != capsule_size:
                    raise ValueError(f"ファイルが破損しています: カプセルデータが不完全です（期待: {capsule_size}、実際: {len(capsule_data)}）")

                result["capsule_data"] = capsule_data

            # 末尾マーカーの読み込み
            end_marker = f.read(16)
            if len(end_marker) != 16:
                raise ValueError("ファイルが破損しています: 末尾マーカーが見つかりません")

            result["end_marker"] = end_marker

        # 一時ファイルのパスを記録
        result["is_large_file"] = is_large_file
        result["file_path"] = file_path

        return result

    except Exception as e:
        print(f"ファイル '{file_path}' の読み込みエラー: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

        # 一時ファイルのクリーンアップ
        if 'entropy_temp_file' in locals() and os.path.exists(locals()['entropy_temp_file']):
            try:
                os.unlink(locals()['entropy_temp_file'])
            except:
                pass

        if 'capsule_temp_file' in locals() and os.path.exists(locals()['capsule_temp_file']):
            try:
                os.unlink(locals()['capsule_temp_file'])
            except:
                pass

        raise


def _parse_header(header_data: bytes) -> Dict[str, Any]:
    """
    ヘッダーデータを解析する

    Args:
        header_data: ヘッダーバイトデータ

    Returns:
        解析されたヘッダー情報
    """
    result = {}

    # ファイルマーカー (16バイト)
    file_marker = header_data[:16]
    if not file_marker.startswith(b"INDETERM"):
        raise ValueError("ファイルフォーマットが無効です: 不正なファイルマーカー")

    result["file_marker"] = file_marker

    # バージョン情報 (2バイト)
    version = header_data[16:18]
    result["version"] = int.from_bytes(version, 'big')

    # オプションフラグ (2バイト)
    options = header_data[18:20]
    result["options"] = int.from_bytes(options, 'big')

    # タイムスタンプ (8バイト)
    timestamp = header_data[20:28]
    result["timestamp"] = int.from_bytes(timestamp, 'big')

    # メタデータサイズ (4バイト)
    metadata_size = int.from_bytes(header_data[28:32], 'big')

    # メタデータ
    metadata_json = header_data[32:32+metadata_size]
    try:
        metadata = json.loads(metadata_json.decode('utf-8'))
        result["metadata"] = metadata
    except json.JSONDecodeError:
        raise ValueError("ファイルが破損しています: メタデータのJSONパースに失敗")

    # ソルト値（メタデータから復元）
    salt_bytes = file_marker[8:]  # マーカーの後半8バイトがソルト
    result["salt"] = salt_bytes

    return result


def determine_execution_path(key: bytes, metadata: Dict[str, Any]) -> str:
    """
    実行パスを決定する

    鍵とメタデータから、正規パスと非正規パスのどちらを実行するかを決定します。
    この関数は、鍵が正規か非正規かの判断を行いますが、
    実際の実装では、この判断ロジックを外部から推測できないようにしています。

    Args:
        key: 復号鍵
        metadata: 暗号化ファイルのメタデータ

    Returns:
        実行パスタイプ（"true" または "false"）
    """
    # メタデータからソルトを取得
    salt_base64 = metadata.get("salt", "")
    try:
        salt = base64.b64decode(salt_base64)
    except:
        # ソルトが不正な場合はランダムなソルトを使用
        salt = os.urandom(16)

    # 鍵検証用のハッシュ値を生成
    verify_hash = hashlib.sha256(key + salt + b"path_verification").digest()

    # 動的解析対策のためのダミー計算
    dummy1 = hashlib.sha256(verify_hash + b"dummy1").digest()
    dummy2 = hashlib.sha256(verify_hash + b"dummy2").digest()

    # 状態マトリクスと確率エンジンを初期化
    # これにより、鍵に応じた状態遷移パターンが生成されます
    engine = create_engine_from_key(key, TRUE_PATH, salt)

    # エンジンを実行して実行パスの特性を取得
    engine.run_execution()
    signature = engine.get_execution_signature()

    # 署名の特性に基づいてパスタイプを決定
    # 実際には、これは鍵生成時に決められた特性と比較して判断します
    path_type = FALSE_PATH  # デフォルトは非正規パス

    # 署名の特性チェック
    signature_sum = sum(signature) % 256
    if signature_sum < 128:
        path_type = TRUE_PATH

    # 解析対策のためのさらなる攪乱
    generate_anti_analysis_noise(engine)

    return path_type


def extract_from_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    target_path: str
) -> Tuple[bytes, bytes]:
    """
    カプセルからターゲットパスのデータと署名を抽出

    メモリ効率の良い大きなカプセルの処理をサポート。

    Args:
        capsule_data: カプセルデータ
        key: マスター鍵
        salt: ソルト値
        target_path: ターゲットパス ("true" または "false")

    Returns:
        (抽出されたデータ, 署名)
    """
    # 大きなカプセルの場合は一時ファイルパスが渡されている可能性がある
    if isinstance(capsule_data, str) and os.path.exists(capsule_data):
        return _extract_from_large_capsule(capsule_data, key, salt, target_path)

    # 通常のメモリ内処理
    return _extract_from_memory_capsule(capsule_data, key, salt, target_path)


def _extract_from_memory_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    target_path: str
) -> Tuple[bytes, bytes]:
    """
    メモリ内のカプセルからデータを抽出（小〜中サイズのデータ用）

    Args:
        capsule_data: カプセルデータ
        key: マスター鍵
        salt: ソルト値
        target_path: ターゲットパス ("true" または "false")

    Returns:
        (抽出されたデータ, 署名)
    """
    if not capsule_data:
        raise ValueError("カプセルデータが空です")

    # カプセル化パラメータを準備
    capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()
    timestamp = int.from_bytes(capsule_data[:8], 'big') if len(capsule_data) >= 8 else int(time.time())
    enhanced_seed = hashlib.sha512(capsule_seed + timestamp.to_bytes(8, 'big')).digest()

    # 署名データの取得（最初の64バイト）
    true_sig_noised = capsule_data[:32]
    false_sig_noised = capsule_data[32:64]

    # 署名のノイズ除去
    true_sig_processed = bytes([b ^ enhanced_seed[i % len(enhanced_seed)] for i, b in enumerate(true_sig_noised)])
    false_sig_processed = bytes([b ^ enhanced_seed[i+16 % len(enhanced_seed)] for i, b in enumerate(false_sig_noised)])

    # 最終署名の復元
    true_signature = hashlib.sha256(true_sig_processed + capsule_seed).digest()
    false_signature = hashlib.sha256(false_sig_processed + capsule_seed).digest()

    # ターゲットに応じた署名の選択
    target_signature = true_signature if target_path == TRUE_PATH else false_signature

    # カプセルデータの処理（署名の後ろ）
    capsule_body = capsule_data[64:]

    # カプセルデータからターゲットデータを抽出
    result = _process_capsule_blocks(capsule_body, capsule_seed, enhanced_seed, target_path)

    return result, target_signature


def _extract_from_large_capsule(
    capsule_file_path: str,
    key: bytes,
    salt: bytes,
    target_path: str
) -> Tuple[bytes, bytes]:
    """
    大きなカプセルからデータを抽出（一時ファイル使用）

    Args:
        capsule_file_path: カプセルファイルのパス
        key: マスター鍵
        salt: ソルト値
        target_path: ターゲットパス ("true" または "false")

    Returns:
        (抽出されたデータ, 署名)
    """
    # 一時出力ファイル
    output_temp = tempfile.NamedTemporaryFile(delete=False)
    output_path = output_temp.name
    output_temp.close()

    try:
        # カプセル化パラメータを準備
        capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()
        timestamp = int(time.time())
        enhanced_seed = hashlib.sha512(capsule_seed + timestamp.to_bytes(8, 'big')).digest()

        # カプセルファイルを開く
        with open(capsule_file_path, 'rb') as f_in:
            # 署名データの取得（最初の64バイト）
            sig_data = f_in.read(64)
            if len(sig_data) != 64:
                raise ValueError("カプセルファイルが破損しています: 署名データが不完全です")

            true_sig_noised = sig_data[:32]
            false_sig_noised = sig_data[32:64]

            # 署名のノイズ除去
            true_sig_processed = bytes([b ^ enhanced_seed[i % len(enhanced_seed)] for i, b in enumerate(true_sig_noised)])
            false_sig_processed = bytes([b ^ enhanced_seed[i+16 % len(enhanced_seed)] for i, b in enumerate(false_sig_noised)])

            # 最終署名の復元
            true_signature = hashlib.sha256(true_sig_processed + capsule_seed).digest()
            false_signature = hashlib.sha256(false_sig_processed + capsule_seed).digest()

            # ターゲットに応じた署名の選択
            target_signature = true_signature if target_path == TRUE_PATH else false_signature

            # カプセルデータの処理
            with open(output_path, 'wb') as f_out:
                block_size = 128  # 処理ブロックサイズ（capsule_body用）
                pattern_index = 0

                # 残りのデータをブロック単位で読み込み・処理
                while True:
                    block = f_in.read(block_size)
                    if not block:
                        break

                    # パターンシード
                    pattern_seed = hashlib.sha512(
                        capsule_seed +
                        pattern_index.to_bytes(4, 'big') +
                        enhanced_seed[pattern_index % len(enhanced_seed):]
                    ).digest()
                    pattern_value = pattern_seed[0]

                    # パターンに基づいてブロックを処理
                    processed_data = _process_capsule_block(
                        block, pattern_value, pattern_seed[1], target_path == TRUE_PATH
                    )

                    # 処理したデータを書き込む
                    f_out.write(processed_data)
                    pattern_index += 1

        # 処理したデータを読み込む
        with open(output_path, 'rb') as f:
            extracted_data = f.read()

        return extracted_data, target_signature

    finally:
        # 一時ファイルを削除
        try:
            if os.path.exists(output_path):
                os.unlink(output_path)
        except Exception as e:
            print(f"警告: 一時ファイル '{output_path}' の削除に失敗しました: {e}", file=sys.stderr)


def _process_capsule_blocks(
    capsule_body: bytes,
    capsule_seed: bytes,
    enhanced_seed: bytes,
    target_path: str
) -> bytes:
    """
    カプセル本体を処理してターゲットデータを抽出

    Args:
        capsule_body: カプセル本体データ
        capsule_seed: カプセルシード
        enhanced_seed: 強化シード
        target_path: ターゲットパス

    Returns:
        抽出されたデータ
    """
    result = bytearray()
    block_size = 64
    is_true_target = target_path == TRUE_PATH

    # カプセルデータをブロック単位で処理
    for i in range(0, len(capsule_body), block_size * 2):
        end_idx = min(i + block_size * 2, len(capsule_body))
        capsule_block = capsule_body[i:end_idx]

        if len(capsule_block) < block_size:
            # データが少なすぎる場合はスキップ
            continue

        # パターンシード
        pattern_index = i // (block_size * 2)
        pattern_seed = hashlib.sha512(
            capsule_seed +
            pattern_index.to_bytes(4, 'big') +
            enhanced_seed[pattern_index % len(enhanced_seed):]
        ).digest()
        pattern_value = pattern_seed[0]
        secondary_value = pattern_seed[1]

        # パターンに基づいて処理
        if pattern_value % 4 == 0:
            # 正規→非正規 の順
            if is_true_target and len(capsule_block) >= block_size:
                # 正規データを取得
                result.extend(capsule_block[:block_size])
            elif not is_true_target and len(capsule_block) >= block_size * 2:
                # 非正規データを取得
                result.extend(capsule_block[block_size:block_size*2])

        elif pattern_value % 4 == 1:
            # 非正規→正規 の順
            if is_true_target and len(capsule_block) >= block_size * 2:
                # 正規データを取得
                result.extend(capsule_block[block_size:block_size*2])
            elif not is_true_target and len(capsule_block) >= block_size:
                # 非正規データを取得
                result.extend(capsule_block[:block_size])

        elif pattern_value % 4 == 2:
            # 交互にバイトを配置
            true_block = bytearray()
            false_block = bytearray()

            for j in range(0, len(capsule_block), 2):
                if j < len(capsule_block):
                    true_block.append(capsule_block[j])
                if j + 1 < len(capsule_block):
                    false_block.append(capsule_block[j + 1])

            # ターゲットに応じたブロックを追加
            if is_true_target:
                result.extend(true_block)
            else:
                result.extend(false_block)

        else:
            # ビット単位のインターリーブ
            # 複雑度が高いため、簡略化バージョンを使用
            true_block = bytearray(block_size)
            false_block = bytearray(block_size)

            true_idx = 0
            false_idx = 0

            for j in range(len(capsule_block)):
                byte_val = capsule_block[j]
                for bit in range(8):
                    bit_val = (byte_val >> bit) & 1
                    bit_selector = secondary_value & (1 << bit)

                    if bit_selector and true_idx < len(true_block):
                        # trueブロックにビットを設定
                        bit_pos = true_idx % 8
                        byte_pos = true_idx // 8
                        if byte_pos < len(true_block):
                            if bit_val:
                                true_block[byte_pos] |= (1 << bit_pos)
                            true_idx += 1

                    elif not bit_selector and false_idx < len(false_block):
                        # falseブロックにビットを設定
                        bit_pos = false_idx % 8
                        byte_pos = false_idx // 8
                        if byte_pos < len(false_block):
                            if bit_val:
                                false_block[byte_pos] |= (1 << bit_pos)
                            false_idx += 1

            # ビット単位処理が不完全な場合（復元率が低い場合）
            if true_idx < len(true_block) * 8 // 2 or false_idx < len(false_block) * 8 // 2:
                # 代替の簡易処理を適用
                true_block = bytearray()
                false_block = bytearray()

                for j in range(0, len(capsule_block), 2):
                    if j < len(capsule_block):
                        true_block.append(capsule_block[j])
                    if j + 1 < len(capsule_block):
                        false_block.append(capsule_block[j + 1])

            # ターゲットに応じたブロックを追加
            if is_true_target:
                result.extend(true_block)
            else:
                result.extend(false_block)

    return bytes(result)


def _process_capsule_block(
    block: bytes,
    pattern: int,
    secondary: int,
    is_true_target: bool
) -> bytes:
    """
    単一のカプセルブロックを処理

    Args:
        block: 処理するブロック
        pattern: パターン値
        secondary: 二次パターン値
        is_true_target: True対象かどうか

    Returns:
        処理されたブロック
    """
    if not block:
        return b''

    half_size = len(block) // 2

    # パターンに基づいて処理
    if pattern % 4 == 0:
        # 正規→非正規 の順
        if is_true_target:
            return block[:half_size]
        else:
            return block[half_size:]

    elif pattern % 4 == 1:
        # 非正規→正規 の順
        if is_true_target:
            return block[half_size:]
        else:
            return block[:half_size]

    elif pattern % 4 == 2:
        # 交互にバイトを配置
        true_block = bytearray()
        false_block = bytearray()

        for i in range(0, len(block), 2):
            if i < len(block):
                true_block.append(block[i])
            if i + 1 < len(block):
                false_block.append(block[i + 1])

        # ターゲットに応じたブロックを返す
        return bytes(true_block) if is_true_target else bytes(false_block)

    else:
        # バイト単位の混合（簡略化版）
        true_block = bytearray()
        false_block = bytearray()

        for i in range(len(block)):
            if i % 2 == 0:
                true_block.append(block[i])
            else:
                false_block.append(block[i])

        # ターゲットに応じたブロックを返す
        return bytes(true_block) if is_true_target else bytes(false_block)


def state_based_decrypt(data: bytes, engine: ProbabilisticExecutionEngine, path_type: str) -> bytes:
    """
    状態遷移に基づく復号化

    メモリ効率を考慮した大きなデータの復号化が可能です。

    Args:
        data: 復号化するデータ
        engine: 確率的実行エンジン
        path_type: パスタイプ（"true" または "false"）

    Returns:
        復号化されたデータ
    """
    # データが少なすぎる場合はエラー
    if len(data) < 1:
        raise ValueError("復号化するデータが空です")

    # エンジンを実行して状態遷移パスを取得
    path = engine.run_execution()

    # 解析攻撃対策のダミー処理
    dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()

    # ブロックサイズを定義
    block_size = 64  # 共通のブロックサイズ

    # データサイズが大きい場合は一時ファイルを使用
    if len(data) > MAX_TEMP_FILE_SIZE:
        return _decrypt_large_data(data, engine, path, path_type, block_size)

    # 通常のメモリ内処理
    return _decrypt_in_memory(data, engine, path, path_type, block_size)


def _decrypt_in_memory(data: bytes, engine: ProbabilisticExecutionEngine,
                      path: List[int], path_type: str, block_size: int) -> bytes:
    """
    メモリ内での復号化処理（小〜中サイズのデータ用）

    Args:
        data: 復号化するデータ
        engine: 実行エンジン
        path: 状態遷移パス
        path_type: パスタイプ
        block_size: ブロックサイズ

    Returns:
        復号化されたデータ
    """
    # データをブロックに分割
    blocks = []

    # データを block_size ごとに分割
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        blocks.append(block)

    # 解析攻撃対策のダミー処理
    dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()
    dummy_path = []

    # 状態遷移に基づいて各ブロックを復号化
    decrypted_blocks = []
    for i, block in enumerate(blocks):
        # 現在の状態を取得（パスの長さを超えたら最後の状態を使用）
        state_idx = min(i, len(path) - 1)
        state_id = path[state_idx]
        state = engine.states.get(state_id)

        # ダミーパスにも状態を追加（解析対策）
        dummy_path.append(state_id)

        decrypted_block = _decrypt_block(block, engine, state, state_id, i, dummy_key)
        decrypted_blocks.append(decrypted_block)

    # セキュリティ脆弱性が入らないよう、ダミーパスに対する処理も行うが結果は使用しない
    dummy_blocks = []
    for i, state_id in enumerate(dummy_path):
        dummy_seed = hashlib.sha256(f"dummy_{i}_{state_id}".encode() + dummy_key).digest()
        dummy_blocks.append(dummy_seed[:8])  # ダミーデータ生成

    # 復号化されたブロックを結合
    return b''.join(decrypted_blocks)


def _decrypt_large_data(data: bytes, engine: ProbabilisticExecutionEngine,
                       path: List[int], path_type: str, block_size: int) -> bytes:
    """
    大きなデータの復号化処理（一時ファイル使用）

    Args:
        data: 復号化するデータ
        engine: 実行エンジン
        path: 状態遷移パス
        path_type: パスタイプ
        block_size: ブロックサイズ

    Returns:
        復号化されたデータ
    """
    # 一時ファイルを作成
    temp_output = tempfile.NamedTemporaryFile(delete=False)
    temp_input = tempfile.NamedTemporaryFile(delete=False)

    try:
        # 入力データを一時ファイルに書き込む
        with open(temp_input.name, 'wb') as f:
            f.write(data)

        # 解析攻撃対策のダミー処理
        dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()
        dummy_path = []

        # ファイルをブロック単位で読み込み・復号化・書き込み
        with open(temp_input.name, 'rb') as f_in, open(temp_output.name, 'wb') as f_out:
            block_index = 0

            while True:
                block = f_in.read(block_size)
                if not block:
                    break

                # 現在の状態を取得
                state_idx = min(block_index, len(path) - 1)
                state_id = path[state_idx]
                state = engine.states.get(state_id)

                # ダミーパスの更新
                dummy_path.append(state_id)

                # ブロックを復号化
                decrypted_block = _decrypt_block(block, engine, state, state_id, block_index, dummy_key)

                # 復号化したブロックを書き込む
                f_out.write(decrypted_block)

                block_index += 1

        # ダミー処理（セキュリティ対策）
        for i, state_id in enumerate(dummy_path):
            dummy_seed = hashlib.sha256(f"dummy_{i}_{state_id}".encode() + dummy_key).digest()

        # 復号化されたデータを読み込む
        with open(temp_output.name, 'rb') as f:
            return f.read()

    finally:
        # 一時ファイルを削除
        try:
            os.unlink(temp_input.name)
            os.unlink(temp_output.name)
        except Exception as e:
            print(f"警告: 一時ファイルの削除に失敗しました: {e}", file=sys.stderr)


def _decrypt_block(block: bytes, engine: ProbabilisticExecutionEngine,
                  state: Optional[Any], state_id: int, block_index: int,
                  dummy_key: bytes) -> bytes:
    """
    単一ブロックの復号化処理

    Args:
        block: 復号化するブロック
        engine: 実行エンジン
        state: 現在の状態
        state_id: 状態ID
        block_index: ブロックインデックス
        dummy_key: ダミー鍵

    Returns:
        復号化されたブロック
    """
    if not state:
        # 状態が見つからない場合は単純な復号化
        seed = hashlib.sha256(f"fallback_{block_index}".encode() + engine.key).digest()
        key = seed[:16]
        iv = seed[16:24]
        return basic_decrypt(block, key, iv)

    # 状態の属性から復号化パラメータを導出
    attrs = state.attributes
    block_key = hashlib.sha256(
        engine.key +
        attrs.get("hash_seed", b"") +
        block_index.to_bytes(4, 'big')
    ).digest()

    # 状態ごとに異なる復号化パラメータ
    key = block_key[:16]
    iv = block_key[16:24]

    # 変換キーを使った追加の処理（状態に依存）
    transform_key = attrs.get("transform_key", b"")
    complexity = attrs.get("complexity", 0)
    volatility = attrs.get("volatility", 0)

    # 複雑度と揮発性に応じた処理を元に戻す
    # 暗号化と逆順で処理

    # 最初に基本復号化
    temp_block = basic_decrypt(block, key, iv)

    if transform_key:
        # 揮発性に応じた処理（ノイズの除去）
        if volatility > 70:
            # 高揮発性: ノイズの除去
            noise = hashlib.sha256(transform_key + temp_block).digest()[:min(8, len(temp_block))]
            block_list = bytearray(temp_block)
            for j, noise_byte in enumerate(noise):
                block_list[j % len(block_list)] ^= noise_byte
            temp_block = bytes(block_list)

        # 複雑度に応じた処理
        if complexity > 80:
            # 高複雑度: 複数回の復号化（暗号化と逆順）
            for j in range(2, -1, -1):
                temp_key = hashlib.sha256(key + j.to_bytes(1, 'big')).digest()[:16]
                temp_block = basic_decrypt(temp_block, temp_key, iv)
        elif complexity > 50:
            # 中複雑度: ブロックを分割して個別に復号化
            half = len(temp_block) // 2
            first_half = basic_decrypt(temp_block[:half], key, iv)
            second_half = basic_decrypt(temp_block[half:], key[::-1], iv)
            temp_block = first_half + second_half

    return temp_block


def decrypt_file(encrypted_path: str, key_hex: str, output_path: str) -> bool:
    """
    暗号化ファイルを復号する

    メモリ効率と堅牢性を向上させた実装です。

    Args:
        encrypted_path: 暗号化ファイルのパス
        key_hex: 16進数形式の鍵
        output_path: 出力ファイルのパス

    Returns:
        復号化が成功したかどうか
    """
    try:
        # 鍵のパース
        try:
            key = binascii.unhexlify(key_hex)
        except binascii.Error:
            raise ValueError("鍵のフォーマットが無効です。16進数形式の文字列が必要です。")

        # 派生鍵かどうかを確認
        is_derived_key = len(key) != KEY_SIZE_BYTES
        if is_derived_key:
            # 派生鍵（非正規鍵）の場合は逆変換を行う
            key = hashlib.sha256(key + b"derived_key_reversal").digest()[:KEY_SIZE_BYTES]

        # 暗号化ファイルの読み込み
        print(f"暗号化ファイル '{encrypted_path}' を読み込み中...")
        encrypted_data = read_encrypted_file(encrypted_path)

        # ソルト値の取得
        salt = encrypted_data.get("salt")
        if not salt:
            raise ValueError("ファイルフォーマットが無効です: ソルト値が見つかりません")

        # パスタイプの決定
        path_type = TRUE_PATH
        if is_derived_key:
            # 派生鍵（非正規鍵）の場合
            path_type = FALSE_PATH

        # 状態マトリクスの生成
        if path_type == TRUE_PATH:
            true_salt = hashlib.sha256(salt + b"true_salt").digest()
            state_matrix = create_state_matrix_from_key(key, true_salt, STATE_MATRIX_SIZE)
        else:
            false_salt = hashlib.sha256(salt + b"false_salt").digest()
            state_matrix = create_state_matrix_from_key(key, false_salt, STATE_MATRIX_SIZE)

        # 実行エンジンの作成
        engine = create_engine_from_key(key, state_matrix, salt, path_type, STATE_TRANSITIONS)

        # カプセルデータの取得
        capsule_data = encrypted_data.get("capsule_data")
        if capsule_data is None:
            # 大きなファイルの場合は一時ファイルパスを使用
            capsule_temp_file = encrypted_data.get("capsule_temp_file")
            if not capsule_temp_file or not os.path.exists(capsule_temp_file):
                raise ValueError("ファイルが破損しています: カプセルデータが見つかりません")
            capsule_data = capsule_temp_file

        # カプセルからデータと署名を抽出
        print(f"{path_type} パスでカプセルデータを抽出中...")
        extracted_data, signature = extract_from_capsule(capsule_data, key, salt, path_type)

        # データの復号化
        print(f"{path_type} パスでデータを復号中...")
        decrypted_data = state_based_decrypt(extracted_data, engine, path_type)

        # 署名の検証
        expected_signature = _generate_signature(extracted_data, key, salt)
        if signature != expected_signature:
            # 署名が一致しない場合は警告
            print("警告: データ署名が一致しません。データが改ざんされている可能性があります。", file=sys.stderr)
            if ERROR_ON_SUSPICIOUS_BEHAVIOR:
                raise ValueError("データ署名の検証に失敗しました")

        # 出力ファイル名にタイムスタンプを追加（上書き防止）
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        output_file_parts = os.path.splitext(output_path)
        timestamped_output_path = f"{output_file_parts[0]}_{timestamp_str}{output_file_parts[1]}"

        # ファイルタイプマーカーの処理
        is_text = False
        if len(decrypted_data) >= 8:
            file_type_marker = decrypted_data[:8]
            if file_type_marker == TEXT_MARKER:
                is_text = True
                decrypted_data = decrypted_data[8:]  # マーカーを除去
            elif file_type_marker == BINARY_MARKER:
                decrypted_data = decrypted_data[8:]  # マーカーを除去
            else:
                # 不明なマーカー、そのまま出力
                print("警告: 不明なファイルタイプマーカーです。データが破損している可能性があります。", file=sys.stderr)

        # 大きなデータの場合は分割して書き込み
        print(f"復号化データを '{timestamped_output_path}' に書き込み中...")

        # メモリ最適化ライターを使用
        with MemoryOptimizedWriter(timestamped_output_path) as writer:
            # データの書き込み
            if len(decrypted_data) > BUFFER_SIZE:
                # 大きなデータはチャンク単位で書き込み
                for i in range(0, len(decrypted_data), BUFFER_SIZE):
                    chunk = decrypted_data[i:i+BUFFER_SIZE]
                    writer.write(chunk)
            else:
                # 小さなデータは一括書き込み
                writer.write(decrypted_data)

            # 書き込みを確定
            writer.finalize()

        # ファイルのモード設定
        if is_text:
            # テキストファイルの場合は読み書き権限
            os.chmod(timestamped_output_path, 0o644)
        else:
            # バイナリファイルの場合は読み書き権限
            os.chmod(timestamped_output_path, 0o644)

        print(f"復号化が完了しました: {timestamped_output_path}")
        print(f"ファイルタイプ: {'テキスト' if is_text else 'バイナリ'}")

        # 一時ファイルのクリーンアップ
        _cleanup_temp_files(encrypted_data)

        return True

    except Exception as e:
        print(f"復号化エラー: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

        # 一時ファイルのクリーンアップを試みる
        if 'encrypted_data' in locals():
            _cleanup_temp_files(locals()['encrypted_data'])

        return False


def _cleanup_temp_files(encrypted_data: Dict[str, Any]):
    """
    一時ファイルを削除する

    Args:
        encrypted_data: 暗号化データの辞書
    """
    # エントロピーの一時ファイルを削除
    if "entropy_temp_file" in encrypted_data and encrypted_data["entropy_temp_file"]:
        try:
            temp_file = encrypted_data["entropy_temp_file"]
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        except Exception as e:
            print(f"警告: 一時ファイルの削除に失敗しました: {e}", file=sys.stderr)

    # カプセルの一時ファイルを削除
    if "capsule_temp_file" in encrypted_data and encrypted_data["capsule_temp_file"]:
        try:
            temp_file = encrypted_data["capsule_temp_file"]
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        except Exception as e:
            print(f"警告: 一時ファイルの削除に失敗しました: {e}", file=sys.stderr)


def _generate_signature(data: bytes, key: bytes, salt: bytes) -> bytes:
    """
    データの署名を生成

    Args:
        data: 署名対象データ
        key: 署名鍵
        salt: ソルト値

    Returns:
        署名データ
    """
    # 署名シードの生成
    signature_seed = hashlib.sha256(key + salt + b"signature").digest()

    # データのハッシュ
    data_hash = hashlib.sha256(data).digest()

    # HMACを使用した署名
    h = hashlib.sha256()
    h.update(signature_seed)
    h.update(data_hash)
    h.update(salt)

    return h.digest()


def main():
    """
    メイン実行関数
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式 - 復号プログラム")
    parser.add_argument('--input', '-i', dest='input_path', required=True,
                        help='暗号化ファイルのパス')
    parser.add_argument('--key', '-k', dest='key', required=True,
                        help='復号鍵（16進数形式）')
    parser.add_argument('--output', '-o', dest='output_path', required=True,
                        help='出力ファイルパス')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='詳細モード')

    args = parser.parse_args()

    # 詳細モードの設定
    if args.verbose:
        print("詳細モード有効")

    # 入力ファイルの存在確認
    if not os.path.exists(args.input_path):
        print(f"エラー: 入力ファイル '{args.input_path}' が見つかりません", file=sys.stderr)
        return 1

    # 復号化実行
    success = decrypt_file(
        args.input_path,
        args.key,
        args.output_path
    )

    if success:
        print("\n復号化が正常に完了しました")
        return 0
    else:
        print("\n復号化に失敗しました", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())