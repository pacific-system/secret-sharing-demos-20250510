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


class MemoryOptimizedReader:
    """
    メモリを効率的に使用するファイル読み込みクラス

    大きなファイルを分割してバッファリングして読み込み、メモリ使用量を最適化します。
    """

    def __init__(self, file_path: str, buffer_size: int = BUFFER_SIZE):
        """
        リーダーの初期化

        Args:
            file_path: 読み込むファイルのパス
            buffer_size: 読み込みバッファのサイズ
        """
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.file_size = os.path.getsize(file_path)
        self.temp_files = []
        self.fp = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        self.cleanup()

    def open(self):
        """ファイルを開く"""
        if self.fp is None:
            try:
                self.fp = open(self.file_path, 'rb')
            except Exception as e:
                raise IOError(f"ファイルを開けません: {e}")

    def close(self):
        """ファイルを閉じる"""
        if self.fp is not None:
            try:
                self.fp.close()
                self.fp = None
            except Exception as e:
                print(f"警告: ファイル閉じエラー: {e}", file=sys.stderr)

    def cleanup(self):
        """一時ファイルを削除"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル削除エラー: {e}", file=sys.stderr)
        self.temp_files = []

    def read_chunk(self, size: int = None) -> bytes:
        """
        指定サイズのチャンクを読み込む

        Args:
            size: 読み込むサイズ（Noneの場合はバッファサイズ）

        Returns:
            読み込んだデータ
        """
        if self.fp is None:
            self.open()

        chunk_size = size if size is not None else self.buffer_size
        try:
            data = self.fp.read(chunk_size)
            return data
        except Exception as e:
            raise IOError(f"ファイル読み込みエラー: {e}")

    def read_all(self) -> bytes:
        """
        ファイル全体を読み込む

        メモリ使用量を抑えるため、大きなファイルは一時ファイルを経由して読み込みます。

        Returns:
            ファイル全体のデータ
        """
        if self.file_size > MAX_TEMP_FILE_SIZE:
            return self._read_large_file()
        else:
            return self._read_normal_file()

    def _read_normal_file(self) -> bytes:
        """
        通常サイズのファイルを読み込む

        Returns:
            ファイル全体のデータ
        """
        if self.fp is None:
            self.open()

        # ファイルポインタを先頭に戻す
        self.fp.seek(0)

        try:
            return self.fp.read()
        except Exception as e:
            raise IOError(f"ファイル読み込みエラー: {e}")

    def _read_large_file(self) -> bytes:
        """
        大きなファイルをメモリ効率良く読み込む

        Returns:
            ファイル全体のデータ
        """
        if self.fp is None:
            self.open()

        # ファイルポインタを先頭に戻す
        self.fp.seek(0)

        # 進捗状況の計算用
        total_chunks = (self.file_size + self.buffer_size - 1) // self.buffer_size
        progress_interval = max(1, total_chunks // 10)  # 10%ごとに表示

        # 一時ファイルに分割して読み込み
        temp_data = bytearray()

        # サイズが小さい場合は直接メモリに読み込む（MAX_MEMORY_SIZE以下）
        if self.file_size <= MAX_MEMORY_SIZE:
            chunk_idx = 0
            while True:
                chunk = self.read_chunk()
                if not chunk:
                    break

                temp_data.extend(chunk)

                # 進捗表示
                chunk_idx += 1
                if chunk_idx % progress_interval == 0:
                    print(f"読み込み進捗: {chunk_idx * 100 // total_chunks}%")

            return bytes(temp_data)
        else:
            # 大きいファイルは一時ファイルに書き込んでから読み込む
            temp_file = tempfile.NamedTemporaryFile(delete=False, prefix="reader_temp_")
            self.temp_files.append(temp_file.name)

            try:
                # 一時ファイルにデータを書き込む
                chunk_idx = 0
                while True:
                    chunk = self.read_chunk()
                    if not chunk:
                        break

                    temp_file.write(chunk)

                    # 進捗表示
                    chunk_idx += 1
                    if chunk_idx % progress_interval == 0:
                        print(f"読み込み進捗: {chunk_idx * 100 // total_chunks}%")

                temp_file.flush()
                temp_file.close()

                # 一時ファイルからデータを読み込む
                with open(temp_file.name, 'rb') as f:
                    result = bytearray()
                    chunk_size = min(MAX_MEMORY_SIZE // 2, self.buffer_size * 4)

                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        result.extend(chunk)

                return bytes(result)
            finally:
                # 確実に一時ファイルを削除
                self.cleanup()

    def read_at(self, offset: int, size: int) -> bytes:
        """
        指定オフセットから指定サイズのデータを読み込む

        Args:
            offset: 読み込み開始位置
            size: 読み込むサイズ

        Returns:
            読み込んだデータ
        """
        if self.fp is None:
            self.open()

        # 境界チェック
        if offset < 0:
            offset = 0

        if offset >= self.file_size:
            return b''

        # サイズ調整
        if offset + size > self.file_size:
            size = self.file_size - offset

        try:
            self.fp.seek(offset)
            return self.fp.read(size)
        except Exception as e:
            raise IOError(f"ファイル読み込みエラー: {e}")

    def __iter__(self) -> Iterator[bytes]:
        """
        チャンク単位でファイルをイテレートする

        Returns:
            バイトチャンクのイテレータ
        """
        if self.fp is None:
            self.open()

        # ファイルポインタを先頭に戻す
        self.fp.seek(0)

        while True:
            chunk = self.read_chunk()
            if not chunk:
                break
            yield chunk


class MemoryOptimizedWriter:
    """
    メモリを効率的に使用するファイル書き込みクラス

    大きなデータを分割して書き込み、メモリ使用量を最適化します。
    """

    def __init__(self, file_path: str, buffer_size: int = BUFFER_SIZE):
        """
        ライターの初期化

        Args:
            file_path: 書き込むファイルのパス
            buffer_size: 書き込みバッファのサイズ
        """
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.temp_files = []
        self.fp = None
        self.bytes_written = 0
        self.is_open = False

        # 親ディレクトリが存在しない場合は作成
        parent_dir = os.path.dirname(file_path)
        if parent_dir and not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except Exception as e:
                raise IOError(f"ディレクトリ '{parent_dir}' を作成できません: {e}")

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        self.cleanup()

    def open(self):
        """ファイルを開く"""
        if self.fp is None:
            try:
                self.fp = open(self.file_path, 'wb')
                self.is_open = True
            except Exception as e:
                raise IOError(f"ファイルを開けません: {e}")

    def close(self):
        """ファイルを閉じる"""
        if self.fp is not None:
            try:
                self.fp.flush()
                self.fp.close()
                self.fp = None
                self.is_open = False
            except Exception as e:
                print(f"警告: ファイル閉じエラー: {e}", file=sys.stderr)

    def cleanup(self):
        """一時ファイルを削除"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル削除エラー: {e}", file=sys.stderr)
        self.temp_files = []

    def write(self, data: bytes) -> int:
        """
        データを書き込む

        メモリ効率を考慮して大きなデータは分割して書き込みます。

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if not data:
            return 0

        data_size = len(data)

        # データサイズが大きい場合は分割して書き込む
        if data_size > MAX_TEMP_FILE_SIZE:
            return self._write_large_data(data)
        else:
            return self._write_normal_data(data)

    def _write_normal_data(self, data: bytes) -> int:
        """
        通常サイズのデータを書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if self.fp is None:
            self.open()

        try:
            self.fp.write(data)
            self.bytes_written += len(data)
            return len(data)
        except Exception as e:
            raise IOError(f"ファイル書き込みエラー: {e}")

    def _write_large_data(self, data: bytes) -> int:
        """
        大きなデータをメモリ効率良く書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if self.fp is None:
            self.open()

        data_size = len(data)
        bytes_written = 0

        # チャンクサイズの計算
        chunk_size = min(self.buffer_size, MAX_MEMORY_SIZE // 4)

        # 進捗状況の計算
        total_chunks = (data_size + chunk_size - 1) // chunk_size
        progress_interval = max(1, total_chunks // 10)  # 10%ごとに表示

        # チャンク単位で書き込み
        for i in range(0, data_size, chunk_size):
            # 現在のチャンクサイズを計算
            current_chunk_size = min(chunk_size, data_size - i)
            chunk = data[i:i+current_chunk_size]

            try:
                self.fp.write(chunk)
                bytes_written += len(chunk)

                # 進捗表示
                chunk_idx = i // chunk_size
                if chunk_idx % progress_interval == 0:
                    progress = min(100, (i + current_chunk_size) * 100 // data_size)
                    print(f"書き込み進捗: {progress}%")

            except Exception as e:
                raise IOError(f"ファイル書き込みエラー（{i}/{data_size}バイト地点）: {e}")

        self.bytes_written += bytes_written
        return bytes_written

    def write_at(self, offset: int, data: bytes) -> int:
        """
        指定オフセットにデータを書き込む

        Args:
            offset: 書き込み開始位置
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if not data:
            return 0

        if self.fp is None:
            self.open()

        try:
            # 現在のファイルサイズを取得
            current_size = os.path.getsize(self.file_path) if os.path.exists(self.file_path) else 0

            # 必要ならパディング
            if offset > current_size:
                # ファイルポインタを末尾に移動
                self.fp.seek(0, os.SEEK_END)
                # 0で埋める
                padding_size = offset - current_size
                padding = b'\x00' * min(padding_size, self.buffer_size)

                # バッファサイズより大きい場合は分割
                remaining = padding_size
                while remaining > 0:
                    chunk_size = min(remaining, self.buffer_size)
                    if chunk_size < self.buffer_size:
                        self.fp.write(padding[:chunk_size])
                    else:
                        self.fp.write(padding)
                    remaining -= chunk_size

            # 指定位置に移動してデータ書き込み
            self.fp.seek(offset)
            self.fp.write(data)

            # 書き込み位置を更新
            new_pos = offset + len(data)
            if new_pos > self.bytes_written:
                self.bytes_written = new_pos

            return len(data)
        except Exception as e:
            raise IOError(f"ファイル書き込みエラー（オフセット {offset}）: {e}")

    def get_bytes_written(self) -> int:
        """
        書き込んだバイト数を取得

        Returns:
            書き込んだバイト総数
        """
        return self.bytes_written


def basic_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    基本的な復号を行う

    暗号化ライブラリがある場合はAESを使用し、ない場合はXORベースの暗号化を行います。

    Args:
        data: 復号するデータ
        key: 暗号鍵
        iv: 初期化ベクトル

    Returns:
        復号されたデータ
    """
    if not data:
        raise ValueError("復号するデータが空です")

    if not key:
        raise ValueError("暗号鍵が空です")

    if not iv:
        raise ValueError("初期化ベクトルが空です")

    # メモリ使用量を考慮して、大きなデータの場合はチャンク単位で処理
    large_data_threshold = 50 * 1024 * 1024  # 50MB
    if len(data) > large_data_threshold:
        if HAS_CRYPTOGRAPHY:
            return _decrypt_large_data_aes(data, key, iv)
        else:
            return _decrypt_large_data_xor(data, key, iv)

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

            # 復号
            return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            print(f"警告: AES復号化に失敗しました: {e}", file=sys.stderr)
            print("XOR復号化にフォールバックします")
            # AES復号化に失敗した場合はXOR復号化にフォールバック

    # XORベースの簡易復号化（セキュリティ強化版）
    return _decrypt_xor(data, key, iv)


def _decrypt_large_data_aes(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AESを使用した大きなデータの復号化処理

    メモリ効率を考慮して一時ファイルを使用します。

    Args:
        data: 復号化するデータ
        key: 暗号鍵
        iv: 初期化ベクトル

    Returns:
        復号化されたデータ
    """
    # 鍵とIVを正規化
    normalized_key = normalize_key(key, 32)
    normalized_iv = normalize_key(iv, 16)

    # 暗号器を準備
    cipher = Cipher(
        algorithms.AES(normalized_key),
        modes.CTR(normalized_iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # 一時ファイルを作成
    temp_output = tempfile.NamedTemporaryFile(delete=False)

    try:
        # データをチャンク単位で処理
        total_size = len(data)
        bytes_processed = 0

        while bytes_processed < total_size:
            chunk_size = min(BUFFER_SIZE, total_size - bytes_processed)
            chunk = data[bytes_processed:bytes_processed + chunk_size]

            # チャンクを復号化
            decrypted_chunk = decryptor.update(chunk)
            temp_output.write(decrypted_chunk)

            bytes_processed += chunk_size

        # 最終ブロックを処理
        final_block = decryptor.finalize()
        if final_block:
            temp_output.write(final_block)

        temp_output.flush()
        temp_output.close()

        # 復号化されたデータを読み込む
        with open(temp_output.name, 'rb') as f:
            return f.read()

    finally:
        # 一時ファイルを削除
        try:
            if os.path.exists(temp_output.name):
                os.unlink(temp_output.name)
        except Exception as e:
            print(f"警告: 一時ファイルの削除に失敗しました: {e}", file=sys.stderr)


def _decrypt_xor(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    XORベースの復号化

    簡易な復号化だが、セキュリティを高める工夫を追加。

    Args:
        data: 復号化するデータ
        key: 暗号鍵
        iv: 初期化ベクトル

    Returns:
        復号化されたデータ
    """
    # 大きなデータの場合はチャンク単位で処理
    if len(data) > BUFFER_SIZE:
        return _decrypt_large_data_xor(data, key, iv)

    # 鍵をデータサイズに拡張
    extended_key = bytearray()
    segment_size = 32  # SHA-256のサイズ

    # データサイズに合わせて拡張鍵を生成
    key_rounds = (len(data) + segment_size - 1) // segment_size
    for i in range(key_rounds):
        # ソルトとして位置情報とカウンタを使用してセキュリティを向上
        counter = i.to_bytes(8, 'big')
        segment_key = hashlib.sha256(key + iv + counter).digest()
        extended_key.extend(segment_key)

    # データとXOR
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ extended_key[i]

    return bytes(result)


def _decrypt_large_data_xor(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    XORベースの大きなデータの復号化処理

    メモリ効率を考慮して一時ファイルを使用します。

    Args:
        data: 復号化するデータ
        key: 暗号鍵
        iv: 初期化ベクトル

    Returns:
        復号化されたデータ
    """
    # 一時ファイルを作成
    temp_output = tempfile.NamedTemporaryFile(delete=False)

    try:
        # データをチャンク単位で処理
        total_size = len(data)
        bytes_processed = 0

        while bytes_processed < total_size:
            chunk_size = min(BUFFER_SIZE, total_size - bytes_processed)
            chunk = data[bytes_processed:bytes_processed + chunk_size]

            # このチャンク用の拡張鍵を生成
            start_segment = bytes_processed // 32
            end_segment = (bytes_processed + chunk_size + 31) // 32
            extended_key = bytearray()

            for i in range(start_segment, end_segment):
                counter = i.to_bytes(8, 'big')
                segment_key = hashlib.sha256(key + iv + counter).digest()
                extended_key.extend(segment_key)

            # チャンクを復号化
            decrypted_chunk = bytearray(chunk_size)
            for i in range(chunk_size):
                key_offset = i % len(extended_key)
                decrypted_chunk[i] = chunk[i] ^ extended_key[key_offset]

            temp_output.write(decrypted_chunk)
            bytes_processed += chunk_size

        temp_output.flush()
        temp_output.close()

        # 復号化されたデータを読み込む
        with open(temp_output.name, 'rb') as f:
            return f.read()

    finally:
        # 一時ファイルを削除
        try:
            if os.path.exists(temp_output.name):
                os.unlink(temp_output.name)
        except Exception as e:
            print(f"警告: 一時ファイルの削除に失敗しました: {e}", file=sys.stderr)


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


def extract_from_state_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    path_type: str
) -> bytes:
    """
    状態カプセルからデータを抽出

    メモリ効率の良い処理を行い、大きなカプセルデータも効率的に処理します。

    Args:
        capsule_data: カプセル化されたデータ
        key: マスター鍵
        salt: ソルト値
        path_type: パスタイプ（"true" または "false"）

    Returns:
        抽出されたデータ
    """
    # 入力検証
    if not capsule_data:
        raise ValueError("カプセルデータが空です")
    if not key:
        raise ValueError("鍵が空です")
    if not salt:
        raise ValueError("ソルト値が空です")
    if path_type not in (TRUE_PATH, FALSE_PATH):
        raise ValueError(f"無効なパスタイプです: {path_type}。'true' または 'false' を指定してください")

    # 大きなカプセルデータの場合は一時ファイル処理
    very_large_threshold = 1 * 1024 * 1024 * 1024  # 1GB
    if len(capsule_data) > very_large_threshold:
        return _extract_streaming_capsule(capsule_data, key, salt, path_type)

    # 中〜大サイズの場合
    if len(capsule_data) > MAX_TEMP_FILE_SIZE:
        return _extract_large_capsule(capsule_data, key, salt, path_type)

    # 通常サイズの場合はメモリ内処理
    return _extract_memory_capsule(capsule_data, key, salt, path_type)


def _extract_memory_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    path_type: str
) -> bytes:
    """
    メモリ内でカプセルからデータを抽出（小〜中サイズ用）

    Args:
        capsule_data: カプセル化されたデータ
        key: マスター鍵
        salt: ソルト値
        path_type: パスタイプ（"true" または "false"）

    Returns:
        抽出されたデータ
    """
    # 抽出パラメータのシード値
    capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()

    # カプセルヘッダーの解析（署名データを取得）
    signature_size = 32  # SHA-256ハッシュサイズ
    if len(capsule_data) < signature_size * 2:
        raise ValueError("カプセルデータが不正：署名セクションが不足しています")

    # 署名の取得（最初の部分に格納されている）
    true_sig_noised = capsule_data[:signature_size]
    false_sig_noised = capsule_data[signature_size:signature_size*2]

    # 署名を判別し検証
    timestamp_bytes = int(time.time()).to_bytes(8, 'big')
    enhanced_seed = hashlib.sha512(capsule_seed + timestamp_bytes).digest()

    # ノイズ除去処理
    true_sig_processed = bytes([b ^ enhanced_seed[i % len(enhanced_seed)]
                             for i, b in enumerate(true_sig_noised)])
    false_sig_processed = bytes([b ^ enhanced_seed[i+16 % len(enhanced_seed)]
                              for i, b in enumerate(false_sig_noised)])

    # 署名の検証
    required_signature = true_sig_processed if path_type == TRUE_PATH else false_sig_processed

    # 本体データの開始位置
    data_start = signature_size * 2

    # 構造データとカプセル終了マーカーのサイズ
    struct_marker_size = 32 + 16  # 構造データ32バイト + 終了マーカー16バイト

    # カプセル本体部分の取得
    capsule_body = capsule_data[data_start:-struct_marker_size]

    # カプセル構造情報の取得
    structure_noised = capsule_data[-struct_marker_size:-16]

    # 構造情報のノイズ除去
    structure_data = bytes([b ^ enhanced_seed[i+32 % len(enhanced_seed)]
                          for i, b in enumerate(structure_noised)])

    # ブロックサイズの定義とパターン生成
    block_size = 1024  # 1KBのブロックサイズ

    # カプセル内のブロックを分解して目的のデータを抽出
    data_blocks = []

    # 小さなデータの場合はチャンクごとに処理
    body_size = len(capsule_body)

    # 一時データバッファ
    temp_data = bytearray()

    # ブロック数を特定（パターンにより異なる）
    block_idx = 0
    offset = 0

    # 本文データからブロックを抽出
    while offset < body_size:
        # パターン計算
        pattern_seed = hashlib.sha512(capsule_seed + block_idx.to_bytes(4, 'big')).digest()
        pattern_value = pattern_seed[0] % 4  # 0-3の値

        # 残りデータサイズ
        remaining = body_size - offset

        # パターンに基づいて適切なブロックを抽出
        if pattern_value == 0:  # 正規→非正規
            if path_type == TRUE_PATH:
                if remaining >= block_size:
                    # 正規ブロックを取得
                    block = capsule_body[offset:offset+block_size]
                    data_blocks.append(block)
                    offset += block_size * 2  # 両方のブロックをスキップ
                else:
                    # 残りデータが不足
                    break
            else:  # FALSE_PATH
                if remaining >= block_size * 2:
                    # 非正規ブロックを取得
                    block = capsule_body[offset+block_size:offset+block_size*2]
                    data_blocks.append(block)
                    offset += block_size * 2
                else:
                    # 残りデータが不足
                    break
        elif pattern_value == 1:  # 非正規→正規
            if path_type == TRUE_PATH:
                if remaining >= block_size * 2:
                    # 正規ブロックを取得
                    block = capsule_body[offset+block_size:offset+block_size*2]
                    data_blocks.append(block)
                    offset += block_size * 2
                else:
                    # 残りデータが不足
                    break
            else:  # FALSE_PATH
                if remaining >= block_size:
                    # 非正規ブロックを取得
                    block = capsule_body[offset:offset+block_size]
                    data_blocks.append(block)
                    offset += block_size * 2
                else:
                    # 残りデータが不足
                    break
        else:  # インターリーブパターン（2または3）
            if remaining >= block_size:
                # インターリーブされたブロックから対象データを抽出
                interleaved = capsule_body[offset:offset+block_size]
                extracted = bytearray(block_size // 2)

                # バイト単位で抽出（偶数または奇数のインデックスを抽出）
                for i in range(0, min(block_size, len(interleaved)), 2):
                    if i + 1 < len(interleaved):
                        if path_type == TRUE_PATH:
                            extracted[i//2] = interleaved[i]  # 偶数インデックス（true）
                        else:
                            extracted[i//2] = interleaved[i+1]  # 奇数インデックス（false）

                data_blocks.append(bytes(extracted))
                offset += block_size
            else:
                # 残りデータが不足
                break

        # 次のブロックへ
        block_idx += 1

    # 抽出されたブロックを結合
    extracted_data = b''.join(data_blocks)

    # パディングを除去
    return remove_padding(extracted_data)


def _extract_large_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    path_type: str
) -> bytes:
    """
    メモリ効率のよいカプセル抽出処理（大きめのデータ用）

    一時ファイルを使用してメモリ使用量を抑制します。

    Args:
        capsule_data: カプセル化されたデータ
        key: マスター鍵
        salt: ソルト値
        path_type: パスタイプ

    Returns:
        抽出されたデータ
    """
    # 一時ファイルを作成
    capsule_temp = tempfile.NamedTemporaryFile(delete=False, prefix="extract_capsule_")
    output_temp = tempfile.NamedTemporaryFile(delete=False, prefix="extract_output_")

    temp_files = [capsule_temp.name, output_temp.name]

    try:
        # カプセルデータを一時ファイルに書き込む
        capsule_temp.write(capsule_data)
        capsule_temp.flush()
        capsule_temp.close()

        # 抽出パラメータのシード値
        capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()
        timestamp_bytes = int(time.time()).to_bytes(8, 'big')
        enhanced_seed = hashlib.sha512(capsule_seed + timestamp_bytes).digest()

        # 署名サイズと構造データサイズ
        signature_size = 32  # SHA-256ハッシュサイズ
        struct_marker_size = 32 + 16  # 構造データ32バイト + 終了マーカー16バイト

        # ファイルを開いて処理
        with open(capsule_temp.name, 'rb') as f_in, open(output_temp.name, 'wb') as f_out:
            # 署名データの読み込み
            true_sig_noised = f_in.read(signature_size)
            false_sig_noised = f_in.read(signature_size)

            # ノイズ除去処理
            true_sig_processed = bytes([b ^ enhanced_seed[i % len(enhanced_seed)]
                                     for i, b in enumerate(true_sig_noised)])
            false_sig_processed = bytes([b ^ enhanced_seed[i+16 % len(enhanced_seed)]
                                      for i, b in enumerate(false_sig_noised)])

            # ブロックサイズの定義
            block_size = 1024  # 1KBのブロックサイズ

            # カプセルサイズからブロック数を計算
            capsule_size = os.path.getsize(capsule_temp.name)
            body_size = capsule_size - signature_size * 2 - struct_marker_size
            total_blocks = (body_size + block_size - 1) // block_size

            # 進捗表示用
            progress_interval = max(1, total_blocks // 20)  # 5%ごとに表示

            # ブロック単位で処理
            block_idx = 0
            bytes_processed = 0

            # 本文の処理
            while bytes_processed < body_size:
                # パターン計算
                pattern_seed = hashlib.sha512(capsule_seed + block_idx.to_bytes(4, 'big')).digest()
                pattern_value = pattern_seed[0] % 4  # 0-3の値

                # 残りデータサイズ
                remaining = body_size - bytes_processed

                # 進捗表示
                if block_idx % progress_interval == 0:
                    print(f"抽出進捗: {bytes_processed * 100 // body_size}%")

                # パターンに基づいて適切なブロックを抽出
                if pattern_value == 0:  # 正規→非正規
                    true_block = f_in.read(min(block_size, remaining))
                    false_block = f_in.read(min(block_size, remaining - len(true_block)))

                    if path_type == TRUE_PATH:
                        if true_block:
                            f_out.write(true_block)
                    else:  # FALSE_PATH
                        if false_block:
                            f_out.write(false_block)

                    bytes_processed += len(true_block) + len(false_block)

                elif pattern_value == 1:  # 非正規→正規
                    false_block = f_in.read(min(block_size, remaining))
                    true_block = f_in.read(min(block_size, remaining - len(false_block)))

                    if path_type == TRUE_PATH:
                        if true_block:
                            f_out.write(true_block)
                    else:  # FALSE_PATH
                        if false_block:
                            f_out.write(false_block)

                    bytes_processed += len(false_block) + len(true_block)

                else:  # インターリーブパターン
                    interleaved = f_in.read(min(block_size, remaining))
                    if interleaved:
                        # インターリーブされたブロックから対象データを抽出
                        extracted = bytearray(len(interleaved) // 2 + len(interleaved) % 2)

                        # バイト単位で抽出
                        for i in range(0, len(interleaved), 2):
                            if path_type == TRUE_PATH and i < len(interleaved):
                                extracted[i//2] = interleaved[i]  # 偶数インデックス（true）
                            elif i + 1 < len(interleaved):
                                extracted[i//2] = interleaved[i+1]  # 奇数インデックス（false）

                        f_out.write(extracted)

                    bytes_processed += len(interleaved)

                # 次のブロックへ
                block_idx += 1

            # 構造データとマーカーをスキップ
            f_in.seek(signature_size * 2 + body_size)

        # 出力ファイルからデータを読み込む
        with open(output_temp.name, 'rb') as f:
            extracted_data = f.read()

        # パディングを除去
        return remove_padding(extracted_data)

    finally:
        # 一時ファイルの削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


def _extract_streaming_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    path_type: str
) -> bytes:
    """
    ストリーミング方式でカプセルからデータを抽出（超大容量データ用）

    特に大きなデータ向けに最適化されたストリーミング処理を行います。

    Args:
        capsule_data: カプセル化されたデータ
        key: マスター鍵
        salt: ソルト値
        path_type: パスタイプ

    Returns:
        抽出されたデータ
    """
    # この関数は _extract_large_capsule と似ていますが、より大きなデータに最適化
    # 入出力バッファサイズを大きくし、メモリ使用量を最小限に抑える工夫を実装

    # 一時ファイルを作成
    capsule_temp = tempfile.NamedTemporaryFile(delete=False, prefix="extract_capsule_xl_")
    output_temp = tempfile.NamedTemporaryFile(delete=False, prefix="extract_output_xl_")

    temp_files = [capsule_temp.name, output_temp.name]

    try:
        # カプセルデータを一時ファイルに書き込む（チャンク単位）
        chunk_size = 16 * 1024 * 1024  # 16MB
        bytes_written = 0
        total_size = len(capsule_data)

        while bytes_written < total_size:
            current_chunk_size = min(chunk_size, total_size - bytes_written)
            chunk = capsule_data[bytes_written:bytes_written+current_chunk_size]
            capsule_temp.write(chunk)
            bytes_written += current_chunk_size

        capsule_temp.flush()
        capsule_temp.close()

        # 抽出パラメータのシード値
        capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()
        timestamp_bytes = int(time.time()).to_bytes(8, 'big')
        enhanced_seed = hashlib.sha512(capsule_seed + timestamp_bytes).digest()

        # 署名サイズと構造データサイズ
        signature_size = 32  # SHA-256ハッシュサイズ
        struct_marker_size = 32 + 16  # 構造データ32バイト + 終了マーカー16バイト

        # 開始時間
        start_time = time.time()

        # ファイルを開いて処理（より大きなバッファサイズを使用）
        with open(capsule_temp.name, 'rb', buffering=16*1024*1024) as f_in, \
             open(output_temp.name, 'wb', buffering=16*1024*1024) as f_out:

            # 署名データの読み込み
            true_sig_noised = f_in.read(signature_size)
            false_sig_noised = f_in.read(signature_size)

            # ノイズ除去処理
            true_sig_processed = bytes([b ^ enhanced_seed[i % len(enhanced_seed)]
                                     for i, b in enumerate(true_sig_noised)])
            false_sig_processed = bytes([b ^ enhanced_seed[i+16 % len(enhanced_seed)]
                                      for i, b in enumerate(false_sig_noised)])

            # ブロックサイズをより大きくして、I/O効率を向上
            block_size = 64 * 1024  # 64KB

            # カプセルサイズからブロック数を計算
            capsule_size = os.path.getsize(capsule_temp.name)
            body_size = capsule_size - signature_size * 2 - struct_marker_size
            total_blocks = (body_size + block_size - 1) // block_size

            # 進捗表示用
            progress_interval = max(1, total_blocks // 20)  # 5%ごとに表示

            # ブロック単位で処理
            block_idx = 0
            bytes_processed = 0

            # 本文の処理
            while bytes_processed < body_size:
                # パターン計算
                pattern_seed = hashlib.sha512(capsule_seed + block_idx.to_bytes(4, 'big')).digest()
                pattern_value = pattern_seed[0] % 4  # 0-3の値

                # 残りデータサイズ
                remaining = body_size - bytes_processed

                # 進捗表示
                if block_idx % progress_interval == 0:
                    percent = bytes_processed * 100 // body_size
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        rate = bytes_processed / (1024 * 1024 * elapsed)
                        eta = (body_size - bytes_processed) / (bytes_processed / elapsed) if bytes_processed > 0 else 0
                        print(f"抽出進捗: {percent}% ({rate:.1f} MB/s, 残り約 {eta:.0f} 秒)")

                # パターンに基づいて適切なブロックを抽出
                if pattern_value == 0:  # 正規→非正規
                    true_block = f_in.read(min(block_size, remaining))
                    false_block = f_in.read(min(block_size, remaining - len(true_block)))

                    if path_type == TRUE_PATH:
                        if true_block:
                            f_out.write(true_block)
                    else:  # FALSE_PATH
                        if false_block:
                            f_out.write(false_block)

                    bytes_processed += len(true_block) + len(false_block)

                elif pattern_value == 1:  # 非正規→正規
                    false_block = f_in.read(min(block_size, remaining))
                    true_block = f_in.read(min(block_size, remaining - len(false_block)))

                    if path_type == TRUE_PATH:
                        if true_block:
                            f_out.write(true_block)
                    else:  # FALSE_PATH
                        if false_block:
                            f_out.write(false_block)

                    bytes_processed += len(false_block) + len(true_block)

                else:  # インターリーブパターン
                    interleaved = f_in.read(min(block_size, remaining))
                    if interleaved:
                        # メモリ効率の向上: 大きなバッファを一度に処理せず、小さなチャンクで処理
                        interleave_chunk_size = 4096  # 4KB
                        for offset in range(0, len(interleaved), interleave_chunk_size):
                            chunk = interleaved[offset:offset+interleave_chunk_size]
                            # インターリーブされたブロックから対象データを抽出
                            extracted = bytearray(len(chunk) // 2 + len(chunk) % 2)

                            # バイト単位で抽出
                            for i in range(0, len(chunk), 2):
                                if path_type == TRUE_PATH and i < len(chunk):
                                    extracted[i//2] = chunk[i]  # 偶数インデックス（true）
                                elif i + 1 < len(chunk):
                                    extracted[i//2] = chunk[i+1]  # 奇数インデックス（false）

                            f_out.write(extracted)

                    bytes_processed += len(interleaved)

                # 次のブロックへ
                block_idx += 1

            # 構造データとマーカーをスキップ（ファイルの最後まで読み込む必要はない）

        # 処理完了時間の表示
        elapsed = time.time() - start_time
        rate = body_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
        print(f"抽出完了: 処理時間 {elapsed:.2f} 秒 ({rate:.1f} MB/s)")

        # 出力ファイルからデータを読み込む（メモリ使用量を制限して読み込む）
        output_size = os.path.getsize(output_temp.name)
        max_return_size = 500 * 1024 * 1024  # 500MB

        if output_size > max_return_size:
            # ファイルサイズが大きすぎる場合は警告を出し、より効率的な方法でデータを処理
            print(f"警告: 抽出データが大きすぎます ({output_size/(1024*1024):.2f} MB)。", file=sys.stderr)
            print(f"メモリ使用量を抑えるため、データは別途処理されます。", file=sys.stderr)

            # この場合、出力ファイルを削除せず、呼び出し元で処理してもらうように戻す
            result_file = output_temp.name
            temp_files.remove(result_file)

            # ファイルパスを返す代わりに、ファイルの内容をサンプリング
            with open(result_file, 'rb') as f:
                # 先頭と末尾の部分をサンプリング
                header = f.read(1024 * 1024)  # 先頭1MB
                f.seek(-min(1024 * 1024, output_size), os.SEEK_END)
                footer = f.read(min(1024 * 1024, output_size))

                # 先頭と末尾を結合（中間部分は省略）
                sampled_data = header + b'...[データ省略]...' + footer

                # 呼び出し元にファイルパスも通知
                print(f"抽出データは一時ファイル '{result_file}' に保存されました。")
                print(f"処理完了後、このファイルを手動で削除してください。")

                # パディングを除去（サンプルデータに対して）
                return remove_padding(sampled_data)
        else:
            # 通常サイズならメモリに読み込む
            with open(output_temp.name, 'rb') as f:
                extracted_data = f.read()

            # パディングを除去
            return remove_padding(extracted_data)

    finally:
        # 一時ファイルの削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


def remove_padding(data: bytes) -> bytes:
    """
    データからパディングを除去

    末尾の0バイトを削除します。

    Args:
        data: パディングを含むデータ

    Returns:
        パディングを除去したデータ
    """
    if not data:
        return b''

    # 末尾の0バイトを検出
    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1

    # パディングを削除して返す（i+1バイトまで）
    return data[:i+1] if i >= 0 else b''


def state_based_decrypt(data: bytes, engine: ProbabilisticExecutionEngine, path_type: str) -> bytes:
    """
    状態遷移に基づく復号

    メモリ効率を考慮した大きなデータの復号が可能です。

    Args:
        data: 復号するデータ
        engine: 確率的実行エンジン
        path_type: パスタイプ（"true" または "false"）

    Returns:
        復号されたデータ
    """
    # データが少なすぎる場合はエラー
    if len(data) < 1:
        raise ValueError("復号するデータが空です")

    # パスタイプの検証
    if path_type not in (TRUE_PATH, FALSE_PATH):
        raise ValueError(f"無効なパスタイプです: {path_type}。'true' または 'false' を指定してください。")

    # エンジンを実行して状態遷移パスを取得
    path = engine.run_execution()
    if not path or len(path) < 1:
        raise ValueError("状態遷移パスの生成に失敗しました")

    # 解析攻撃対策のダミー処理
    dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()

    # ブロックサイズを定義
    block_size = 64  # 共通のブロックサイズ

    # データサイズのチェック - 非常に大きなファイルの場合
    very_large_threshold = 500 * 1024 * 1024  # 500MB

    if len(data) > very_large_threshold:
        # 非常に大きなファイルの場合はファイルベースの処理を行う
        return _decrypt_very_large_data(data, engine, path, path_type, block_size)
    # 大きなファイルだがメモリで処理可能な場合
    elif len(data) > MAX_TEMP_FILE_SIZE:
        return _decrypt_large_data(data, engine, path, path_type, block_size)
    # 通常のメモリ内処理
    else:
        return _decrypt_in_memory(data, engine, path, path_type, block_size)


def _decrypt_very_large_data(data: bytes, engine: ProbabilisticExecutionEngine,
                           path: List[int], path_type: str, block_size: int) -> bytes:
    """
    非常に大きなデータの復号処理（ストリーミングアプローチ）

    データを直接メモリに読み込まず、ファイルストリームとして処理します。

    Args:
        data: 復号するデータ
        engine: 実行エンジン
        path: 状態遷移パス
        path_type: パスタイプ
        block_size: ブロックサイズ

    Returns:
        復号されたデータ
    """
    # 入力用と出力用の一時ファイルを作成
    input_temp = tempfile.NamedTemporaryFile(delete=False, prefix="decrypt_in_")
    output_temp = tempfile.NamedTemporaryFile(delete=False, prefix="decrypt_out_")
    temp_files = [input_temp.name, output_temp.name]

    try:
        # 入力データを一時ファイルに書き込む（チャンク単位）
        total_size = len(data)
        bytes_written = 0
        write_chunk_size = 8 * 1024 * 1024  # 8MB書き込みチャンク

        while bytes_written < total_size:
            chunk_size = min(write_chunk_size, total_size - bytes_written)
            chunk = data[bytes_written:bytes_written+chunk_size]
            input_temp.write(chunk)
            bytes_written += chunk_size

        input_temp.flush()
        input_temp.close()

        # 解析攻撃対策のダミー処理
        dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()

        # 進捗表示用変数
        total_blocks = (total_size + block_size - 1) // block_size
        progress_interval = max(1, total_blocks // 20)  # 5%ごとに表示

        # ファイルをブロック単位で読み込み・復号・書き込み
        with open(input_temp.name, 'rb') as f_in, open(output_temp.name, 'wb') as f_out:
            block_index = 0

            while True:
                block = f_in.read(block_size)
                if not block:
                    break

                # 最後のブロックにパディングを適用
                if len(block) < block_size:
                    block = block + b'\x00' * (block_size - len(block))

                # 現在の状態を取得
                state_idx = min(block_index, len(path) - 1)
                state_id = path[state_idx]
                state = engine.states.get(state_id)

                # ブロックを復号
                decrypted_block = _decrypt_block(block, engine, state, state_id, block_index, dummy_key)

                # 復号したブロックを書き込む
                f_out.write(decrypted_block)

                # 進捗表示
                block_index += 1
                if block_index % progress_interval == 0:
                    print(f"復号進捗: {block_index * 100 // total_blocks}% ({block_index}/{total_blocks})")

        # 復号されたデータを読み込む
        with open(output_temp.name, 'rb') as f:
            # 大きなファイルを分割読み込み
            result = bytearray()
            read_chunk_size = 8 * 1024 * 1024  # 8MB読み込みチャンク

            while True:
                chunk = f.read(read_chunk_size)
                if not chunk:
                    break
                result.extend(chunk)

        # パディングを除去
        result = remove_padding(bytes(result))
        return result

    finally:
        # 一時ファイルを必ず削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


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

        # メモリ使用量を管理（大きな中間サイズのデータ用）
        if i > 0 and i % 1000 == 0:
            # 一時的なオブジェクトの参照を解放
            block = None
            if i % 10000 == 0:
                import gc
                gc.collect()

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
    temp_files = [temp_input.name, temp_output.name]

    try:
        # 入力データを一時ファイルに書き込む（チャンク単位）
        total_size = len(data)
        bytes_written = 0

        while bytes_written < total_size:
            chunk_size = min(BUFFER_SIZE, total_size - bytes_written)
            chunk = data[bytes_written:bytes_written+chunk_size]
            temp_input.write(chunk)
            bytes_written += chunk_size

        temp_input.flush()
        temp_input.close()

        # 解析攻撃対策のダミー処理
        dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()
        dummy_path = []

        # ファイルをブロック単位で読み込み・復号化・書き込み
        with open(temp_input.name, 'rb') as f_in, open(temp_output.name, 'wb') as f_out:
            block_index = 0
            total_blocks = (total_size + block_size - 1) // block_size

            # 進捗表示用
            progress_interval = max(1, total_blocks // 20)  # 5%ごとに表示
            progress_next = progress_interval

            while True:
                block = f_in.read(block_size)
                if not block:
                    break

                # 現在の状態を取得
                state_idx = min(block_index, len(path) - 1)
                state_id = path[state_idx]
                state = engine.states.get(state_id)

                # ダミーパスの更新（解析対策）
                dummy_path.append(state_id)

                # ブロックを復号化
                decrypted_block = _decrypt_block(block, engine, state, state_id, block_index, dummy_key)

                # 復号化したブロックを書き込む
                f_out.write(decrypted_block)

                # 進捗表示
                block_index += 1
                if block_index >= progress_next:
                    print(f"復号化進捗: {block_index * 100 // total_blocks}% ({block_index}/{total_blocks})")
                    progress_next += progress_interval

                # メモリ使用量を定期的に確認し、必要に応じてGCを促進
                if block_index % 1000 == 0:
                    # ダミー変数の明示的なクリア
                    decrypted_block = None
                    block = None
                    import gc
                    gc.collect()

        # ダミー処理（セキュリティ対策）
        for i, state_id in enumerate(dummy_path):
            dummy_seed = hashlib.sha256(f"dummy_{i}_{state_id}".encode() + dummy_key).digest()

        # 復号化されたデータを読み込む（チャンク単位）
        result = bytearray()
        with open(temp_output.name, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                result.extend(chunk)

        return bytes(result)

    except Exception as e:
        print(f"大きなデータの復号化中にエラーが発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        raise
    finally:
        # 一時ファイルを必ず削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


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


def decrypt_file(encrypted_path: str, key_path: str, output_path: str = None) -> bool:
    """
    暗号化ファイルを復号する

    メモリ効率と堅牢性を向上させた実装です。

    Args:
        encrypted_path: 暗号化ファイルのパス
        key_path: 鍵ファイルのパス
        output_path: 出力ファイルのパス（省略時は暗号化ファイル名から.encを除いたもの）

    Returns:
        復号化が成功したかどうか
    """
    try:
        # 入力ファイルの存在確認
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"暗号化ファイル '{encrypted_path}' が見つかりません")

        if not os.path.exists(key_path):
            raise FileNotFoundError(f"鍵ファイル '{key_path}' が見つかりません")

        # 出力パスのデフォルト設定
        if not output_path:
            # 入力パスから.encを削除したものをデフォルトとする
            if encrypted_path.lower().endswith('.enc'):
                output_path = encrypted_path[:-4]
            else:
                output_path = f"{encrypted_path}.dec"

        # 鍵ファイルの読み込み
        print(f"鍵ファイル '{key_path}' を読み込み中...")
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
                if not key_data:
                    raise ValueError("鍵ファイルが空です")

                key_info = json.loads(key_data.decode('utf-8'))
        except json.JSONDecodeError:
            raise ValueError("鍵ファイルの形式が不正です。JSON形式である必要があります。")

        # 鍵情報の検証
        if "version" not in key_info or key_info["version"] != VERSION:
            raise ValueError(f"鍵のバージョンが一致しません。期待: {VERSION}, 実際: {key_info.get('version')}")

        # マスター鍵の取得
        try:
            master_key = base64.b64decode(key_info["master_key"])
        except:
            raise ValueError("マスター鍵のデコードに失敗しました")

        # 暗号化データの取得
        try:
            encrypted_data = base64.b64decode(key_info["encrypted_data"])
        except:
            raise ValueError("暗号化データのデコードに失敗しました")

        # チェックサムの検証
        if key_info.get("checksum") != hashlib.sha256(encrypted_data).hexdigest():
            raise ValueError("チェックサムが一致しません。鍵ファイルが改ざんされている可能性があります。")

        # 機密データの復号
        encryption_key = hashlib.pbkdf2_hmac('sha256', master_key, b'key_encryption', 10000)
        encryption_iv = hashlib.sha256(master_key + b'iv_for_key').digest()[:16]

        try:
            decrypted_sensitive = basic_decrypt(encrypted_data, encryption_key, encryption_iv)
            sensitive_data = json.loads(decrypted_sensitive.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"機密データの復号に失敗しました: {e}")

        # パスと状態シードの取得
        primary_path = sensitive_data["primary_path"]
        alternative_path = sensitive_data["alternative_path"]

        # ファイルタイプの取得
        is_text = key_info.get("file_type") == "text"

        # 状態シードの復元
        state_seeds = {}
        for state_id, seed_b64 in sensitive_data["state_seeds"].items():
            try:
                state_seeds[int(state_id)] = base64.b64decode(seed_b64)
            except:
                raise ValueError(f"状態シード {state_id} のデコードに失敗しました")

        # エンジンの初期化
        engine = ProbabilisticExecutionEngine()
        engine.key = master_key

        # 状態の復元
        for state_id, seed in state_seeds.items():
            engine.add_state(state_id, seed)

        # 暗号化ファイルの読み込み
        print(f"暗号化ファイル '{encrypted_path}' を読み込み中...")
        with MemoryOptimizedReader(encrypted_path) as reader:
            encrypted_content = reader.read_all()

            if not encrypted_content:
                raise ValueError("暗号化ファイルが空です")

            # ファイルの復号化
            print("ファイルを復号中...")
            decrypted_data = state_based_decrypt(encrypted_content, engine, "primary")

            # 出力ファイル名にタイムスタンプを追加（上書き防止）
            timestamp_str = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            output_file_parts = os.path.splitext(output_path)
            timestamped_output_path = f"{output_file_parts[0]}_{timestamp_str}{output_file_parts[1]}"

            # メモリ最適化ライターを使用して書き込み
            print(f"復号化データを '{timestamped_output_path}' に書き込み中...")
            with MemoryOptimizedWriter(timestamped_output_path) as writer:
                writer.write(decrypted_data)

            # ファイルのモード設定
            os.chmod(timestamped_output_path, 0o644)  # rw-r--r--

            print(f"復号化が完了しました: {timestamped_output_path}")
            print(f"ファイルタイプ: {'テキスト' if is_text else 'バイナリ'}")

            return True

    except Exception as e:
        print(f"復号化エラー: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def main():
    """
    メイン実行関数
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式 - 復号プログラム")
    parser.add_argument('--input', '-i', dest='input_path', required=True,
                        help='暗号化ファイルのパス')
    parser.add_argument('--key', '-k', dest='key_path', required=True,
                        help='鍵ファイルのパス')
    parser.add_argument('--output', '-o', dest='output_path',
                        help='出力ファイルパス（省略時は暗号化ファイル名から.encを除いたもの）')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='詳細モード')

    args = parser.parse_args()

    # 詳細モードの設定
    if args.verbose:
        print("詳細モード有効")
        print(f"入力ファイル: {args.input_path}")
        print(f"鍵ファイル: {args.key_path}")
        print(f"出力ファイル: {args.output_path or '<入力ファイル名>.dec'}")

    # 入力ファイルの存在確認
    if not os.path.exists(args.input_path):
        print(f"エラー: 入力ファイル '{args.input_path}' が見つかりません", file=sys.stderr)
        return 1

    if not os.path.exists(args.key_path):
        print(f"エラー: 鍵ファイル '{args.key_path}' が見つかりません", file=sys.stderr)
        return 1

    # 復号化実行
    success = decrypt_file(
        encrypted_path=args.input_path,
        key_path=args.key_path,
        output_path=args.output_path
    )

    if success:
        print("\n復号化が正常に完了しました")
        return 0
    else:
        print("\n復号化に失敗しました", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())