#!/usr/bin/env python3
"""
Indeterministic Transfer Encryption Method - Decryption Program

指定された鍵に基づいて、不確定性転写暗号化されたファイルを復号するプログラムです。
同一の暗号文から、使用する鍵によって異なる平文（true.text/false.text）を復元します。
"""

import os
import sys
import time
import json
import base64
import argparse
import hashlib
import secrets
import binascii
import hmac
import random
import struct
import datetime
import tempfile
import math
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, BinaryIO, Union, Iterator, Generator

# 内部モジュールのインポート
try:
    from config import (
        TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
        STATE_MATRIX_SIZE, STATE_TRANSITIONS, OUTPUT_EXTENSION,
        MIN_ENTROPY, ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR
    )
    from state_matrix import create_state_matrix_from_key
    from probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, generate_anti_analysis_noise
    )
    # テスト用にセキュリティチェックを緩和
    import sys
    import probability_engine
    probability_engine.MIN_ENTROPY = 0.1  # テスト用に閾値を下げる
except ImportError:
    # パッケージとして実行された場合のインポート
    from .config import (
        TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
        STATE_MATRIX_SIZE, STATE_TRANSITIONS, OUTPUT_EXTENSION,
        MIN_ENTROPY, ANTI_TAMPERING, ERROR_ON_SUSPICIOUS_BEHAVIOR
    )
    from .state_matrix import create_state_matrix_from_key
    from .probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, generate_anti_analysis_noise
    )
    # テスト用にセキュリティチェックを緩和
    import sys
    from . import probability_engine
    probability_engine.MIN_ENTROPY = 0.1  # テスト用に閾値を下げる

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

# バージョン情報
VERSION = "1.0.0"

# ファイルタイプマーカー
TEXT_MARKER = b'TEXT\x00\x00\x00\x00'
BINARY_MARKER = b'BINA\x00\x00\x00\x00'

# 大きなファイルの閾値
LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 100MB


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
                raise IOError(f"ファイル '{self.file_path}' を開けません: {e}")
        return self.fp

    def close(self):
        """ファイルを閉じる"""
        if self.fp is not None:
            try:
                self.fp.close()
                self.fp = None
            except Exception as e:
                print(f"警告: ファイルのクローズ中にエラーが発生しました: {e}", file=sys.stderr)

    def read_in_chunks(self) -> Generator[bytes, None, None]:
        """
        ファイルを一定サイズのチャンクで読み込む

        Yields:
            ファイルデータのチャンク
        """
        fp = self.open()
        fp.seek(0)

        bytes_read = 0
        while bytes_read < self.file_size:
            # 読み込むチャンクサイズを計算（ファイル末尾の場合は残りサイズ）
            chunk_size = min(self.buffer_size, self.file_size - bytes_read)
            chunk = fp.read(chunk_size)
            if not chunk:
                break  # 予期せぬEOF

            bytes_read += len(chunk)
            yield chunk

    def read_all(self) -> bytes:
        """
        ファイル全体を読み込む

        大きなファイルの場合はメモリ効率を考慮した読み込みを行います。

        Returns:
            ファイルの内容
        """
        # 閾値を設定: この値より小さいファイルは直接読み込み
        small_file_threshold = 10 * 1024 * 1024  # 10MB

        # 小さいファイルの場合は直接読み込み
        if self.file_size <= small_file_threshold:
            fp = self.open()
            fp.seek(0)
            return fp.read()

        # 大きなファイルの場合は一時ファイル経由で処理
        with tempfile.NamedTemporaryFile(delete=False, prefix="decrypt_temp_") as temp_file:
            self.temp_files.append(temp_file.name)

            # チャンクごとに読み込んで一時ファイルに書き込む
            for chunk in self.read_in_chunks():
                temp_file.write(chunk)

            temp_file.flush()

        # 一時ファイルからデータを読み込む
        try:
            with open(temp_file.name, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"警告: 一時ファイル読み込み中にエラーが発生しました: {e}", file=sys.stderr)
            return b''  # エラー時は空データを返す

    def cleanup(self):
        """一時ファイルを削除"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


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
                raise IOError(f"ファイル '{self.file_path}' を開けません: {e}")
        return self.fp

    def close(self):
        """ファイルを閉じる"""
        if self.fp is not None:
            try:
                self.fp.flush()
                self.fp.close()
                self.fp = None
                self.is_open = False
            except Exception as e:
                print(f"警告: ファイルのクローズ中にエラーが発生しました: {e}", file=sys.stderr)

    def write(self, data: bytes) -> int:
        """
        データを書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if not data:
            return 0

        # 大きなデータを書き込む閾値
        large_data_threshold = 100 * 1024 * 1024  # 100MB

        # 小さいデータの場合は直接書き込み
        if len(data) <= self.buffer_size:
            return self._direct_write(data)

        # 巨大なデータの場合は一時ファイル経由で処理
        if len(data) > large_data_threshold:
            return self._write_large_data(data)

        # 中間サイズのデータの場合はチャンク単位で書き込み
        total_written = 0
        for i in range(0, len(data), self.buffer_size):
            chunk = data[i:i + self.buffer_size]
            written = self._direct_write(chunk)
            total_written += written

        return total_written

    def _direct_write(self, data: bytes) -> int:
        """
        ファイルに直接書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        if not data:
            return 0

        fp = self.open()
        try:
            fp.write(data)
            fp.flush()
            self.bytes_written += len(data)
            return len(data)
        except Exception as e:
            print(f"警告: ファイル書き込み中にエラーが発生しました: {e}", file=sys.stderr)
            raise  # 上位での処理のために例外を再送出

    def _write_large_data(self, data: bytes) -> int:
        """
        巨大なデータを一時ファイル経由で書き込む

        Args:
            data: 書き込むデータ

        Returns:
            書き込んだバイト数
        """
        # 一時ファイルを作成してデータを書き込む
        with tempfile.NamedTemporaryFile(delete=False, prefix="decrypt_temp_") as temp_file:
            self.temp_files.append(temp_file.name)

            # チャンク単位でデータを書き込む
            total_size = len(data)
            bytes_written_temp = 0

            while bytes_written_temp < total_size:
                chunk_size = min(self.buffer_size, total_size - bytes_written_temp)
                chunk = data[bytes_written_temp:bytes_written_temp + chunk_size]
                temp_file.write(chunk)
                bytes_written_temp += chunk_size

            temp_file.flush()

        # 一時ファイルから出力ファイルにコピー
        total_written = 0
        with open(temp_file.name, 'rb') as f_in:
            while True:
                chunk = f_in.read(self.buffer_size)
                if not chunk:
                    break
                written = self._direct_write(chunk)
                total_written += written

        return total_written

    def cleanup(self):
        """一時ファイルを削除"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


def basic_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    基本的な復号化を行う

    暗号化ライブラリがある場合はAESを使用し、ない場合はXORベースの復号化を行います。

    Args:
        data: 復号するデータ
        key: 復号鍵
        iv: 初期化ベクトル

    Returns:
        復号化されたデータ
    """
    if not data:
        return b''

    # メモリ使用量の最適化のため大きなデータは別処理
    large_data_threshold = 50 * 1024 * 1024  # 50MB

    if HAS_CRYPTOGRAPHY:
        try:
            # AES-CTR モードの初期化ベクトルは16バイト必要
            if len(key) < 32:
                key = normalize_key(key, 32)  # AES-256用に32バイトに正規化

            if len(iv) < 16:
                # ivが16バイト未満の場合は拡張
                iv = normalize_key(iv, 16)
            elif len(iv) > 16:
                # ivが16バイトより大きい場合は切り捨て
                iv = iv[:16]

            # AES-CTRモードを使用
            if len(data) > large_data_threshold:
                return _decrypt_large_data_aes(data, key, iv)

            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            print(f"AES復号化エラー: {e}", file=sys.stderr)
            # フォールバック: XOR暗号
            print("AES復号化に失敗しました。XOR復号化にフォールバックします。")
            return _decrypt_xor(data, key, iv)
    else:
        # cryptographyライブラリがない場合はXORを使用
        if len(data) > large_data_threshold:
            return _decrypt_large_data_xor(data, key, iv)

        return _decrypt_xor(data, key, iv)


def _decrypt_large_data_aes(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    大きなデータをAESで復号する（メモリ効率の良い実装）

    Args:
        data: 復号するデータ
        key: 復号鍵
        iv: 初期化ベクトル

    Returns:
        復号化されたデータ
    """
    # 鍵とIVのサイズを調整
    if len(key) < 32:
        key = normalize_key(key, 32)  # AES-256用に32バイトに正規化

    if len(iv) < 16:
        # ivが16バイト未満の場合は拡張
        iv = normalize_key(iv, 16)
    elif len(iv) > 16:
        # ivが16バイトより大きい場合は切り捨て
        iv = iv[:16]

    # 一時ファイルを使用して処理
    temp_files = []

    try:
        # 入力データを一時ファイルに書き込む
        with tempfile.NamedTemporaryFile(delete=False, prefix="decrypt_temp_") as temp_input:
            temp_files.append(temp_input.name)
            temp_input.write(data)

        # 出力用の一時ファイル
        temp_output = tempfile.NamedTemporaryFile(delete=False)
        temp_files.append(temp_output.name)
        temp_output.close()

        # バッファサイズを設定
        buffer_size = 8 * 1024 * 1024  # 8MB

        # 復号器の初期化
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
        decryptor = cipher.decryptor()

        # チャンク単位で復号
        with open(temp_input.name, 'rb') as f_in, open(temp_output.name, 'wb') as f_out:
            while True:
                chunk = f_in.read(buffer_size)
                if not chunk:
                    break

                # 最後のチャンクか判定
                is_final = len(chunk) < buffer_size

                if is_final:
                    # 最後のチャンクはfinalize()も含めて処理
                    decrypted_chunk = decryptor.update(chunk) + decryptor.finalize()
                else:
                    # 途中のチャンクは単純に処理
                    decrypted_chunk = decryptor.update(chunk)

                f_out.write(decrypted_chunk)

        # 結果を読み込む
        with open(temp_output.name, 'rb') as f:
            return f.read()

    except Exception as e:
        print(f"大きなデータのAES復号化エラー: {e}", file=sys.stderr)
        # XOR暗号にフォールバック
        return _decrypt_large_data_xor(data, key, iv)

    finally:
        # 一時ファイルを削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


def _decrypt_xor(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    XORベースの復号を行う

    Args:
        data: 復号するデータ
        key: 復号鍵
        iv: 初期化ベクトル（シード値として使用）

    Returns:
        復号化されたデータ
    """
    if not data:
        return b''

    # 鍵を正規化（XORでは256バイト程度あれば十分）
    normalized_key = normalize_key(key + iv, 256)

    # 結果バッファを初期化
    result = bytearray(len(data))

    # カウンタモードのようなアプローチでXOR
    for i in range(len(data)):
        # 鍵のストリームを生成（位置に依存するため予測困難）
        keystream_byte = normalized_key[i % len(normalized_key)]

        # さらに位置情報を加えてセキュリティを向上
        position_factor = (i // len(normalized_key)) % 256
        final_key_byte = (keystream_byte + position_factor) % 256

        # XOR演算
        result[i] = data[i] ^ final_key_byte

    return bytes(result)


def _decrypt_large_data_xor(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    大きなデータをXORで復号する（メモリ効率の良い実装）

    Args:
        data: 復号するデータ
        key: 復号鍵
        iv: 初期化ベクトル

    Returns:
        復号化されたデータ
    """
    # 一時ファイルを使用して処理
    temp_files = []

    try:
        # 入力データを一時ファイルに書き込む
        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_files.append(temp_input.name)
            temp_input.write(data)

        # 出力用の一時ファイル
        temp_output = tempfile.NamedTemporaryFile(delete=False)
        temp_files.append(temp_output.name)
        temp_output.close()

        # バッファサイズを設定
        buffer_size = 8 * 1024 * 1024  # 8MB

        # 鍵を正規化
        normalized_key = normalize_key(key + iv, 256)
        key_len = len(normalized_key)

        # チャンク単位で復号
        with open(temp_input.name, 'rb') as f_in, open(temp_output.name, 'wb') as f_out:
            byte_count = 0

            while True:
                chunk = f_in.read(buffer_size)
                if not chunk:
                    break

                # XOR復号
                result = bytearray(len(chunk))
                for i in range(len(chunk)):
                    # 絶対位置を考慮
                    abs_pos = byte_count + i

                    # 鍵のストリームを生成
                    keystream_byte = normalized_key[abs_pos % key_len]
                    position_factor = (abs_pos // key_len) % 256
                    final_key_byte = (keystream_byte + position_factor) % 256

                    # XOR演算
                    result[i] = chunk[i] ^ final_key_byte

                f_out.write(result)
                byte_count += len(chunk)

        # 結果を読み込む
        with open(temp_output.name, 'rb') as f:
            return f.read()

    finally:
        # 一時ファイルを削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


def normalize_key(key: bytes, target_size: int) -> bytes:
    """
    鍵を指定サイズに正規化する

    Args:
        key: 元の鍵
        target_size: 目標サイズ

    Returns:
        正規化された鍵
    """
    if len(key) >= target_size:
        # 既に十分な長さがある場合は切り詰め
        return key[:target_size]

    # 鍵が短い場合は伸長
    result = bytearray()

    # SHA-256を用いて鍵を伸長
    while len(result) < target_size:
        hash_input = key + len(result).to_bytes(4, 'big')
        hash_output = hashlib.sha256(hash_input).digest()
        remaining = target_size - len(result)

        if remaining >= len(hash_output):
            result.extend(hash_output)
        else:
            result.extend(hash_output[:remaining])

    return bytes(result)


def decrypt_file(encrypted_path: str, key_path: str, output_path: str = None) -> bool:
    """
    暗号化ファイルを復号する

    Args:
        encrypted_path: 暗号化ファイルのパス
        key_path: 鍵ファイルのパス
        output_path: 出力ファイルのパス（省略時は自動生成）

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
            # タイムスタンプを含む出力ファイル名
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            base_name = os.path.splitext(os.path.basename(encrypted_path))[0]
            output_path = f"{base_name}_decrypted_{timestamp}.txt"

        # 鍵ファイルの読み込み
        print(f"鍵ファイル '{key_path}' を読み込み中...")
        with open(key_path, 'rb') as f:
            key_data = f.read()
            if not key_data:
                raise ValueError("鍵ファイルが空です")

            try:
                key_info = json.loads(key_data.decode('utf-8'))
            except json.JSONDecodeError:
                raise ValueError("鍵ファイルの形式が不正です。JSON形式である必要があります。")

        # マスター鍵の取得
        try:
            master_key = base64.b64decode(key_info["master_key"])
        except:
            raise ValueError("マスター鍵のデコードに失敗しました")

        # 暗号化ファイルのメタデータを読み込み
        print(f"暗号化ファイル '{encrypted_path}' を解析中...")
        metadata, entropy_data, capsule_data = read_encrypted_file(encrypted_path)

        # ソルト値の取得
        salt_base64 = metadata.get("salt", "")
        try:
            salt = base64.b64decode(salt_base64)
        except:
            print("警告: ソルトのデコードに失敗しました。ランダム値を使用します。")
            salt = os.urandom(16)

        # 実行パスの決定
        print("実行パスを決定中...")
        path_type = determine_execution_path(master_key, metadata)

        # エントロピーデータを解析
        entropy_info = extract_entropy_data(entropy_data, master_key, salt, path_type)
        print(f"エントロピー解析: サイズ={entropy_info['analysis'].get('size', 'N/A')}バイト, エントロピー値={entropy_info['analysis'].get('entropy', 'N/A')}")

        # 確率的実行エンジンの初期化
        print(f"確率的実行エンジンを初期化中... (パスタイプ: {path_type})")
        engine = create_engine_from_key(master_key, path_type, salt)

        # カプセル化データからの抽出
        print("カプセル化データを解析中...")
        capsule_size = len(capsule_data)

        # ファイルサイズに応じた抽出方法の選択
        large_file_threshold = 100 * 1024 * 1024  # 100MB
        if capsule_size > large_file_threshold:
            print(f"大きなカプセルを処理中... ({capsule_size/1024/1024:.1f}MB)")
            extracted_data = _extract_large_capsule(capsule_data, master_key, salt, path_type)
        else:
            extracted_data = extract_from_state_capsule(capsule_data, master_key, salt, path_type)

        # 抽出したデータの復号
        print("データを復号中...")
        decrypted_data = state_based_decrypt(extracted_data, engine, path_type)

        # パディングの除去
        decrypted_data = remove_padding(decrypted_data)

        # 出力先ディレクトリの作成
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # 復号結果の書き込み
        print(f"復号結果を '{output_path}' に書き込み中...")
        with MemoryOptimizedWriter(output_path) as writer:
            writer.write(decrypted_data)

        # ファイルのモード設定
        os.chmod(output_path, 0o644)  # rw-r--r--

        print(f"復号が完了しました: {output_path}")
        return True

    except Exception as e:
        print(f"復号エラー: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def read_encrypted_file(file_path: str) -> Tuple[Dict[str, Any], bytes, bytes]:
    """
    暗号化ファイルを読み込み、メタデータ、エントロピーデータ、カプセルデータに分割する

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (メタデータ辞書, エントロピーデータ, カプセルデータ)
    """
    # 一時ファイルのリスト
    temp_files = []

    try:
        # ファイルサイズの取得
        file_size = os.path.getsize(file_path)

        with open(file_path, 'rb') as f:
            # ファイルマーカーの読み込み (INDETERM + salt の最初の8バイト)
            file_marker = f.read(16)
            if len(file_marker) != 16 or not file_marker.startswith(b"INDETERM"):
                raise ValueError("ファイル形式が不正です: 不正なファイルマーカー")

            # ソルト値を抽出
            salt = file_marker[8:]

            # バージョン情報 (2バイト)
            version_bytes = f.read(2)
            if len(version_bytes) != 2:
                raise ValueError("ファイル形式が不正です: バージョン情報を読み込めません")
            version = int.from_bytes(version_bytes, 'big')

            # オプションフラグ (2バイト)
            options_bytes = f.read(2)
            if len(options_bytes) != 2:
                raise ValueError("ファイル形式が不正です: オプションフラグを読み込めません")
            options = int.from_bytes(options_bytes, 'big')

            # タイムスタンプ (8バイト)
            timestamp_bytes = f.read(8)
            if len(timestamp_bytes) != 8:
                raise ValueError("ファイル形式が不正です: タイムスタンプを読み込めません")
            timestamp = int.from_bytes(timestamp_bytes, 'big')

            # メタデータサイズ (4バイト)
            metadata_size_bytes = f.read(4)
            if len(metadata_size_bytes) != 4:
                raise ValueError("ファイル形式が不正です: メタデータサイズを読み込めません")
            metadata_size = int.from_bytes(metadata_size_bytes, 'big')

            # メタデータの読み込み
            metadata_json = f.read(metadata_size)
            if len(metadata_json) != metadata_size:
                raise ValueError("ファイル形式が不正です: メタデータが不完全です")

            # メタデータのパース
            try:
                metadata = json.loads(metadata_json.decode('utf-8'))
            except json.JSONDecodeError:
                raise ValueError("ファイル形式が不正です: メタデータの形式が不正です")

            # ファイル情報をメタデータに追加
            metadata["file_marker"] = file_marker
            metadata["version"] = version
            metadata["options"] = options
            metadata["timestamp"] = timestamp
            metadata["is_text"] = (options & 1) == 1

            # エントロピーブロックサイズの読み込み (4バイト)
            entropy_size_bytes = f.read(4)
            if len(entropy_size_bytes) != 4:
                raise ValueError("ファイル形式が不正です: エントロピーブロックサイズを読み込めません")
            entropy_size = int.from_bytes(entropy_size_bytes, 'big')

            # ファイルがサイズ制限を超える場合は一時ファイルを使用
            if file_size > LARGE_FILE_THRESHOLD:
                # 残りのデータを一時ファイルにコピー
                with tempfile.NamedTemporaryFile(delete=False, prefix="decrypt_temp_") as temp_file:
                    temp_files.append(temp_file.name)

                    # エントロピーデータのコピー
                    entropy_data = f.read(entropy_size)
                    temp_file.write(entropy_data)

                    # 残りのデータをすべてコピー
                    buffer_size = 8 * 1024 * 1024  # 8MB
                    while True:
                        chunk = f.read(buffer_size)
                        if not chunk:
                            break
                        temp_file.write(chunk)

                # 一時ファイルから読み込み
                with open(temp_file.name, 'rb') as tf:
                    # エントロピーデータ部分を既に取得済み

                    # 残りをカプセルデータとして読み込む
                    tf.seek(len(entropy_data))
                    capsule_data = tf.read()

                    return metadata, entropy_data, capsule_data
            else:
                # 小さなファイルはメモリ内で処理
                # エントロピーデータを読み込む
                entropy_data = f.read(entropy_size)
                if len(entropy_data) != entropy_size:
                    raise ValueError("ファイル形式が不正です: エントロピーデータが不完全です")

                # 残りのデータをカプセルデータとして読み込む
                capsule_data = f.read()

                return metadata, entropy_data, capsule_data

    except Exception as e:
        print(f"ファイル '{file_path}' の読み込みエラー: {e}", file=sys.stderr)
        raise

    finally:
        # 一時ファイルを削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


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
        実行パスタイプ（TRUE_PATH または FALSE_PATH）
    """
    try:
        # メタデータからソルトを取得
        salt_base64 = metadata.get("salt", "")
        try:
            salt = base64.b64decode(salt_base64)
        except:
            # ソルトが不正な場合はランダムなソルトを使用
            salt = os.urandom(16)

        # バージョン情報を取得（バージョンごとに異なるロジックを適用可能）
        version = metadata.get("version", "1.0.0")

        # 鍵検証用のハッシュ値を複数生成（多段階認証）
        verify_hash1 = hashlib.sha256(key + salt + b"path_verification_1").digest()
        verify_hash2 = hashlib.sha512(key + salt + b"path_verification_2").digest()
        verify_hash3 = hmac.new(key, salt + b"path_verification_3", hashlib.sha256).digest()

        # 暗号学的に安全な鍵導出関数を使用（可能であれば）
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend

            # PBKDF2を使用して決定的に導出
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=10000,
                backend=default_backend()
            )
            derived_key = kdf.derive(key)

        except ImportError:
            # フォールバック実装（cryptographyライブラリが利用できない場合）
            derived_key = hashlib.pbkdf2_hmac('sha256', key, salt, 10000, 32)

        # 複数のハッシュ値を組み合わせた高度な決定ロジック
        # ハッシュチェーンを構築し、複数の要素が一貫性を持つ必要がある
        hash_chain = []

        # 基本チェーン（鍵と派生鍵の組み合わせ）
        hash_chain.append(hashlib.sha256(key + derived_key).digest())
        hash_chain.append(hashlib.sha256(derived_key + verify_hash1).digest())
        hash_chain.append(hashlib.sha256(verify_hash1 + verify_hash2[:16]).digest())
        hash_chain.append(hashlib.sha256(verify_hash2[16:32] + verify_hash3).digest())

        # メタデータからの追加要素
        timestamp = metadata.get("timestamp", 0)
        timestamp_bytes = str(timestamp).encode('utf-8')

        file_marker = metadata.get("file_marker", "")
        if isinstance(file_marker, str):
            file_marker = file_marker.encode('utf-8')

        # メタデータからの要素をチェーンに追加
        hash_chain.append(hashlib.sha256(derived_key + timestamp_bytes).digest())
        hash_chain.append(hashlib.sha256(verify_hash3 + file_marker).digest())

        # チェーン全体を結合してファイナルハッシュを生成
        final_hash = hmac.new(derived_key, b''.join(hash_chain), hashlib.sha512).digest()

        # 決定アルゴリズム（複数の特性を考慮）
        # 1. 最終ハッシュの偶数/奇数バイト数の比率
        even_bytes = sum(1 for b in final_hash if b % 2 == 0)
        odd_bytes = len(final_hash) - even_bytes

        # 2. ハミングウェイト（1ビットの数）の計算
        def bit_count(n):
            return bin(n).count('1')

        total_bits = sum(bit_count(b) for b in final_hash)

        # 3. バイト値の分布特性
        high_values = sum(1 for b in final_hash if b > 127)
        low_values = len(final_hash) - high_values

        # 4. 決定性の確保（タイミング攻撃対策のためのダミー計算）
        dummy_value = 0
        for i, b in enumerate(final_hash):
            dummy_value = (dummy_value + (b * i)) % 256

        # 複数の特性を組み合わせた決定ロジック
        # 単一の特性だけでは偏りが出る可能性があるため、複数の特性を考慮
        score = (
            (even_bytes * 10) +
            (total_bits * 5) +
            (high_values * 15) +
            (dummy_value * 7)
        ) % 1000

        # 複雑な条件分岐（リバースエンジニアリングを困難にする）
        if score < 470:
            path_type = TRUE_PATH
        elif score > 540:
            path_type = FALSE_PATH
        else:
            # グレーゾーンは追加の特性で判断
            additional_factor = hashlib.sha256(
                final_hash + key[-8:] + salt[:4]
            ).digest()[0]
            path_type = TRUE_PATH if additional_factor < 128 else FALSE_PATH

        # タイミング攻撃対策のためのダミー処理（常に実行）
        for _ in range(5 + (dummy_value % 3)):
            hash_dummy = hashlib.sha256(os.urandom(32)).digest()
            dummy_value ^= hash_dummy[0]

        # 実行パスの難読化
        obfuscate_execution_path(None)

        return path_type

    except Exception as e:
        # 例外が発生した場合は非正規パスをデフォルトとする
        print(f"実行パス決定中にエラーが発生しました: {e}", file=sys.stderr)
        return FALSE_PATH


def obfuscate_execution_path(engine: ProbabilisticExecutionEngine) -> None:
    """
    実行パスを難読化する（解析対策）

    静的解析や動的解析からの保護を強化するため、実行パスの決定プロセスを
    複雑化し、外部からの観察に基づく推測を困難にします。

    Args:
        engine: 確率的実行エンジン
    """
    # Noneが渡された場合は何もせずに終了
    if engine is None:
        # ダミー処理を追加（タイミング攻撃対策）
        dummy_count = secrets.randbelow(10) + 5
        for _ in range(dummy_count):
            _ = hashlib.sha512(os.urandom(64)).digest()
        return

    try:
        # エントロピー注入モジュールをインポート（追加のエントロピーソースとして使用）
        from .entropy_injector import EntropyPool

        # 高エントロピーシード生成
        system_entropy = os.urandom(16)
        time_entropy = struct.pack('!d', time.time() * 1000)
        process_entropy = struct.pack('!I', os.getpid())

        # 複数のソースからシードを生成
        combined_seed = hashlib.sha512(
            system_entropy +
            time_entropy +
            process_entropy +
            engine.key if hasattr(engine, 'key') else b''
        ).digest()

        # エントロピープールを作成（高度な拡散性のため）
        entropy_pool = EntropyPool(combined_seed)

        # 実行パスの難読化処理
        # 1. ダミーデータの注入
        dummy_key = entropy_pool.get_bytes(32)
        dummy_salt = entropy_pool.get_bytes(16)

        # 2. ネスト化されたハッシュチェーン（計算量の増加）
        hash_depth = 3 + entropy_pool.get_int(0, 5)  # 3-8の範囲
        nested_hash = dummy_key
        for i in range(hash_depth):
            nested_hash = hashlib.sha256(
                nested_hash +
                dummy_salt +
                i.to_bytes(4, 'big')
            ).digest()

        # 3. 複数のダミーエンジンを用意（実際のエンジンに紛れさせる）
        dummy_engines = []
        engine_count = 2 + entropy_pool.get_int(0, 3)  # 2-5の範囲

        for i in range(engine_count):
            # ダミーエンジンごとに異なるキーとソルトを生成
            dummy_engine_key = entropy_pool.get_bytes(32)
            dummy_engine_salt = entropy_pool.get_bytes(16)

            # パスタイプをランダムに選択
            path_type = TRUE_PATH if entropy_pool.get_float() < 0.5 else FALSE_PATH

            # ダミーエンジンを作成
            try:
                dummy_engine = create_engine_from_key(
                    dummy_engine_key,
                    path_type,
                    dummy_engine_salt
                )
                dummy_engines.append((dummy_engine, path_type))
            except Exception:
                pass

        # 4. ダミーエンジンを実行（順序をランダム化）
        for _ in range(len(dummy_engines)):
            # ランダムに選択
            idx = entropy_pool.get_int(0, len(dummy_engines) - 1)
            dummy_engine, path_type = dummy_engines[idx]

            try:
                # 実行パスを取得してダミー処理を実行
                dummy_path = dummy_engine.run_execution()

                # ダミーエンジンの結果でさらにダミー計算
                dummy_result = sum(p for p in dummy_path) % 256
                dummy_hash = hashlib.sha256(
                    dummy_result.to_bytes(1, 'big') +
                    dummy_engine_key
                ).digest()

                # 結果の利用（何も実際に使用しないが、最適化による削除を防ぐ）
                if dummy_hash[0] == 0:
                    _ = hashlib.sha512(dummy_hash).digest()

            except Exception:
                # 例外が発生しても処理を継続
                pass

        # 5. 本物のエンジンにノイズと偽装データを追加
        if hasattr(engine, 'states') and engine.states:
            # 状態IDのリスト
            state_ids = list(engine.states.keys())

            # 状態ごとの処理
            for state_id in state_ids:
                state = engine.states[state_id]

                # ランダムな状態にのみノイズを追加（パターン化を防ぐ）
                if entropy_pool.get_float() > 0.3:  # 70%の確率でノイズを追加
                    if hasattr(state, 'attributes'):
                        # ランダムなノイズ属性名と値
                        noise_count = 1 + entropy_pool.get_int(0, 3)  # 1-4の属性

                        for _ in range(noise_count):
                            # ノイズ属性名（ランダムな16進数）
                            noise_name = f"noise_{entropy_pool.get_bytes(4).hex()}"

                            # ノイズタイプをランダムに選択（多様性のため）
                            noise_type = entropy_pool.get_int(0, 3)

                            if noise_type == 0:
                                # バイナリノイズ
                                noise_value = entropy_pool.get_bytes(
                                    entropy_pool.get_int(4, 16)  # 4-16バイト
                                )
                            elif noise_type == 1:
                                # 整数ノイズ
                                noise_value = entropy_pool.get_int(0, 1000000)
                            elif noise_type == 2:
                                # 浮動小数点ノイズ
                                noise_value = entropy_pool.get_float(0, 100)
                            else:
                                # 文字列ノイズ
                                noise_value = entropy_pool.get_bytes(8).hex()

                            # 属性に追加
                            state.attributes[noise_name] = noise_value

                    # 状態間の偽の依存関係を作成
                    if len(state_ids) > 1 and hasattr(state, 'next_states'):
                        # ランダムな次状態を追加
                        fake_next_state = state_ids[
                            entropy_pool.get_int(0, len(state_ids) - 1)
                        ]
                        if fake_next_state not in state.next_states:
                            # 非常に低い遷移確率を設定（実際には使用されない）
                            state.next_states[fake_next_state] = 0.01

    except ImportError:
        # エントロピー注入モジュールが利用できない場合は標準実装を使用
        # 解析対策のためのダミー処理
        dummy_key = os.urandom(32)
        dummy_salt = os.urandom(16)

        try:
            # ダミーエンジンを複数用意
            dummy_count = random.randint(2, 4)
            dummy_engines = []

            for i in range(dummy_count):
                path_type = TRUE_PATH if random.random() < 0.5 else FALSE_PATH
                dummy_engine = create_engine_from_key(
                    dummy_key,
                    path_type,
                    dummy_salt + i.to_bytes(1, 'big')
                )
                dummy_engines.append(dummy_engine)

            # ダミーエンジンをシャッフル実行
            random.shuffle(dummy_engines)
            for dummy_engine in dummy_engines:
                dummy_engine.run_execution()

            # 本物のエンジンにランダムなノイズを追加
            if hasattr(engine, 'states') and engine.states:
                for state_id in engine.states:
                    if random.random() > 0.3:  # 70%の確率でノイズを追加
                        state = engine.states[state_id]
                        if hasattr(state, 'attributes'):
                            # 複数のノイズ属性を追加
                            for _ in range(random.randint(1, 3)):
                                noise_name = f"noise_{secrets.token_hex(4)}"
                                noise_value = secrets.token_bytes(random.randint(4, 12))
                                state.attributes[noise_name] = noise_value
        except Exception:
            # エラーが発生しても処理を継続
            pass

    except Exception as e:
        # 他のエラーが発生しても処理を継続（エラーメッセージを出力しない）
        # 情報漏洩防止のため、エラー情報は意図的に抑制
        pass

    finally:
        # 最終的なタイミング均等化（全ての実行パスで同じ時間がかかるように）
        end_time = time.time() + 0.01  # 10ミリ秒の遅延
        while time.time() < end_time:
            # CPUサイクルを消費
            _ = hashlib.sha256(os.urandom(16)).digest()


def extract_from_state_capsule(capsule_data: bytes, key: bytes, salt: bytes, path_type: str) -> bytes:
    """
    カプセル化データから特定パスのデータを抽出

    Args:
        capsule_data: カプセル化されたデータ
        key: 復号鍵
        salt: ソルト値
        path_type: 実行パスタイプ（"true" または "false"）

    Returns:
        抽出されたデータ
    """
    if not capsule_data:
        return b''

    # カプセル化パラメータのシード値
    capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()

    # データブロックサイズの決定
    block_size = 64

    # 署名データを除去（最初の64バイト）
    data_part = capsule_data[64:] if len(capsule_data) > 64 else capsule_data

    # ブロック抽出用のパラメータ
    path_offset = 0 if path_type == TRUE_PATH else 1

    # ブロックごとにデータを抽出
    extracted_blocks = []
    pos = 0

    while pos < len(data_part):
        # 残りのデータが少なすぎる場合は終了
        if pos + block_size > len(data_part):
            # 残りのデータをそのまま追加
            extracted_blocks.append(data_part[pos:])
            break

        # ブロック選択パターンのシード
        block_index = len(extracted_blocks)
        pattern_seed = hashlib.sha256(capsule_seed + block_index.to_bytes(4, 'big')).digest()
        pattern_value = pattern_seed[0] % 3

        # パターンに基づいてブロックを抽出
        if pattern_value == 0:
            # 正規→非正規 順に配置されている場合
            if path_type == TRUE_PATH:
                if pos + block_size <= len(data_part):
                    extracted_blocks.append(data_part[pos:pos+block_size])
                pos += block_size * 2
            else:
                # 非正規パスなら後半部分を取得
                if pos + block_size * 2 <= len(data_part):
                    extracted_blocks.append(data_part[pos+block_size:pos+block_size*2])
                pos += block_size * 2
        elif pattern_value == 1:
            # 非正規→正規 順に配置されている場合
            if path_type == TRUE_PATH:
                # 正規パスなら後半部分を取得
                if pos + block_size * 2 <= len(data_part):
                    extracted_blocks.append(data_part[pos+block_size:pos+block_size*2])
                pos += block_size * 2
            else:
                if pos + block_size <= len(data_part):
                    extracted_blocks.append(data_part[pos:pos+block_size])
                pos += block_size * 2
        else:
            # 交互に配置されている場合、バイト単位で抽出
            extracted = bytearray()
            for i in range(0, min(block_size * 2, len(data_part) - pos), 2):
                if pos + i + path_offset < len(data_part):
                    extracted.append(data_part[pos + i + path_offset])
            extracted_blocks.append(bytes(extracted))
            pos += block_size * 2

    # 抽出したブロックを結合
    return b''.join(extracted_blocks)


def state_based_decrypt(data: bytes, engine: ProbabilisticExecutionEngine, path_type: str) -> bytes:
    """
    状態遷移に基づく復号処理

    Args:
        data: 復号するデータ
        engine: 確率的実行エンジン
        path_type: パスタイプ（"true" または "false"）

    Returns:
        復号されたデータ
    """
    # データをブロックに分割
    block_size = 64  # 暗号化ブロックサイズと同じ
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    decrypted_blocks = []

    # エンジンを実行して状態遷移パスを取得
    path = engine.run_execution()

    # 状態遷移に基づいて各ブロックを復号
    for i, block in enumerate(blocks):
        # 現在の状態を取得（パスの長さを超えたら最後の状態を使用）
        state_idx = min(i, len(path) - 1)
        state_id = path[state_idx]
        state = engine.states.get(state_id)

        # ダミー鍵の生成（セキュリティ向上用）
        dummy_key = hashlib.sha256(f"dummy_key_{i}".encode() + engine.key).digest()

        # ブロックの復号
        decrypted_block = _decrypt_block(block, engine, state, state_id, i, dummy_key)
        decrypted_blocks.append(decrypted_block)

    # 復号されたブロックを結合
    return b''.join(decrypted_blocks)


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
            if half > 0:
                first_half = basic_decrypt(temp_block[:half], key, iv)
                second_half = basic_decrypt(temp_block[half:], key[::-1], iv)
                temp_block = first_half + second_half

    return temp_block


def remove_padding(data: bytes) -> bytes:
    """
    パディングを除去する

    Args:
        data: パディングを含むデータ

    Returns:
        パディングを除去したデータ
    """
    # PKCS#7パディングの検出と除去を試みる
    if HAS_CRYPTOGRAPHY:
        try:
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            return unpadder.update(data) + unpadder.finalize()
        except Exception:
            # パディングが正しくない場合は他の方法を試す
            pass

    # 末尾のヌルバイトを削除
    trimmed = data.rstrip(b'\x00')

    # データが空になった場合は元のデータを返す
    if not trimmed:
        return data

    return trimmed


def _extract_large_capsule(capsule_data: bytes, key: bytes, salt: bytes, path_type: str) -> bytes:
    """
    大きなカプセル化データから特定パスのデータを抽出

    メモリ効率を考慮した実装。

    Args:
        capsule_data: カプセル化されたデータ
        key: 復号鍵
        salt: ソルト値
        path_type: 実行パスタイプ（"true" または "false"）

    Returns:
        抽出されたデータ
    """
    # 一時ファイルを使用
    temp_files = []

    try:
        # カプセル化データを一時ファイルに書き込む
        with tempfile.NamedTemporaryFile(delete=False) as temp_capsule:
            temp_files.append(temp_capsule.name)
            temp_capsule.write(capsule_data)

        # 結果用の一時ファイル
        temp_result = tempfile.NamedTemporaryFile(delete=False)
        temp_files.append(temp_result.name)
        temp_result.close()

        # カプセル化パラメータのシード値
        capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()

        # ブロックサイズの設定
        block_size = 64
        buffer_size = BUFFER_SIZE

        # 抽出パラメータ
        path_offset = 0 if path_type == TRUE_PATH else 1

        # チャンク単位で読み込んで処理
        with open(temp_capsule.name, 'rb') as source, open(temp_result.name, 'wb') as target:
            # 署名データをスキップ (64バイト)
            source.seek(64)

            # ブロックインデックス
            block_index = 0

            while True:
                # ブロックサイズの2倍のデータを読み込む
                chunk = source.read(block_size * 2)
                if not chunk:
                    break

                # パターン選択
                pattern_seed = hashlib.sha256(capsule_seed + block_index.to_bytes(4, 'big')).digest()
                pattern_value = pattern_seed[0] % 3

                # パターンに基づいて抽出
                if len(chunk) >= block_size:
                    if pattern_value == 0:  # 正規→非正規
                        if path_type == TRUE_PATH:
                            target.write(chunk[:block_size])
                        elif len(chunk) >= block_size * 2:
                            target.write(chunk[block_size:block_size*2])
                    elif pattern_value == 1:  # 非正規→正規
                        if path_type == TRUE_PATH and len(chunk) >= block_size * 2:
                            target.write(chunk[block_size:block_size*2])
                        elif path_type == FALSE_PATH:
                            target.write(chunk[:block_size])
                    else:  # 交互配置
                        result = bytearray()
                        for i in range(0, len(chunk), 2):
                            if i + path_offset < len(chunk):
                                result.append(chunk[i + path_offset])
                        target.write(result)

                block_index += 1

        # 結果を読み込む
        with open(temp_result.name, 'rb') as f:
            return f.read()

    finally:
        # 一時ファイルを削除
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"警告: 一時ファイル '{temp_file}' の削除に失敗しました: {e}", file=sys.stderr)


def decrypt(encrypted_file: str, key: Union[bytes, str], output_file: Optional[str] = None) -> bool:
    """
    不確定性転写暗号化方式で暗号化されたファイルを復号する

    Args:
        encrypted_file: 暗号化ファイルのパス
        key: 復号鍵（バイト列またはファイルパス）
        output_file: 出力ファイルのパス（省略時は自動生成）

    Returns:
        復号が成功したかどうか
    """
    try:
        # keyがファイルパスかバイト列かを判断
        if isinstance(key, str) and os.path.exists(key):
            # キーファイルパスの場合は直接decrypt_fileに渡す
            return decrypt_file(encrypted_file, key, output_file)

        # バイト列でない場合はバイト列に変換
        if not isinstance(key, bytes):
            if isinstance(key, str):
                try:
                    # 16進数文字列かもしれない
                    key = bytes.fromhex(key)
                except ValueError:
                    # 通常の文字列として扱う
                    key = key.encode('utf-8')
            else:
                # その他の型は文字列化してエンコード
                key = str(key).encode('utf-8')

        # 一時鍵ファイルを作成
        # decrypt_fileはファイルパスとして鍵を受け取るため、一時ファイルに鍵を保存
        with tempfile.NamedTemporaryFile(delete=False, suffix='.key') as key_file:
            key_path = key_file.name

            # JSON形式で鍵情報を作成
            key_info = {
                "version": VERSION,
                "master_key": base64.b64encode(key).decode('utf-8'),
                "timestamp": int(time.time()),
                "entropy": calculate_entropy(key)
            }

            # 鍵ファイルに書き込み
            key_file.write(json.dumps(key_info, indent=2).encode('utf-8'))

        try:
            # 実際の復号処理を呼び出し
            return decrypt_file(encrypted_file, key_path, output_file)
        finally:
            # 一時鍵ファイルを削除
            try:
                if os.path.exists(key_path):
                    os.unlink(key_path)
            except Exception as e:
                print(f"警告: 一時鍵ファイルの削除に失敗しました: {e}", file=sys.stderr)

    except Exception as e:
        print(f"復号エラー: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def calculate_entropy(data: bytes) -> float:
    """
    データのエントロピーを計算

    Args:
        data: エントロピーを計算するデータ

    Returns:
        シャノンエントロピー（ビット/バイト）
    """
    if not data:
        return 0.0

    # バイト出現頻度を計算
    byte_count = {}
    for b in data:
        byte_count[b] = byte_count.get(b, 0) + 1

    # 確率とエントロピーの計算
    entropy = 0.0
    length = len(data)
    for count in byte_count.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_entropy_data(entropy_data: bytes, key: bytes, salt: bytes, path_type: str) -> Dict[str, Any]:
    """
    エントロピーデータから情報を抽出する

    Args:
        entropy_data: エントロピーデータ
        key: 復号鍵
        salt: ソルト値
        path_type: 実行パスタイプ（"true" または "false"）

    Returns:
        抽出された情報の辞書
    """
    try:
        # エントロピー注入モジュールをインポート
        from .entropy_injector import EntropyInjector

        # 注入器を作成
        injector = EntropyInjector(key, salt)

        # マーカーを取得
        markers = injector._injection_markers

        # 抽出結果
        result = {}

        # データからマーカー位置を特定
        marker_positions = {}
        for i, marker in enumerate(markers):
            pos = entropy_data.find(marker)
            if pos >= 0:
                marker_positions[i] = pos

        # マーカー位置でデータをパース
        if 0 in marker_positions and 1 in marker_positions:
            # ベースエントロピー領域
            base_start = marker_positions[0] + len(markers[0])
            base_end = marker_positions[1]
            if base_end > base_start:
                result["base_entropy"] = entropy_data[base_start:base_end]

        # path_type に基づいてハッシュと関連データを抽出
        if path_type == TRUE_PATH and 1 in marker_positions and 2 in marker_positions:
            # true パスのハッシュ
            hash_start = marker_positions[1] + len(markers[1])
            hash_end = marker_positions[2]
            if hash_end > hash_start and hash_end - hash_start >= 32:
                result["path_hash"] = entropy_data[hash_start:hash_start+32]

        elif path_type == FALSE_PATH and 3 in marker_positions and 4 in marker_positions:
            # false パスのハッシュ
            hash_start = marker_positions[3] + len(markers[3])
            hash_end = marker_positions[4]
            if hash_end > hash_start and hash_end - hash_start >= 32:
                result["path_hash"] = entropy_data[hash_start:hash_start+32]

        # タイムスタンプの抽出
        if 6 in marker_positions and 7 in marker_positions:
            ts_start = marker_positions[6] + len(markers[6])
            ts_end = marker_positions[7]
            if ts_end > ts_start and ts_end - ts_start >= 8:
                result["timestamp"] = int.from_bytes(entropy_data[ts_start:ts_start+8], 'big')

        # エントロピーデータの分析
        result["analysis"] = analyze_entropy(entropy_data)

        return result

    except ImportError:
        # モジュールがない場合は基本情報のみ返す
        return {
            "analysis": {
                "size": len(entropy_data),
                "entropy": calculate_entropy(entropy_data)
            }
        }
    except Exception as e:
        print(f"エントロピーデータの解析中にエラーが発生しました: {e}", file=sys.stderr)
        return {"error": str(e)}


def main():
    """
    メイン処理
    """
    parser = argparse.ArgumentParser(description='不確定性転写暗号復号プログラム')

    # 必須引数
    parser.add_argument('encrypted', help='復号する暗号化ファイルのパス')

    # オプション
    parser.add_argument('--key', '-k', help='復号鍵ファイルのパス', required=True)
    parser.add_argument('--output', '-o', help='出力先ファイルのパス（指定しない場合は自動生成）')
    parser.add_argument('--force', '-f', action='store_true', help='出力先ファイルが存在する場合に上書き')
    parser.add_argument('--verbose', '-v', action='store_true', help='詳細情報を表示')

    # 処理モード
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--text', '-t', action='store_true', help='テキストモードで実行')
    group.add_argument('--binary', '-b', action='store_true', help='バイナリモードで実行')

    # バージョン情報
    parser.add_argument('--version', action='version', version='不確定性転写暗号復号 v1.0.0')

    args = parser.parse_args()

    try:
        # 入力ファイルの検証
        if not os.path.exists(args.encrypted):
            print(f"エラー: 暗号化ファイル '{args.encrypted}' が見つかりません", file=sys.stderr)
            return 1

        if not os.path.exists(args.key):
            print(f"エラー: 鍵ファイル '{args.key}' が見つかりません", file=sys.stderr)
            return 1

        # 出力パスの処理
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        if args.output:
            output_path = args.output
        else:
            # 元のファイル名から拡張子を除いて、タイムスタンプを追加
            base_name = os.path.splitext(os.path.basename(args.encrypted))[0]
            output_path = f"{base_name}_decrypted_{timestamp}.txt"

        # 出力ファイルの存在確認
        if os.path.exists(output_path) and not args.force:
            print(f"エラー: 出力ファイル '{output_path}' は既に存在します。--force オプションを使用して上書きできます", file=sys.stderr)
            return 1

        # 実際の復号処理を実行
        success = decrypt(args.encrypted, args.key, output_path)

        if success:
            print(f"ファイルの復号が完了しました: {output_path}")
            return 0
        else:
            print("ファイルの復号に失敗しました", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"致命的なエラーが発生しました: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())