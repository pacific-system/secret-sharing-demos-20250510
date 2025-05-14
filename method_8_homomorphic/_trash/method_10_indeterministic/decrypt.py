#!/usr/bin/env python3
"""
不確定性転写暗号化方式の復号スクリプト

鍵に基づいた確率的実行パスに従って復号を行います。
TRUE/FALSE 2種類の鍵を使用し、どちらの鍵を使っても復号は可能ですが、
結果として得られる情報は鍵に応じて確率的に異なります。
"""

import os
import sys
import time
import json
import hashlib
import argparse
import secrets
from typing import Dict, List, Tuple, Optional, Union, Any

# パッケージとして利用する場合と直接実行する場合でインポートを切り替え
if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.append(current_dir)
    from state_matrix import create_state_matrix_from_key, State
    from probability_engine import (
        ProbabilisticExecutionEngine, create_engine_from_key,
        TRUE_PATH, FALSE_PATH, obfuscate_execution_path, generate_anti_analysis_noise
    )
else:
    from .state_matrix import create_state_matrix_from_key, State
    from .probability_engine import (
        ProbabilisticExecutionEngine, create_engine_from_key,
        TRUE_PATH, FALSE_PATH, obfuscate_execution_path, generate_anti_analysis_noise
    )

# 定数定義
VERSION = "1.0.0"
CIPHER_HEADER = b"INDTCRYP"
FILE_FORMAT_VERSION = 1
MAX_HEADER_SIZE = 1024  # ヘッダサイズの最大値（バイト）
DEFAULT_CHUNK_SIZE = 64 * 1024  # チャンク処理サイズ（64KB）
DEFAULT_TRANSITIONS = 20  # デフォルトの状態遷移回数


class IndeterministicDecryptor:
    """
    不確定性転写暗号化の復号を行うクラス

    鍵に基づいた確率的実行パスに従って復号を行います。
    """

    def __init__(
        self,
        key: bytes,
        mode: str,
    ):
        """
        復号機能の初期化

        Args:
            key: 使用する鍵
            mode: 使用する鍵のタイプ（"true" または "false"）
        """
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("鍵はバイト列で、空であってはなりません")

        if mode not in [TRUE_PATH, FALSE_PATH]:
            raise ValueError(f"モードは '{TRUE_PATH}' または '{FALSE_PATH}' である必要があります")

        self.key = key
        self.mode = mode

        # 内部状態
        self._initialized = False
        self._execution_count = 0
        self._cipher_params = None
        self._metadata = None
        self.engine = None

    def _initialize_from_encrypted_data(self, encrypted_data: bytes) -> bool:
        """
        暗号化データから復号パラメータを初期化

        Args:
            encrypted_data: 暗号化されたデータ

        Returns:
            初期化に成功した場合はTrue、失敗した場合はFalse
        """
        try:
            # ヘッダーの検証
            if not encrypted_data.startswith(CIPHER_HEADER):
                raise ValueError("無効なファイル形式です。暗号化ヘッダーが見つかりません。")

            # メタデータ長の取得
            metadata_len_bytes = encrypted_data[len(CIPHER_HEADER):len(CIPHER_HEADER) + 4]
            metadata_len = int.from_bytes(metadata_len_bytes, byteorder="big")

            # メタデータ長の検証
            if metadata_len <= 0 or metadata_len > MAX_HEADER_SIZE:
                raise ValueError(f"無効なメタデータサイズです: {metadata_len}")

            # メタデータの取得
            metadata_start = len(CIPHER_HEADER) + 4
            metadata_end = metadata_start + metadata_len
            metadata_json = encrypted_data[metadata_start:metadata_end]

            # メタデータのデコード
            try:
                metadata = json.loads(metadata_json.decode("utf-8"))
            except json.JSONDecodeError:
                raise ValueError("メタデータの解析に失敗しました")

            # バージョンの検証
            if metadata.get("version") != FILE_FORMAT_VERSION:
                raise ValueError(f"サポートされていないファイルバージョンです: {metadata.get('version')}")

            # メタデータの保存
            self._metadata = metadata

            # ソルトの取得
            salt_hex = metadata.get("salt")
            if not salt_hex:
                raise ValueError("メタデータにソルトが含まれていません")

            salt = bytes.fromhex(salt_hex)

            # 遷移回数の取得
            transitions = metadata.get("transitions", DEFAULT_TRANSITIONS)

            # 実行エンジンの初期化
            self.engine = create_engine_from_key(self.key, self.mode, salt)

            # エンジンの実行
            self.engine.run_execution(transitions)

            # 実行署名の取得
            signature = self.engine.get_execution_signature()

            # 暗号パラメータの導出
            self._cipher_params = self._derive_cipher_parameters(signature)

            # 初期化完了
            self._initialized = True
            return True

        except Exception as e:
            print(f"初期化中にエラーが発生しました: {e}", file=sys.stderr)
            return False

    def _derive_cipher_parameters(self, seed: bytes) -> Dict[str, Any]:
        """
        暗号パラメータの導出

        Args:
            seed: パラメータ導出のシード

        Returns:
            暗号パラメータの辞書
        """
        if not isinstance(seed, bytes) or len(seed) < 16:
            raise ValueError("シードは少なくとも16バイトのバイト列である必要があります")

        params = {}

        # HMAC-SHA256を使用してパラメータを派生
        hmac_key = self.key

        # 暗号化鍵の派生（32バイト）
        params["cipher_key"] = hashlib.pbkdf2_hmac(
            "sha256",
            hmac_key,
            seed + b"cipher_key",
            iterations=10000,
            dklen=32
        )

        # 初期化ベクトルの派生（16バイト）
        params["iv"] = hashlib.pbkdf2_hmac(
            "sha256",
            hmac_key,
            seed + b"iv",
            iterations=10000,
            dklen=16
        )

        # データ認証コード用の鍵の派生（32バイト）
        params["mac_key"] = hashlib.pbkdf2_hmac(
            "sha256",
            hmac_key,
            seed + b"mac_key",
            iterations=10000,
            dklen=32
        )

        # ノンスの派生（12バイト）
        params["nonce"] = hashlib.pbkdf2_hmac(
            "sha256",
            hmac_key,
            seed + b"nonce",
            iterations=10000,
            dklen=12
        )

        return params

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        暗号化データの復号

        Args:
            encrypted_data: 復号するデータ

        Returns:
            復号されたデータ
        """
        if not isinstance(encrypted_data, bytes):
            raise TypeError("暗号化データはバイト列である必要があります")

        # メタデータから初期化
        if not self._initialized and not self._initialize_from_encrypted_data(encrypted_data):
            raise RuntimeError("暗号化データからの初期化に失敗しました")

        # エンジンの実行カウンタを更新
        self._execution_count += 1

        try:
            # AES-GCM復号用にモジュールをインポート
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # メタデータの取得
            metadata = self._metadata

            # タイムスタンプの取得
            timestamp = metadata.get("timestamp")
            timestamp_bytes = timestamp.to_bytes(8, byteorder="big") if isinstance(timestamp, int) else b"\x00" * 8

            # ソルトの取得
            salt_hex = metadata.get("salt")
            salt = bytes.fromhex(salt_hex) if salt_hex else b""

            # 暗号化データの取得（ヘッダーとメタデータを除く）
            metadata_json = json.dumps(metadata).encode("utf-8")
            data_start = len(CIPHER_HEADER) + 4 + len(metadata_json)
            cipher_data = encrypted_data[data_start:]

            # 復号エンジンの作成
            cipher = AESGCM(self._cipher_params["cipher_key"])

            # ノンスを取得
            nonce = self._cipher_params["nonce"]

            # 追加の認証データの構築
            aad = timestamp_bytes + salt

            # 復号を実行
            try:
                decrypted_data = cipher.decrypt(nonce, cipher_data, aad)
            except Exception as e:
                if "MAC check failed" in str(e):
                    # MACの検証失敗（鍵が違う、またはデータが改ざんされている）
                    raise ValueError("認証に失敗しました。鍵が間違っているか、データが改ざんされています。")
                else:
                    # その他の復号エラー
                    raise ValueError(f"復号中にエラーが発生しました: {e}")

            # 実行パスを難読化（解析対策）
            obfuscate_execution_path(self.engine)

            return decrypted_data

        except ImportError:
            # cryptographyモジュールがない場合は例外を発生
            raise RuntimeError("復号に必要なcryptographyモジュールがインストールされていません")
        except Exception as e:
            # 復号中の例外を処理
            raise RuntimeError(f"復号中にエラーが発生しました: {e}")

    def decrypt_file(self, input_file: str, output_file: str) -> bool:
        """
        ファイルの復号

        Args:
            input_file: 入力ファイルのパス
            output_file: 出力ファイルのパス

        Returns:
            成功した場合はTrue、失敗した場合はFalse
        """
        try:
            # 入力ファイルと出力ファイルが同じ場合はエラー
            if os.path.abspath(input_file) == os.path.abspath(output_file):
                raise ValueError("入力ファイルと出力ファイルは同じであってはなりません")

            # 入力ファイルの存在確認
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"入力ファイル '{input_file}' が見つかりません")

            # 入力ファイルの読み取り
            with open(input_file, "rb") as f_in:
                encrypted_data = f_in.read()

            # データの復号
            try:
                decrypted_data = self.decrypt(encrypted_data)
            except Exception as e:
                print(f"復号処理中にエラーが発生しました: {e}", file=sys.stderr)
                return False

            # 出力ファイルに書き込み
            with open(output_file, "wb") as f_out:
                f_out.write(decrypted_data)

            # タイムスタンプを付与（証拠保全）
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            base, ext = os.path.splitext(output_file)
            output_file_with_timestamp = f"{base}_{timestamp}{ext}"

            # タイムスタンプ付きのファイル名にリネーム
            os.rename(output_file, output_file_with_timestamp)

            print(f"ファイルを復号しました: {input_file} -> {output_file_with_timestamp}")
            return True

        except Exception as e:
            print(f"復号処理中にエラーが発生しました: {e}", file=sys.stderr)
            return False

    def get_stats(self) -> Dict[str, Any]:
        """
        復号エンジンの統計情報を取得

        Returns:
            統計情報の辞書
        """
        stats = {
            "version": VERSION,
            "operation_mode": self.mode,
            "execution_count": self._execution_count,
            "initialized": self._initialized
        }

        # メタデータを追加
        if self._metadata:
            stats.update({"metadata_" + k: v for k, v in self._metadata.items()})

        # エンジンの状態を追加
        if self.engine and hasattr(self.engine, 'get_engine_state'):
            engine_state = self.engine.get_engine_state()
            stats.update({"engine_" + k: v for k, v in engine_state.items()})

        return stats


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    パスワードから鍵を導出

    Args:
        password: 鍵生成に使用するパスワード
        salt: ソルト値

    Returns:
        導出された鍵
    """
    if not password:
        raise ValueError("パスワードが空です")

    if not salt or not isinstance(salt, bytes):
        raise ValueError("ソルトは空でないバイト列である必要があります")

    # PBKDF2を使用して鍵を導出
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=100000,
        dklen=32
    )


def extract_salt_from_encrypted_file(input_file: str) -> Optional[bytes]:
    """
    暗号化ファイルからソルトを抽出

    Args:
        input_file: 暗号化ファイルのパス

    Returns:
        抽出されたソルト値（失敗した場合はNone）
    """
    try:
        # ファイルの先頭部分だけを読み取る
        with open(input_file, "rb") as f:
            header_data = f.read(MAX_HEADER_SIZE)

        # ヘッダーの検証
        if not header_data.startswith(CIPHER_HEADER):
            print("無効なファイル形式です。暗号化ヘッダーが見つかりません。", file=sys.stderr)
            return None

        # メタデータ長の取得
        metadata_len_bytes = header_data[len(CIPHER_HEADER):len(CIPHER_HEADER) + 4]
        metadata_len = int.from_bytes(metadata_len_bytes, byteorder="big")

        # メタデータ長の検証
        if metadata_len <= 0 or metadata_len > MAX_HEADER_SIZE:
            print(f"無効なメタデータサイズです: {metadata_len}", file=sys.stderr)
            return None

        # メタデータの取得
        metadata_start = len(CIPHER_HEADER) + 4
        metadata_end = metadata_start + metadata_len

        if metadata_end > len(header_data):
            print("ヘッダーデータが不完全です", file=sys.stderr)
            return None

        metadata_json = header_data[metadata_start:metadata_end]

        # メタデータのデコード
        try:
            metadata = json.loads(metadata_json.decode("utf-8"))
        except json.JSONDecodeError:
            print("メタデータの解析に失敗しました", file=sys.stderr)
            return None

        # ソルトの取得
        salt_hex = metadata.get("salt")
        if not salt_hex:
            print("メタデータにソルトが含まれていません", file=sys.stderr)
            return None

        return bytes.fromhex(salt_hex)

    except Exception as e:
        print(f"ソルトの抽出中にエラーが発生しました: {e}", file=sys.stderr)
        return None


def decrypt_file_cli(
    input_file: str,
    output_file: str,
    password: str,
    mode: str = TRUE_PATH
) -> bool:
    """
    CLI用のファイル復号関数

    Args:
        input_file: 入力ファイルのパス
        output_file: 出力ファイルのパス
        password: 復号用のパスワード
        mode: 操作モード（"true" または "false"）

    Returns:
        成功した場合はTrue、失敗した場合はFalse
    """
    try:
        # 暗号化ファイルからソルトを抽出
        salt = extract_salt_from_encrypted_file(input_file)
        if not salt:
            return False

        # パスワードから鍵を導出
        key = derive_key_from_password(password, salt)

        # 復号器の初期化
        decryptor = IndeterministicDecryptor(key, mode)

        # ファイルの復号
        result = decryptor.decrypt_file(input_file, output_file)

        return result

    except Exception as e:
        print(f"復号処理中にエラーが発生しました: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="不確定性転写暗号化の復号")
    parser.add_argument("input_file", help="復号する暗号化ファイル")
    parser.add_argument("output_file", help="復号されたデータを出力するファイル")
    parser.add_argument("--password", help="復号用のパスワード")
    parser.add_argument("--mode", choices=[TRUE_PATH, FALSE_PATH], default=TRUE_PATH, help="操作モード")

    args = parser.parse_args()

    # パスワードが指定されていない場合は対話式で入力
    if not args.password:
        import getpass
        args.password = getpass.getpass("復号パスワード: ")

    # ファイルの復号
    success = decrypt_file_cli(
        args.input_file,
        args.output_file,
        args.password,
        args.mode
    )

    sys.exit(0 if success else 1)
