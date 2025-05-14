#!/usr/bin/env python3
"""
不確定性転写暗号化方式の暗号化スクリプト

鍵に基づいた確率的実行パスに従って暗号化を行います。
TRUE/FALSE 2種類の鍵を使用し、どちらが「正規」かは使用者の意図によって決まります。
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


class IndeterministicEncryptor:
    """
    不確定性転写暗号化を行うクラス

    鍵に基づいた確率的実行パスに従って暗号化を行います。
    """

    def __init__(
        self,
        true_key: bytes,
        false_key: bytes,
        operation_key: str = TRUE_PATH,
        salt: Optional[bytes] = None,
        transitions: int = DEFAULT_TRANSITIONS
    ):
        """
        暗号化機能の初期化

        Args:
            true_key: TRUE パス用の鍵
            false_key: FALSE パス用の鍵
            operation_key: 使用する鍵のタイプ（"true" または "false"）
            salt: ソルト値（省略時はランダム生成）
            transitions: 状態遷移回数
        """
        if not isinstance(true_key, bytes) or len(true_key) == 0:
            raise ValueError("TRUE鍵はバイト列で、空であってはなりません")

        if not isinstance(false_key, bytes) or len(false_key) == 0:
            raise ValueError("FALSE鍵はバイト列で、空であってはなりません")

        if operation_key not in [TRUE_PATH, FALSE_PATH]:
            raise ValueError(f"操作鍵は '{TRUE_PATH}' または '{FALSE_PATH}' である必要があります")

        self.true_key = true_key
        self.false_key = false_key
        self.operation_key = operation_key
        self.salt = salt or os.urandom(16)
        self.transitions = transitions

        # 鍵の使用に応じたエンジンを初期化
        key_to_use = true_key if operation_key == TRUE_PATH else false_key
        self.engine = create_engine_from_key(key_to_use, operation_key, self.salt)

        # 内部状態
        self._initialized = True
        self._execution_count = 0
        self._cipher_params = self._initialize_cipher_params()

    def _initialize_cipher_params(self) -> Dict[str, Any]:
        """
        暗号化パラメータの初期化

        Returns:
            初期化されたパラメータ辞書
        """
        # エンジンを実行して初期状態を設定
        self.engine.run_execution(self.transitions)

        # エンジンの実行署名を取得
        signature = self.engine.get_execution_signature()

        # 鍵導出関数を使用して暗号パラメータを生成
        key_params = self._derive_cipher_parameters(signature)

        return key_params

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
        hmac_key = self.true_key if self.operation_key == TRUE_PATH else self.false_key

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

    def encrypt(self, data: bytes) -> bytes:
        """
        データの暗号化

        Args:
            data: 暗号化するデータ

        Returns:
            暗号化されたデータ
        """
        if not self._initialized:
            raise RuntimeError("暗号化機能が初期化されていません")

        if not isinstance(data, bytes):
            raise TypeError("暗号化するデータはバイト列である必要があります")

        # エンジンの実行カウンタを更新
        self._execution_count += 1

        try:
            # AES-GCM暗号化用にモジュールをインポート
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # 暗号化エンジンの作成
            cipher = AESGCM(self._cipher_params["cipher_key"])

            # タイムスタンプ（追加の認証データとして使用）
            timestamp = int(time.time()).to_bytes(8, byteorder="big")

            # ノンスを取得
            nonce = self._cipher_params["nonce"]

            # 追加の認証データの構築（暗号文の一部ではない情報）
            aad = timestamp + self.salt

            # 暗号化を実行
            encrypted_data = cipher.encrypt(nonce, data, aad)

            # 実行パスを難読化（解析対策）
            obfuscate_execution_path(self.engine)

            # メタデータの作成
            metadata = {
                "version": FILE_FORMAT_VERSION,
                "timestamp": int.from_bytes(timestamp, byteorder="big"),
                "salt": self.salt.hex(),
                "mode": self.operation_key,
                "transitions": self.transitions,
                "signature": self.engine.get_execution_signature().hex()
            }

            # メタデータをJSON形式にエンコード
            metadata_json = json.dumps(metadata).encode("utf-8")
            metadata_len = len(metadata_json).to_bytes(4, byteorder="big")

            # ヘッダーにメタデータを追加
            header = CIPHER_HEADER + metadata_len + metadata_json

            # ヘッダーと暗号化データの結合
            return header + encrypted_data

        except ImportError:
            # cryptographyモジュールがない場合は例外を発生
            raise RuntimeError("暗号化に必要なcryptographyモジュールがインストールされていません")
        except Exception as e:
            # 暗号化中の例外を処理
            raise RuntimeError(f"暗号化中にエラーが発生しました: {e}")

    def encrypt_file(self, input_file: str, output_file: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bool:
        """
        ファイルの暗号化

        Args:
            input_file: 入力ファイルのパス
            output_file: 出力ファイルのパス
            chunk_size: チャンク処理サイズ（バイト）

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
                data = f_in.read()

            # データの暗号化
            encrypted_data = self.encrypt(data)

            # 出力ファイルに書き込み
            with open(output_file, "wb") as f_out:
                f_out.write(encrypted_data)

            # タイムスタンプを付与（証拠保全）
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            base, ext = os.path.splitext(output_file)
            output_file_with_timestamp = f"{base}_{timestamp}{ext}"

            # タイムスタンプ付きのファイル名にリネーム
            os.rename(output_file, output_file_with_timestamp)

            print(f"ファイルを暗号化しました: {input_file} -> {output_file_with_timestamp}")
            return True

        except Exception as e:
            print(f"暗号化中にエラーが発生しました: {e}", file=sys.stderr)
            return False

    def get_stats(self) -> Dict[str, Any]:
        """
        暗号化エンジンの統計情報を取得

        Returns:
            統計情報の辞書
        """
        stats = {
            "version": VERSION,
            "operation_mode": self.operation_key,
            "salt": self.salt.hex(),
            "transitions": self.transitions,
            "execution_count": self._execution_count,
        }

        # エンジンの状態を追加
        if hasattr(self.engine, 'get_engine_state'):
            engine_state = self.engine.get_engine_state()
            stats.update({"engine_" + k: v for k, v in engine_state.items()})

        return stats


def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> bytes:
    """
    パスワードから鍵を導出

    Args:
        password: 鍵生成に使用するパスワード
        salt: ソルト値（省略時はランダム生成）

    Returns:
        導出された鍵
    """
    if not password:
        raise ValueError("パスワードが空です")

    salt = salt or os.urandom(16)

    # PBKDF2を使用して鍵を導出
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=100000,
        dklen=32
    )


def encrypt_file_cli(
    input_file: str,
    output_file: str,
    true_password: str,
    false_password: str,
    mode: str = TRUE_PATH
) -> bool:
    """
    CLI用のファイル暗号化関数

    Args:
        input_file: 入力ファイルのパス
        output_file: 出力ファイルのパス
        true_password: TRUE鍵用のパスワード
        false_password: FALSE鍵用のパスワード
        mode: 操作モード（"true" または "false"）

    Returns:
        成功した場合はTrue、失敗した場合はFalse
    """
    try:
        # パスワードから鍵を導出
        salt = os.urandom(16)
        true_key = derive_key_from_password(true_password, salt)
        false_key = derive_key_from_password(false_password, salt)

        # 暗号化器の初期化
        encryptor = IndeterministicEncryptor(true_key, false_key, mode, salt)

        # ファイルの暗号化
        result = encryptor.encrypt_file(input_file, output_file)

        return result

    except Exception as e:
        print(f"暗号化処理中にエラーが発生しました: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="不確定性転写暗号化")
    parser.add_argument("input_file", help="暗号化する入力ファイル")
    parser.add_argument("output_file", help="暗号化されたデータを出力するファイル")
    parser.add_argument("--true-password", help="TRUE鍵のパスワード")
    parser.add_argument("--false-password", help="FALSE鍵のパスワード")
    parser.add_argument("--mode", choices=[TRUE_PATH, FALSE_PATH], default=TRUE_PATH, help="操作モード")

    args = parser.parse_args()

    # パスワードが指定されていない場合は対話式で入力
    if not args.true_password:
        import getpass
        args.true_password = getpass.getpass("TRUE鍵のパスワード: ")

    if not args.false_password:
        import getpass
        args.false_password = getpass.getpass("FALSE鍵のパスワード: ")

    # ファイルの暗号化
    success = encrypt_file_cli(
        args.input_file,
        args.output_file,
        args.true_password,
        args.false_password,
        args.mode
    )

    sys.exit(0 if success else 1)
