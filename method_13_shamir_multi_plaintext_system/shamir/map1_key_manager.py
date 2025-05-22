"""
第1段階MAPパーティションマップキー管理モジュール

【責務】
このモジュールは、シャミア秘密分散法による複数平文復号システムにおける
第1段階MAPのパーティションマップキーの生成と復号を担当します。

主要機能:
1. 第1段階MAPからパーティションマップキーの生成
2. パーティションマップキーから第1段階MAPの復元

【依存関係】
- shamir.constants: システムパラメータ（ARGON2関連定数など）
"""

import base64
import secrets
from typing import List
from gmpy2 import mpz

# 暗号化関連のライブラリ
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# argon2-cffiパッケージを使用
import argon2

from .constants import ShamirConstants


class DecryptionError(Exception):
    """パーティションマップキーの復号失敗エラー"""
    pass


def generate_partition_map_key(partition_distribution: List[int], password: str) -> str:
    """
    第1段階MAPからパーティションマップキーを生成する関数

    Args:
        partition_distribution: 領域の配列インデックス分布（第1段階MAP）
        password: 暗号化に使用するパスワード（全文そのままのパスワード）

    Returns:
        formatted_key: 生成されたパーティションマップキー
    """
    # 1. 第1段階MAPを最大限圧縮してバイナリ形式に変換
    binary_data = serialize_to_binary(partition_distribution)

    # 2. 全文そのままのパスワード（生のパスワード）から暗号化キーを導出
    encryption_key = derive_key_from_password(password)

    # 3. 暗号化（AES-GCM等の認証付き暗号化）を適用
    #    注: 認証タグも含めることで改ざん検知が可能になるが、
    #        パスワードが間違っているのか改ざんされているのかは区別できない
    encrypted_data = encrypt_with_authentication(binary_data, encryption_key)

    # 4. Base64エンコード（パディングを含む）
    encoded_key = base64.b64encode(encrypted_data).decode('ascii')

    # 5. 読みやすさのために区切り文字を挿入
    chunks = [encoded_key[i:i+5] for i in range(0, len(encoded_key), 5)]
    formatted_key = '-'.join(chunks)

    return formatted_key


def restore_partition_distribution(partition_map_key: str, password: str) -> List[int]:
    """
    パーティションマップキーから元の第1段階MAPを復元する関数

    Args:
        partition_map_key: パーティションマップキー
        password: 暗号化に使用したのと同じパスワード

    Returns:
        partition_distribution: 復元された第1段階MAP

    Raises:
        DecryptionError: パスワードが正しくない場合、または改ざんが検出された場合（両者は区別できない）
    """
    try:
        # 1. 区切り文字を除去
        clean_key = partition_map_key.replace('-', '')

        # 2. Base64デコード
        encrypted_data = base64.b64decode(clean_key)

        # 3. 全文そのままのパスワード（生のパスワード）から暗号化キーを導出（生成時と同じ方法）
        decryption_key = derive_key_from_password(password)

        # 4. 復号と認証チェック（認証失敗時は例外発生）
        binary_data = decrypt_with_authentication(encrypted_data, decryption_key)

        # 5. バイナリデータから第1段階MAPを直接復元
        partition_distribution = decompress_distribution(binary_data)

        return partition_distribution

    except Exception as e:
        # 認証失敗（パスワードが異なるか、データが改ざんされている）
        # 注: 暗号学的にはパスワードが間違っているのかデータが改ざんされているのかを区別することはできない
        raise DecryptionError(f"パーティションマップキーの復号に失敗しました。パスワードが正しくないか、データが破損しています。詳細: {e}")


def compress_distribution(distribution: List[int]) -> bytes:
    """
    第1段階MAPを最大限圧縮してバイナリに変換する

    Args:
        distribution: 第1段階MAP（整数リスト）

    Returns:
        compressed: 圧縮されたバイナリデータ
    """
    if not distribution:
        return b''

    # ステップ1: ソート（効率的な圧縮のため）
    sorted_dist = sorted(distribution)

    # ステップ2: 最大値を確認し、必要なビット数を計算
    max_value = sorted_dist[-1]
    share_id_space_size = max_value + 1

    # ステップ3: ビットマップ方式で圧縮（存在するIDのみを1とする）
    # バイト配列を作成（8ビットごとに1バイト）
    bytes_needed = (share_id_space_size + 7) // 8
    bitmap = bytearray(bytes_needed)

    # 各IDに対応するビットを1に設定
    for idx in sorted_dist:
        byte_pos = idx // 8
        bit_pos = idx % 8
        bitmap[byte_pos] |= (1 << bit_pos)

    # ステップ4: さらに圧縮（ランレングス符号化）
    # 長い0や1の連続を圧縮
    compressed = bytearray()
    current_byte = 0
    run_length = 0
    run_value = 0

    for byte in bitmap:
        if byte == current_byte:
            run_length += 1
            if run_length == 255:  # 最大ラン長
                compressed.append(run_value)
                compressed.append(run_length)
                run_length = 0
        else:
            if run_length > 0:
                compressed.append(run_value)
                compressed.append(run_length)
            current_byte = byte
            run_length = 1
            run_value = 0 if byte == 0 else 1

    # 最後のランを追加
    if run_length > 0:
        compressed.append(run_value)
        compressed.append(run_length)

    # ステップ5: 元のビットマップと圧縮後のサイズを比較し、小さい方を使用
    if len(compressed) < len(bitmap):
        # 圧縮形式を示すヘッダ(1バイト) + 圧縮データ
        return b'\x01' + bytes(compressed)
    else:
        # 非圧縮形式を示すヘッダ(1バイト) + 元のビットマップ
        return b'\x00' + bytes(bitmap)


def decompress_distribution(compressed_data: bytes) -> List[int]:
    """
    圧縮された第1段階MAPを復元する

    Args:
        compressed_data: 圧縮されたバイナリデータ

    Returns:
        distribution: 復元された第1段階MAP
    """
    if not compressed_data:
        return []

    # ヘッダーから圧縮形式を判断
    compression_type = compressed_data[0]
    data = compressed_data[1:]

    # ビットマップデータを復元
    if compression_type == 0:  # 非圧縮ビットマップ
        bitmap = data
    else:  # ランレングス圧縮
        bitmap = bytearray()
        i = 0
        while i < len(data):
            value = data[i]
            length = data[i+1]
            bitmap.extend([0xFF if value else 0x00] * length)
            i += 2

    # ビットマップからインデックスリストを復元
    distribution = []
    for byte_pos, byte in enumerate(bitmap):
        for bit_pos in range(8):
            if byte & (1 << bit_pos):
                idx = byte_pos * 8 + bit_pos
                distribution.append(idx)

    return distribution


def serialize_to_binary(distribution: List[int]) -> bytes:
    """
    第1段階MAPを圧縮してバイナリ形式に変換

    Args:
        distribution: 第1段階MAP（整数リスト）

    Returns:
        serialized: 圧縮されたバイナリデータ
    """
    # 直接圧縮関数を呼び出し
    return compress_distribution(distribution)


def derive_key_from_password(password: str) -> bytes:
    """
    パスワードから暗号化キーを導出

    Args:
        password: 生のパスワード

    Returns:
        key: 導出された暗号化キー
    """
    # パスワードをUTF-8エンコード
    password_bytes = password.encode('utf-8')

    # ソルト値（固定）
    # 注: 通常は個別のソルトを使用しますが、パーティションマップキーでは
    # 決定論的な結果が必要なため固定ソルトを使用
    salt = b'fixed_salt_for_partition_map_key'

    # Argon2idを使用（より安全）
    try:
        # argon2-cffiパッケージを使用
        key = argon2.low_level.hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=ShamirConstants.ARGON2_TIME_COST,
            memory_cost=ShamirConstants.ARGON2_MEMORY_COST,
            parallelism=ShamirConstants.ARGON2_PARALLELISM,
            hash_len=ShamirConstants.ARGON2_OUTPUT_LENGTH,
            type=argon2.low_level.Type.ID
        )
        return key
    except Exception:
        # フォールバックとしてPBKDF2を使用
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ShamirConstants.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password_bytes)


def encrypt_with_authentication(data: bytes, key: bytes) -> bytes:
    """
    認証付き暗号化を使用してデータを暗号化

    Args:
        data: 暗号化するデータ
        key: 暗号化キー

    Returns:
        encrypted: 暗号化されたデータ（ノンス + 暗号文 + 認証タグ）
    """
    # ノンスを生成
    nonce = secrets.token_bytes(12)  # AES-GCMの推奨ノンスサイズ

    # AES-GCMで暗号化
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # ノンスと暗号文を結合
    return nonce + ciphertext


def decrypt_with_authentication(encrypted_data: bytes, key: bytes) -> bytes:
    """
    認証付き暗号化されたデータを復号

    Args:
        encrypted_data: 暗号化されたデータ（ノンス + 暗号文 + 認証タグ）
        key: 復号キー

    Returns:
        decrypted: 復号されたデータ

    Raises:
        DecryptionError: 復号に失敗した場合（パスワードが不正、または改ざんされた場合）
    """
    # ノンスと暗号文を分離
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    # AES-GCMで復号
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        # 認証失敗（パスワードが異なるか、データが改ざんされている）
        # 注: 暗号学的にはパスワードが間違っているのかデータが改ざんされているのかを区別することはできない
        raise DecryptionError("パーティションマップキーの復号に失敗しました。パスワードが正しくないか、データが破損しています。")