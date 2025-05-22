"""
暗号書庫生成機能

このモジュールでは、シャミア秘密分散法による複数平文復号システムの
暗号書庫生成（createCryptoStorage）機能を実装します。
"""

import os
import uuid
import json
import base64
import secrets
import hashlib
import time
from typing import Dict, List, Tuple, Any, Set
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from gmpy2 import mpz

# argon2-cffiパッケージを使用
import argon2

from .constants import ShamirConstants
from .core import generate_polynomial, evaluate_polynomial, generate_shares


def create_crypto_storage(a_password: str, b_password: str, output_dir: str = './output',
                        parameters: Dict[str, Any] = None) -> Tuple[str, str, str]:
    """
    暗号書庫を生成する関数

    Args:
        a_password: A領域用のパスワード
        b_password: B領域用のパスワード
        output_dir: 出力ディレクトリパス
        parameters: 設定ファイルから読み込まれたシステムパラメータ設定（指定がない場合はデフォルト値を使用）

    Returns:
        storage_file: 生成された暗号書庫のファイルパス
        a_partition_map_key: A領域のパーティションマップキー
        b_partition_map_key: B領域のパーティションマップキー
    """
    # システムパラメータの確認と設定
    params = parameters or {
        'ACTIVE_SHARES': ShamirConstants.ACTIVE_SHARES,
        'GARBAGE_SHARES': ShamirConstants.GARBAGE_SHARES,
        'PARTITION_SIZE': ShamirConstants.PARTITION_SIZE,
        'UNASSIGNED_SHARES': ShamirConstants.UNASSIGNED_SHARES,
        'SHARE_ID_SPACE': ShamirConstants.SHARE_ID_SPACE,
    }

    # シェアID空間の設定と3区画への分割
    a_partition, b_partition, unassigned = divide_share_id_space(params)

    # 領域の重複がないことを検証
    validate_partitions(a_partition, b_partition)

    # ガベージシェアの生成と配置
    crypto_storage = generate_garbage_shares(params)

    # パーティションマップキーの生成
    a_partition_map_key = generate_partition_map_key(a_partition, a_password)
    b_partition_map_key = generate_partition_map_key(b_partition, b_password)

    # 暗号書庫ファイルの生成
    os.makedirs(output_dir, exist_ok=True)
    storage_file = os.path.join(output_dir, f"crypto_storage_{uuid.uuid4()}.json")

    # 暗号書庫を保存
    save_crypto_storage(crypto_storage, storage_file)

    return storage_file, a_partition_map_key, b_partition_map_key


def divide_share_id_space(params: Dict[str, int]) -> Tuple[List[int], List[int], List[int]]:
    """
    シェアID空間を3区画に分割する関数

    Args:
        params: 設定ファイルから読み込まれたシステムパラメータ（PARTITION_SIZE, UNASSIGNED_SHARESなど）

    Returns:
        a_partition: A用パーティション（ID配列）
        b_partition: B用パーティション（ID配列）
        unassigned: 未割当領域（ID配列）
    """
    # 全体空間サイズの計算
    share_id_space_size = params['PARTITION_SIZE'] * 2 + params['UNASSIGNED_SHARES']

    # 全IDのリスト生成（0からshare_id_space_size-1）
    all_ids = list(range(share_id_space_size))

    # セキュアなシャッフル（ランダム化）
    secure_shuffle(all_ids)

    # 3区画に分割
    a_partition = all_ids[:params['PARTITION_SIZE']]
    b_partition = all_ids[params['PARTITION_SIZE']:params['PARTITION_SIZE']*2]
    unassigned = all_ids[params['PARTITION_SIZE']*2:]

    return a_partition, b_partition, unassigned


def secure_shuffle(array: List[int]) -> None:
    """
    配列を暗号学的に安全な方法でシャッフルする関数

    Args:
        array: シャッフルする配列
    """
    for i in range(len(array) - 1, 0, -1):
        # secrets.randbelow を使用して暗号学的に安全な乱数を生成
        j = secrets.randbelow(i + 1)
        array[i], array[j] = array[j], array[i]


def validate_partitions(a_partition: List[int], b_partition: List[int]) -> None:
    """
    A領域とB領域のパーティションが重複していないことを検証

    Args:
        a_partition: A用パーティション（ID配列）
        b_partition: B用パーティション（ID配列）

    Raises:
        ValueError: パーティションに重複がある場合
    """
    # セットに変換して交差を確認
    a_set = set(a_partition)
    b_set = set(b_partition)

    # 交差部分を取得
    intersection = a_set.intersection(b_set)

    # 重複がある場合はエラー
    if intersection:
        raise ValueError(f"A領域とB領域に重複があります: {intersection}")


def generate_garbage_shares(params: Dict[str, int]) -> List[Any]:
    """
    ガベージシェアで満たされた暗号書庫を生成

    Args:
        params: システムパラメータ

    Returns:
        ガベージシェアのリスト
    """
    # 使用する素数
    prime = ShamirConstants.PRIME

    # ソルト値を生成（メタデータ用）
    salt = secrets.token_bytes(16)
    salt_b64 = base64.urlsafe_b64encode(salt).decode('ascii')

    # ガベージシェアのリスト
    garbage_shares = []

    # 全シェアID空間サイズ
    share_id_space_size = params['PARTITION_SIZE'] * 2 + params['UNASSIGNED_SHARES']

    # 各シェアIDに対してガベージシェアを生成
    for share_id in range(share_id_space_size):
        # 完全なランダム値（実際のシェアと統計的に区別不可能）
        value = mpz(secrets.randbelow(int(prime - 1))) + 1

        # シェア値を文字列として格納
        garbage_shares.append(str(value))

    # salt以外のメタデータを作成しないでください
    metadata = {
        'salt': salt_b64
    }

    # 暗号書庫データ構造
    crypto_storage = {
        'metadata': metadata,
        'shares': garbage_shares
    }

    return crypto_storage


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


def save_crypto_storage(crypto_storage: Dict[str, Any], file_path: str) -> None:
    """
    暗号書庫をファイルに保存

    Args:
        crypto_storage: 保存する暗号書庫データ
        file_path: 保存先ファイルパス
    """
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(crypto_storage, f)


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


def verify_partition_distribution(
    a_partition: List[int],
    b_partition: List[int],
    partition_size: int
) -> bool:
    """
    パーティション分布をチェックする関数

    Args:
        a_partition: A用パーティション
        b_partition: B用パーティション
        partition_size: 各パーティションの目標サイズ

    Returns:
        valid: 検証結果（True=有効、False=無効）
    """
    # サイズチェック
    if len(a_partition) != partition_size or len(b_partition) != partition_size:
        return False

    # 重複チェック
    a_set = set(a_partition)
    b_set = set(b_partition)

    # サイズが同じなら重複なし
    if len(a_set) != len(a_partition) or len(b_set) != len(b_partition):
        return False

    # 交差チェック
    if a_set.intersection(b_set):
        return False

    return True


def generate_garbage_share() -> mpz:
    """
    統計的に区別不可能なガベージシェアを生成する

    Returns:
        ガベージシェア値
    """
    # 暗号論的に安全な乱数で大きな整数を生成
    prime = ShamirConstants.PRIME
    return mpz(secrets.randbelow(int(prime - 1))) + 1


def verify_statistical_indistinguishability(
    garbage_shares: List[mpz],
    valid_shares: List[mpz],
    confidence_level: float = 0.05
) -> bool:
    """
    ガベージシェアと有効シェアの統計的区別不可能性を検証

    Args:
        garbage_shares: ガベージシェアのリスト
        valid_shares: 有効シェアのリスト
        confidence_level: 信頼水準（0.05 = 95%信頼区間）

    Returns:
        indistinguishable: 統計的に区別不可能ならTrue
    """
    # 基本的な統計値を計算
    def calculate_stats(shares):
        n = len(shares)
        if n == 0:
            return {'mean': 0, 'variance': 0, 'min': 0, 'max': 0}

        # 数値に変換
        numeric_shares = [int(share) for share in shares]

        mean = sum(numeric_shares) / n
        variance = sum((x - mean) ** 2 for x in numeric_shares) / max(1, n - 1)
        return {
            'mean': mean,
            'variance': variance,
            'min': min(numeric_shares),
            'max': max(numeric_shares)
        }

    # 統計値を計算
    garbage_stats = calculate_stats(garbage_shares)
    valid_stats = calculate_stats(valid_shares)

    # 平均値の差の検定
    mean_diff = abs(garbage_stats['mean'] - valid_stats['mean'])
    mean_threshold = (garbage_stats['max'] - garbage_stats['min']) * 0.1  # 10%を閾値とする

    # 分散比の検定
    if valid_stats['variance'] == 0 or garbage_stats['variance'] == 0:
        variance_ratio = 0
    else:
        variance_ratio = garbage_stats['variance'] / valid_stats['variance']

    # 分散比の閾値（0.5から2.0程度が一般的）
    variance_threshold_low = 0.5
    variance_threshold_high = 2.0

    # 両方の条件を満たせば統計的に区別不可能と判断
    is_mean_similar = mean_diff < mean_threshold
    is_variance_similar = variance_threshold_low < variance_ratio < variance_threshold_high

    return is_mean_similar and is_variance_similar


class DecryptionError(Exception):
    """パーティションマップキーの復号失敗エラー"""
    pass