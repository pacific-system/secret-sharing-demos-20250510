#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 復号プログラム

暗号文ファイルと鍵を入力として受け取り、
鍵の種類に応じて異なる平文（true.text/false.text）を復元します。
"""

import os
import sys
import json
import time
import base64
import argparse
import hashlib
import binascii
import math
from typing import Dict, List, Tuple, Optional, Any, BinaryIO, Union

# 内部モジュールのインポート
try:
    # パッケージとして実行する場合
    from .config import (
        TRUE_TEXT_PATH, FALSE_TEXT_PATH, OUTPUT_EXTENSION,
        STATE_MATRIX_SIZE, STATE_TRANSITIONS
    )
    from .state_matrix import State, StateMatrix, create_state_matrix_from_key
    from .probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, obfuscate_execution_path
    )
except ImportError:
    # ローカルモジュールとして実行する場合
    from config import (
        TRUE_TEXT_PATH, FALSE_TEXT_PATH, OUTPUT_EXTENSION,
        STATE_MATRIX_SIZE, STATE_TRANSITIONS
    )
    import state_matrix
    from state_matrix import create_state_matrix_from_key
    from probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, obfuscate_execution_path
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
    print("警告: cryptographyライブラリがインストールされていません。単純なXOR暗号を使用します。", file=sys.stderr)


def basic_decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    基本的な復号を行う

    暗号化ライブラリがある場合はAESを使用し、ない場合はXORベースの復号を行います。

    Args:
        encrypted_data: 復号するデータ
        key: 暗号鍵
        iv: 初期化ベクトル

    Returns:
        復号されたデータ
    """
    if HAS_CRYPTOGRAPHY:
        # AES-CTRモードで復号
        cipher = Cipher(
            algorithms.AES(key[:16]),  # AESは16, 24, 32バイトの鍵をサポート
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # 復号
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # PKCS7パディングを除去
        try:
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except ValueError:
            # パディングエラーの場合はパディングなしで返す
            return padded_data
    else:
        # XORベースの簡易復号
        # 鍵をデータサイズに拡張
        extended_key = bytearray()

        # 鍵が小さすぎる場合のセキュリティ対策
        if len(key) < 16:
            raise ValueError("鍵は少なくとも16バイト必要です")

        for i in range(0, len(encrypted_data), len(key)):
            # HMAC派生でより安全な拡張キーを生成
            chunk_key = hashlib.sha256(key + iv + i.to_bytes(4, 'big')).digest()
            extended_key.extend(chunk_key)

        # データとXOR
        return bytes(a ^ b for a, b in zip(encrypted_data, extended_key[:len(encrypted_data)]))


def read_encrypted_file(file_path: str) -> Tuple[Dict[str, Any], bytes, bytes]:
    """
    暗号化ファイルを読み込む

    Args:
        file_path: 読み込む暗号化ファイルのパス

    Returns:
        (メタデータ, エントロピーデータ, カプセル化データ)
    """
    try:
        with open(file_path, 'rb') as f:
            # ヘッダーの長さを読み込む
            header_length_bytes = f.read(4)
            if not header_length_bytes or len(header_length_bytes) < 4:
                raise ValueError("ファイルヘッダーが不正です")

            header_length = int.from_bytes(header_length_bytes, byteorder='big')

            # ヘッダーを読み込む
            header_json = f.read(header_length)
            if not header_json or len(header_json) < header_length:
                raise ValueError("ファイルヘッダーが不完全です")

            header = json.loads(header_json.decode('utf-8'))
            metadata = header.get("metadata", {})
            entropy_length = header.get("entropy_length", 0)

            # エントロピーデータを読み込む
            entropy_data = f.read(entropy_length)
            if not entropy_data or len(entropy_data) < entropy_length:
                raise ValueError("エントロピーデータが不完全です")

            # 残りのデータ（カプセル化データ）を読み込む
            capsule_data = f.read()
            if not capsule_data:
                raise ValueError("カプセル化データが見つかりません")

            # チェックサムの検証
            if "checksum" in metadata:
                calculated_checksum = hashlib.sha256(capsule_data).hexdigest()
                if calculated_checksum != metadata["checksum"]:
                    raise ValueError("カプセル化データのチェックサムが一致しません")

            return metadata, entropy_data, capsule_data

    except Exception as e:
        print(f"暗号化ファイル '{file_path}' の読み込みエラー: {e}", file=sys.stderr)
        raise


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

    # 解析対策のための複雑な分岐
    if dummy1[0] % 2 == 0:
        temp_value = verify_hash[0] ^ dummy1[1]
    else:
        temp_value = verify_hash[0] ^ dummy2[1]

    # 状態マトリクスと確率エンジンを初期化
    # これにより、鍵に応じた状態遷移パターンが生成されます
    engine = create_engine_from_key(key, TRUE_PATH, salt)

    # エンジンを実行して実行パスの特性を取得
    engine.run_execution()
    signature = engine.get_execution_signature()

    # 署名の特性に基づいてパスタイプを決定
    # この部分が鍵依存のパス決定ロジック

    # 署名の特性を計算
    sig_sum = sum(signature) % 256

    # パス決定のためのハッシュを計算
    path_seed = hashlib.sha256(key + salt + b"path_determination").digest()
    threshold = int.from_bytes(path_seed[:4], byteorder='big') % 256

    # どちらの方向にバイアスするかを決定
    # これは鍵に完全に依存し、ソースコード解析で予測不可能
    path_type = TRUE_PATH if sig_sum < threshold else FALSE_PATH

    # 解析対策のための難読化
    obfuscate_execution_path(engine)

    return path_type


def extract_from_capsule(
    capsule_data: bytes,
    key: bytes,
    salt: bytes,
    path_type: str
) -> bytes:
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
    # カプセル化パラメータのシード値
    capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()

    # データブロックサイズの決定
    block_size = 64

    # シャッフル逆変換
    # シャッフルパターンの生成
    indices = list(range(len(capsule_data)))

    # 鍵依存のシャッフル（決定論的）- 暗号化時と同じパターン
    shuffled_indices = []
    hash_stream = b""

    while indices:
        if not hash_stream:
            hash_stream = hashlib.sha256(capsule_seed + len(shuffled_indices).to_bytes(4, 'big')).digest()

        # ハッシュストリームから4バイト取得してインデックスを選択
        val = int.from_bytes(hash_stream[:4], byteorder='big')
        hash_stream = hash_stream[4:]

        # 残りのインデックスからランダムに選択
        idx = val % len(indices)
        shuffled_indices.append(indices.pop(idx))

    # シャッフル逆変換マップの作成
    inverse_map = {src: dst for dst, src in enumerate(shuffled_indices)}

    # シャッフル逆変換の適用
    unshuffled_capsule = bytearray(len(capsule_data))
    for src, dst in inverse_map.items():
        if src < len(capsule_data) and dst < len(unshuffled_capsule):
            unshuffled_capsule[dst] = capsule_data[src]

    # 署名データを除去（最初の64バイト）
    data_part = unshuffled_capsule[64:]

    # ブロック抽出用のパラメータ
    path_offset = 0 if path_type == TRUE_PATH else 1

    # ブロックごとにデータを抽出
    extracted_blocks = []
    pos = 0

    while pos < len(data_part):
        # 残りのデータが少なすぎる場合は終了
        if pos + block_size > len(data_part):
            break

        # ブロック選択パターンのシード
        block_index = len(extracted_blocks)
        pattern_seed = hashlib.sha256(capsule_seed + block_index.to_bytes(4, 'big')).digest()
        pattern_value = pattern_seed[0] % 3

        # パターンに基づいてブロックを抽出
        if pattern_value == 0:
            # 正規→非正規
            if path_type == TRUE_PATH:
                extracted_blocks.append(data_part[pos:pos+block_size])
                pos += block_size * 2
            else:
                extracted_blocks.append(data_part[pos+block_size:pos+block_size*2])
                pos += block_size * 2
        elif pattern_value == 1:
            # 非正規→正規
            if path_type == TRUE_PATH:
                extracted_blocks.append(data_part[pos+block_size:pos+block_size*2])
                pos += block_size * 2
            else:
                extracted_blocks.append(data_part[pos:pos+block_size])
                pos += block_size * 2
        else:
            # 交互に配置されている場合、バイト単位で抽出
            block = bytearray()
            for i in range(block_size * 2):
                if i % 2 == path_offset and pos + i < len(data_part):
                    block.append(data_part[pos + i])
            extracted_blocks.append(bytes(block))
            pos += block_size * 2

    # 抽出したブロックを結合
    return b''.join(extracted_blocks)


def state_based_decrypt(
    data: bytes,
    engine: ProbabilisticExecutionEngine,
    path_type: str
) -> bytes:
    """
    状態遷移に基づく復号を行う

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

        if not state:
            # 状態が見つからない場合は単純な復号
            seed = hashlib.sha256(f"fallback_{i}".encode() + engine.key).digest()
            key = seed[:16]
            iv = seed[16:28]  # CTRモードでは12バイト必要
            decrypted_block = basic_decrypt(block, key, iv)
        else:
            # 状態の属性から復号パラメータを導出
            attrs = state.attributes
            block_key = hashlib.sha256(
                engine.key +
                attrs.get("hash_seed", b"") +
                i.to_bytes(4, 'big')
            ).digest()

            # 状態ごとに異なる復号パラメータ
            key = block_key[:16]
            iv = block_key[16:28]  # CTRモードでは12バイト必要

            # 基本的な復号
            decrypted_block = basic_decrypt(block, key, iv)

            # 変換キーを使った追加の処理（状態に依存）
            transform_key = attrs.get("transform_key", b"")
            if transform_key:
                # ブロックの一部を逆変換（暗号化時の逆処理）
                complexity = attrs.get("complexity", 0)
                volatility = attrs.get("volatility", 0)

                # 揮発性に応じた処理（ノイズの除去など）
                if volatility > 70:
                    # 高揮発性: ノイズの除去
                    noise = hashlib.sha256(transform_key + decrypted_block).digest()[:min(8, len(decrypted_block))]
                    block_list = bytearray(decrypted_block)
                    for j, noise_byte in enumerate(noise):
                        block_list[j % len(block_list)] ^= noise_byte
                    decrypted_block = bytes(block_list)

                # 複雑度に応じた処理（多重復号など）
                if complexity > 80:
                    # 高複雑度: 複数回の復号（暗号化の逆順）
                    temp_block = decrypted_block
                    for j in range(2, -1, -1):
                        temp_key = hashlib.sha256(key + j.to_bytes(1, 'big')).digest()[:16]
                        temp_iv = hashlib.sha256(iv + j.to_bytes(1, 'big')).digest()[:12]
                        temp_block = basic_decrypt(temp_block, temp_key, temp_iv)
                    decrypted_block = temp_block
                elif complexity > 50:
                    # 中複雑度: 半分ずつ復号
                    half = len(decrypted_block) // 2
                    first_half = basic_decrypt(decrypted_block[:half], key, iv)
                    second_half = basic_decrypt(decrypted_block[half:], key[::-1], iv)
                    decrypted_block = first_half + second_half

        decrypted_blocks.append(decrypted_block)

    # 復号されたブロックを結合
    return b''.join(decrypted_blocks)


def decrypt_file(
    encrypted_file_path: str,
    key: Union[bytes, str],
    output_path: Optional[str] = None
) -> str:
    """
    不確定性転写暗号化方式で復号

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        key: 復号鍵（バイト列または16進数文字列）
        output_path: 出力ファイルのパス（省略時は自動生成）

    Returns:
        復号されたファイルのパス
    """
    # 鍵がバイト列でない場合は変換
    if isinstance(key, str):
        try:
            key = binascii.unhexlify(key)
        except binascii.Error:
            key = key.encode('utf-8')

    # 暗号化ファイルの読み込み
    print("暗号化ファイルを読み込み中...")
    metadata, entropy_data, capsule_data = read_encrypted_file(encrypted_file_path)

    # ソルト値の取得
    salt_base64 = metadata.get("salt", "")
    try:
        salt = base64.b64decode(salt_base64)
    except:
        print("警告: ソルトの復号に失敗しました。ランダムな値を使用します。")
        salt = os.urandom(16)

    # 実行パスの決定
    print("実行パスを決定中...")
    path_type = determine_execution_path(key, metadata)

    # 確率的実行エンジンの初期化
    print(f"確率的実行エンジンを初期化中... (パスタイプ: {path_type})")
    engine = create_engine_from_key(key, path_type, salt)

    # カプセル化データから特定パスのデータを抽出
    print("カプセル化データを解析中...")
    extracted_data = extract_from_capsule(capsule_data, key, salt, path_type)

    # 抽出したデータを復号
    print("データを復号中...")
    decrypted_data = state_based_decrypt(extracted_data, engine, path_type)

    # パディングの除去
    # 終端のゼロバイトを削除
    decrypted_data = decrypted_data.rstrip(b'\x00')

    # 出力ファイル名の決定
    if output_path is None:
        base_name = os.path.splitext(encrypted_file_path)[0]
        output_path = f"{base_name}_decrypted.txt"

    # 復号したデータをファイルに書き込み
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"復号完了: '{output_path}' に結果を書き込みました。")
    return output_path


def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式の復号プログラム")

    parser.add_argument(
        "input_file",
        type=str,
        help="復号する暗号化ファイルのパス"
    )

    parser.add_argument(
        "key",
        type=str,
        help="復号鍵（16進数形式）"
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="出力ファイルのパス（省略時は自動生成）"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在を確認
    if not os.path.exists(args.input_file):
        print(f"エラー: 暗号化ファイル '{args.input_file}' が見つかりません。", file=sys.stderr)
        return 1

    # 出力ディレクトリが存在するか確認
    if args.output:
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"ディレクトリを作成しました: {output_dir}")
            except OSError as e:
                print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
                return 1

    try:
        # 復号鍵の変換
        try:
            key = binascii.unhexlify(args.key)
        except binascii.Error:
            print("警告: 鍵が16進数形式ではありません。UTF-8エンコードされたテキストとして扱います。")
            key = args.key.encode('utf-8')

        # 復号の実行
        start_time = time.time()
        decrypt_file(args.input_file, key, args.output)
        end_time = time.time()

        print(f"復号時間: {end_time - start_time:.2f}秒")
        return 0

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())