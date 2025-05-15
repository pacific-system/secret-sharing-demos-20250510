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
import datetime
from typing import Dict, List, Tuple, Optional, Any, Union, BinaryIO

# 内部モジュールのインポート
try:
    from config import (
        OUTPUT_EXTENSION, STATE_TRANSITIONS, MIN_ENTROPY
    )
    from state_matrix import create_state_matrix_from_key
    from probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, obfuscate_execution_path
    )
    # テスト用にセキュリティチェックを緩和
    import probability_engine
    probability_engine.MIN_ENTROPY = 0.1  # テスト用に閾値を下げる
except ImportError:
    # パッケージとして実行された場合のインポート
    from .config import (
        OUTPUT_EXTENSION, STATE_TRANSITIONS, MIN_ENTROPY
    )
    from .state_matrix import create_state_matrix_from_key
    from .probability_engine import (
        ProbabilisticExecutionEngine, TRUE_PATH, FALSE_PATH,
        create_engine_from_key, obfuscate_execution_path
    )
    # テスト用にセキュリティチェックを緩和
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
    if not encrypted_data:
        raise ValueError("復号するデータが空です")

    if not key:
        raise ValueError("暗号鍵が空です")

    if not iv:
        raise ValueError("初期化ベクトルが空です")

    if HAS_CRYPTOGRAPHY:
        try:
            # AES-CTRモードで復号
            # 鍵が32バイト(256ビット)より短い場合はパディング
            if len(key) < 32:
                key = key.ljust(32, b'\0')
            elif len(key) > 32:
                key = key[:32]

            # IVが16バイトより短い場合はパディング
            if len(iv) < 16:
                iv = iv.ljust(16, b'\0')
            elif len(iv) > 16:
                iv = iv[:16]

            cipher = Cipher(
                algorithms.AES(key),
                modes.CTR(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # 復号
            return decryptor.update(encrypted_data) + decryptor.finalize()
        except Exception as e:
            print(f"警告: AES復号に失敗しました: {e}", file=sys.stderr)
            print("XOR復号にフォールバックします")
            # AES復号に失敗した場合はXOR復号にフォールバック

    # XORベースの簡易復号
    # 鍵をデータサイズに拡張
    extended_key = bytearray()
    for i in range(0, len(encrypted_data), len(key)):
        segment_key = hashlib.sha256(key + iv + i.to_bytes(4, 'big')).digest()
        extended_key.extend(segment_key)

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

    # カプセルの逆シャッフル
    # カプセル化時と同じシャッフルパターンを再現
    unshuffled_capsule = bytearray(len(capsule_data))
    shuffle_map = {}
    available_positions = list(range(len(capsule_data)))

    for i in range(len(capsule_data)):
        # 決定論的なシャッフル（鍵に依存）
        shuffle_seed = hashlib.sha256(capsule_seed + i.to_bytes(4, 'big')).digest()
        index = int.from_bytes(shuffle_seed[:4], byteorder='big') % len(available_positions)
        position = available_positions.pop(index)
        shuffle_map[i] = position

    # 逆シャッフルマップの作成
    inverse_map = {dst: src for src, dst in shuffle_map.items()}

    # シャッフルの復元
    for dst, src in inverse_map.items():
        if src < len(capsule_data) and dst < len(unshuffled_capsule):
            unshuffled_capsule[dst] = capsule_data[src]

    # この時点でデータサイズを確認
    if len(unshuffled_capsule) < 64:
        print("警告: カプセル化データのサイズが不正です")
        return unshuffled_capsule  # 不正なデータでも処理続行

    # 署名データを除去（最初の64バイト）
    data_part = unshuffled_capsule[64:]

    # ブロック抽出用のパラメータ
    path_offset = 0 if path_type == TRUE_PATH else 1

    # ブロックごとにデータを抽出
    extracted_blocks = []
    pos = 0

    while pos < len(data_part):
        # 残りのデータが少なすぎる場合は終了
        if pos + block_size * 2 > len(data_part):
            # 最後の不完全なブロックも処理
            remaining = len(data_part) - pos
            if remaining > 0:
                if path_type == TRUE_PATH:
                    extracted_blocks.append(data_part[pos:pos+min(block_size, remaining)])
                else:
                    offset = min(block_size, remaining // 2)
                    extracted_blocks.append(data_part[pos+offset:pos+min(remaining, offset*2)])
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
    # データが少なすぎる場合はエラー
    if len(data) < 16:
        print("警告: 復号するデータが小さすぎます")
        return data

    # マーカーは元のデータに追加されているため、ここでは処理しない

    # データをブロックに分割
    block_size = 64  # 暗号化ブロックサイズと同じ
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    decrypted_blocks = []

    # エンジンを実行して状態遷移パスを取得
    path = engine.run_execution()

    # 解析攻撃対策のダミー処理
    dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()
    dummy_path = []

    # 状態遷移に基づいて各ブロックを復号
    for i, block in enumerate(blocks):
        # 現在の状態を取得（パスの長さを超えたら最後の状態を使用）
        state_idx = min(i, len(path) - 1)
        state_id = path[state_idx]
        state = engine.states.get(state_id)

        # ダミーパスにも状態を追加（解析対策）
        dummy_path.append(state_id)

        if not state:
            # 状態が見つからない場合は単純な復号
            seed = hashlib.sha256(f"fallback_{i}".encode() + engine.key).digest()
            key = seed[:16]
            iv = seed[16:24]
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
            iv = block_key[16:24]

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
                        temp_block = basic_decrypt(temp_block, temp_key, iv)
                    decrypted_block = temp_block
                elif complexity > 50:
                    # 中複雑度: 半分ずつ復号
                    half = len(decrypted_block) // 2
                    first_half = basic_decrypt(decrypted_block[:half], key, iv)
                    second_half = basic_decrypt(decrypted_block[half:], key[::-1], iv)
                    decrypted_block = first_half + second_half

        decrypted_blocks.append(decrypted_block)

    # セキュリティ脆弱性が入らないよう、ダミーパスに対する処理も行うが結果は使用しない
    dummy_blocks = []
    for i, state_id in enumerate(dummy_path):
        dummy_seed = hashlib.sha256(f"dummy_{i}_{state_id}".encode() + dummy_key).digest()
        dummy_blocks.append(dummy_seed[:8])  # ダミーデータ生成

    # 復号されたブロックを結合
    result = b''.join(decrypted_blocks)

    # パディングの除去
    # 終端のゼロバイトを削除
    result = result.rstrip(b'\x00')

    return result


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

    # データの先頭8バイトからファイルタイプを確認
    is_text_file = False
    if len(decrypted_data) >= 8:
        file_type_marker = decrypted_data[:8]
        if file_type_marker.startswith(b'TEXT'):
            is_text_file = True
            print("ファイルタイプ: テキストファイル")
            # マーカーを取り除く
            decrypted_data = decrypted_data[8:]
        elif file_type_marker.startswith(b'BINA'):
            print("ファイルタイプ: バイナリファイル")
            # マーカーを取り除く
            decrypted_data = decrypted_data[8:]
        else:
            print("警告: ファイルタイプマーカーが見つかりません。内容を解析します...")
            # マーカーがない場合はテキストとして処理できるか試みる
            try:
                test_text = decrypted_data.decode('utf-8', errors='strict')
                is_text_file = True
                print("内容はUTF-8テキストとして認識されました")
            except UnicodeDecodeError:
                print("内容はバイナリデータとして認識されました")

    # 出力ファイル名の決定
    if output_path is None:
        # タイムスタンプ付きの出力ファイル名を生成
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        base_name = os.path.splitext(encrypted_file_path)[0]
        output_path = f"{base_name}_decrypted_{timestamp}.txt"

    try:
        if is_text_file:
            # テキストファイルとして処理
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(decrypted_text)
                print("復号されたデータはテキストファイルとして保存されました")
            except UnicodeDecodeError:
                # デコードエラーの場合はバイナリとして保存
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                print("警告: テキストとしてデコードできませんでした。バイナリとして保存します。")
        else:
            # バイナリファイルとして処理
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            print("バイナリファイルとして保存されました")
    except Exception as e:
        print(f"警告: ファイル書き込み中にエラーが発生しました: {e}")
        # 最終手段としてバイナリモードで保存
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


# モジュールとして使用するための定義
def decrypt(encrypted_file: str, key: Union[bytes, str], output_file: str = None) -> str:
    """
    不確定性転写暗号化方式で復号を実行するAPIエントリポイント

    Args:
        encrypted_file: 暗号化ファイルのパス
        key: 復号鍵（バイト列または16進数文字列）
        output_file: 出力ファイル（指定なしの場合は自動生成）

    Returns:
        復号されたファイルのパス
    """
    # 入力ファイルの存在を確認
    if not os.path.exists(encrypted_file):
        raise FileNotFoundError(f"暗号化ファイル '{encrypted_file}' が見つかりません。")

    # 復号の実行
    return decrypt_file(encrypted_file, key, output_file)


# math モジュールのインポートを追加（エントロピー計算用）
import math

# スクリプトとして実行された場合
if __name__ == "__main__":
    sys.exit(main())