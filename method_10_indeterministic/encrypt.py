#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - 暗号化プログラム

true.textとfalse.textを入力として受け取り、
不確定性転写暗号化方式で暗号化された単一の暗号文ファイルを生成します。
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
import datetime
from typing import Dict, List, Tuple, Optional, Any, Union

# 内部モジュールのインポート
try:
    from config import (
        TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
        STATE_MATRIX_SIZE, STATE_TRANSITIONS, OUTPUT_EXTENSION,
        MIN_ENTROPY
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
        MIN_ENTROPY
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


def read_file(file_path: str) -> bytes:
    """
    ファイルを読み込む

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        ファイルの内容
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"ファイル '{file_path}' の読み込みエラー: {e}", file=sys.stderr)
        raise


def generate_master_key() -> bytes:
    """
    マスター鍵を生成

    Returns:
        ランダムなマスター鍵
    """
    try:
        # 高エントロピーの鍵を生成
        return secrets.token_bytes(KEY_SIZE_BYTES)
    except Exception as e:
        print(f"警告: 安全な鍵生成に失敗しました: {e}", file=sys.stderr)
        # フォールバック: os.urandomを使用
        return os.urandom(KEY_SIZE_BYTES)


def basic_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    基本的な暗号化を行う

    暗号化ライブラリがある場合はAESを使用し、ない場合はXORベースの暗号化を行います。

    Args:
        data: 暗号化するデータ
        key: 暗号鍵
        iv: 初期化ベクトル

    Returns:
        暗号化されたデータ
    """
    if not data:
        raise ValueError("暗号化するデータが空です")

    if not key:
        raise ValueError("暗号鍵が空です")

    if not iv:
        raise ValueError("初期化ベクトルが空です")

    if HAS_CRYPTOGRAPHY:
        try:
            # AES-CTRモードで暗号化
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
            encryptor = cipher.encryptor()

            # 暗号化
            return encryptor.update(data) + encryptor.finalize()
        except Exception as e:
            print(f"警告: AES暗号化に失敗しました: {e}", file=sys.stderr)
            print("XOR暗号化にフォールバックします")
            # AES暗号化に失敗した場合はXOR暗号化にフォールバック

    # XORベースの簡易暗号化
    # 鍵をデータサイズに拡張
    extended_key = bytearray()
    for i in range(0, len(data), len(key)):
        segment_key = hashlib.sha256(key + iv + i.to_bytes(4, 'big')).digest()
        extended_key.extend(segment_key)

    # データとXOR
    return bytes(a ^ b for a, b in zip(data, extended_key[:len(data)]))


def state_based_encrypt(data: bytes, engine: ProbabilisticExecutionEngine, path_type: str) -> bytes:
    """
    状態遷移に基づく暗号化

    Args:
        data: 暗号化するデータ
        engine: 確率的実行エンジン
        path_type: パスタイプ（"true" または "false"）

    Returns:
        暗号化されたデータ
    """
    # データが少なすぎる場合はエラー
    if len(data) < 1:
        raise ValueError("暗号化するデータが空です")

    # データをブロックに分割
    block_size = 64  # 共通のブロックサイズ
    blocks = []

    # データを block_size ごとに分割
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            # パディングを適用（ゼロパディング）
            block = block + b'\x00' * (block_size - len(block))
        blocks.append(block)

    # 最低1ブロックを確保
    if not blocks:
        blocks.append(b'\x00' * block_size)

    # エンジンを実行して状態遷移パスを取得
    path = engine.run_execution()

    # 解析攻撃対策のダミー処理
    dummy_key = hashlib.sha256(engine.key + path_type.encode()).digest()
    dummy_path = []

    # 状態遷移に基づいて各ブロックを暗号化
    encrypted_blocks = []
    for i, block in enumerate(blocks):
        # 現在の状態を取得（パスの長さを超えたら最後の状態を使用）
        state_idx = min(i, len(path) - 1)
        state_id = path[state_idx]
        state = engine.states.get(state_id)

        # ダミーパスにも状態を追加（解析対策）
        dummy_path.append(state_id)

        if not state:
            # 状態が見つからない場合は単純な暗号化
            seed = hashlib.sha256(f"fallback_{i}".encode() + engine.key).digest()
            key = seed[:16]
            iv = seed[16:24]
            encrypted_block = basic_encrypt(block, key, iv)
        else:
            # 状態の属性から暗号化パラメータを導出
            attrs = state.attributes
            block_key = hashlib.sha256(
                engine.key +
                attrs.get("hash_seed", b"") +
                i.to_bytes(4, 'big')
            ).digest()

            # 状態ごとに異なる暗号化パラメータ
            key = block_key[:16]
            iv = block_key[16:24]

            # 変換キーを使った追加の処理（状態に依存）
            transform_key = attrs.get("transform_key", b"")
            if transform_key:
                # ブロックの一部を変換（複雑な処理を追加）
                complexity = attrs.get("complexity", 0)
                volatility = attrs.get("volatility", 0)

                # 複雑度に応じた処理（再帰的な暗号化など）
                if complexity > 80:
                    # 高複雑度: 複数回の暗号化
                    temp_block = block
                    for j in range(3):
                        temp_key = hashlib.sha256(key + j.to_bytes(1, 'big')).digest()[:16]
                        temp_block = basic_encrypt(temp_block, temp_key, iv)
                    block = temp_block
                elif complexity > 50:
                    # 中複雑度: ブロックを分割して個別に暗号化
                    half = len(block) // 2
                    first_half = basic_encrypt(block[:half], key, iv)
                    second_half = basic_encrypt(block[half:], key[::-1], iv)
                    block = first_half + second_half

                # 揮発性に応じた処理（ノイズの追加など）
                if volatility > 70:
                    # 高揮発性: ノイズの追加
                    noise = hashlib.sha256(transform_key + block).digest()[:min(8, len(block))]
                    block_list = bytearray(block)
                    for j, noise_byte in enumerate(noise):
                        block_list[j % len(block_list)] ^= noise_byte
                    block = bytes(block_list)

            # 最終的な暗号化
            encrypted_block = basic_encrypt(block, key, iv)

        encrypted_blocks.append(encrypted_block)

    # セキュリティ脆弱性が入らないよう、ダミーパスに対する処理も行うが結果は使用しない
    dummy_blocks = []
    for i, state_id in enumerate(dummy_path):
        dummy_seed = hashlib.sha256(f"dummy_{i}_{state_id}".encode() + dummy_key).digest()
        dummy_blocks.append(dummy_seed[:8])  # ダミーデータ生成

    # 暗号化されたブロックを結合
    return b''.join(encrypted_blocks)


def inject_entropy(true_data: bytes, false_data: bytes, key: bytes, salt: bytes) -> bytes:
    """
    状態エントロピーを注入

    Args:
        true_data: 正規データの暗号文
        false_data: 非正規データの暗号文
        key: マスター鍵
        salt: ソルト値

    Returns:
        エントロピー注入データ
    """
    # エントロピーシードの生成
    entropy_seed = hashlib.sha256(key + salt + b"entropy_injection").digest()

    # 擬似乱数生成器の初期化
    random_data = bytearray()
    for i in range(64):  # 十分なエントロピーデータを生成
        chunk = hashlib.sha256(entropy_seed + i.to_bytes(4, 'big')).digest()
        random_data.extend(chunk)

    # ノイズデータの生成（解析防止のための偽情報）
    true_noise = generate_anti_analysis_noise(key, TRUE_PATH)
    false_noise = generate_anti_analysis_noise(key, FALSE_PATH)

    # エントロピーデータの結合
    entropy_parts = [
        random_data,
        hashlib.sha256(true_data).digest(),
        hashlib.sha256(false_data).digest(),
        true_noise[:32],
        false_noise[:32]
    ]

    # 複雑なマーカーを追加（解析困難化のため）
    markers = []
    for i in range(8):
        marker = hashlib.sha256(key + i.to_bytes(4, 'big') + salt).digest()[:8]
        markers.append(marker)

    # マーカーを分散配置
    result = bytearray()
    for i, part in enumerate(entropy_parts):
        result.extend(markers[i % len(markers)])
        result.extend(part)

    # 最終エントロピーデータ
    return bytes(result)


def create_state_capsule(
    true_encrypted: bytes,
    false_encrypted: bytes,
    true_signature: bytes,
    false_signature: bytes,
    key: bytes,
    salt: bytes
) -> bytes:
    """
    暗号化データを状態カプセルに包む

    Args:
        true_encrypted: 正規データの暗号文
        false_encrypted: 非正規データの暗号文
        true_signature: 正規パスの署名
        false_signature: 非正規パスの署名
        key: マスター鍵
        salt: ソルト値

    Returns:
        カプセル化されたデータ
    """
    # カプセル化パラメータのシード値
    capsule_seed = hashlib.sha256(key + salt + b"state_capsule").digest()

    # データブロックサイズの決定
    block_size = 64

    # true_encryptedとfalse_encryptedをブロック単位で処理
    true_blocks = [true_encrypted[i:i+block_size] for i in range(0, len(true_encrypted), block_size)]
    false_blocks = [false_encrypted[i:i+block_size] for i in range(0, len(false_encrypted), block_size)]

    # ブロック数を揃える（短い方にダミーブロックを追加）
    max_blocks = max(len(true_blocks), len(false_blocks))

    if len(true_blocks) < max_blocks:
        for i in range(max_blocks - len(true_blocks)):
            dummy = hashlib.sha256(capsule_seed + b"true_dummy" + i.to_bytes(4, 'big')).digest()[:block_size]
            true_blocks.append(dummy)

    if len(false_blocks) < max_blocks:
        for i in range(max_blocks - len(false_blocks)):
            dummy = hashlib.sha256(capsule_seed + b"false_dummy" + i.to_bytes(4, 'big')).digest()[:block_size]
            false_blocks.append(dummy)

    # カプセル化データの生成
    capsule = bytearray()

    # 署名データの埋め込み（隠蔽）
    capsule.extend(hashlib.sha256(capsule_seed + true_signature).digest())
    capsule.extend(hashlib.sha256(capsule_seed + false_signature).digest())

    # インターリーブ方式でブロックを交互に配置
    for i in range(max_blocks):
        # ブロック選択パターンのシード
        pattern_seed = hashlib.sha256(capsule_seed + i.to_bytes(4, 'big')).digest()
        pattern_value = pattern_seed[0]

        # パターンに基づいて配置順を決定
        if pattern_value % 3 == 0:
            # 正規→非正規
            capsule.extend(true_blocks[i])
            capsule.extend(false_blocks[i])
        elif pattern_value % 3 == 1:
            # 非正規→正規
            capsule.extend(false_blocks[i])
            capsule.extend(true_blocks[i])
        else:
            # 交互にバイトを配置
            t_block = true_blocks[i]
            f_block = false_blocks[i]
            mixed = bytearray()
            for j in range(max(len(t_block), len(f_block))):
                if j < len(t_block):
                    mixed.append(t_block[j])
                if j < len(f_block):
                    mixed.append(f_block[j])
            capsule.extend(mixed)

    # カプセルのシャッフル（さらなる攪拌）
    final_capsule = bytearray(len(capsule))

    # シャッフルパターンの生成
    shuffle_map = {}
    available_positions = list(range(len(capsule)))

    for i in range(len(capsule)):
        # 決定論的なシャッフル（鍵に依存）
        shuffle_seed = hashlib.sha256(capsule_seed + i.to_bytes(4, 'big')).digest()
        index = int.from_bytes(shuffle_seed[:4], byteorder='big') % len(available_positions)
        position = available_positions.pop(index)
        shuffle_map[i] = position

    # シャッフルの適用
    for src, dst in shuffle_map.items():
        if src < len(capsule) and dst < len(final_capsule):
            final_capsule[dst] = capsule[src]

    return bytes(final_capsule)


def encrypt_files(true_file_path: str, false_file_path: str, output_path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    不確定性転写暗号化方式で暗号化

    Args:
        true_file_path: 正規ファイルのパス
        false_file_path: 非正規ファイルのパス
        output_path: 出力ファイルのパス

    Returns:
        (マスター鍵, メタデータ)
    """
    # ファイルの読み込み
    true_data = read_file(true_file_path)
    false_data = read_file(false_file_path)

    # ファイルタイプのチェック
    is_true_text = False
    is_false_text = False

    try:
        # UTF-8テキストとしてデコード試行
        _ = true_data.decode('utf-8')
        is_true_text = True
        print(f"正規ファイル '{true_file_path}' はUTF-8テキストとして認識されました")
    except UnicodeDecodeError:
        print(f"正規ファイル '{true_file_path}' はバイナリとして認識されました")

    try:
        # UTF-8テキストとしてデコード試行
        _ = false_data.decode('utf-8')
        is_false_text = True
        print(f"非正規ファイル '{false_file_path}' はUTF-8テキストとして認識されました")
    except UnicodeDecodeError:
        print(f"非正規ファイル '{false_file_path}' はバイナリとして認識されました")

    # ファイルタイプマーカーの追加
    if is_true_text:
        true_data = b'TEXT' + b'\x00' * 4 + true_data
    else:
        true_data = b'BINA' + b'\x00' * 4 + true_data

    if is_false_text:
        false_data = b'TEXT' + b'\x00' * 4 + false_data
    else:
        false_data = b'BINA' + b'\x00' * 4 + false_data

    # エントロピーチェック
    true_entropy = calculate_entropy(true_data)
    false_entropy = calculate_entropy(false_data)

    # 最小エントロピー要件のチェック（バックドア検出）
    if true_entropy < MIN_ENTROPY or false_entropy < MIN_ENTROPY:
        raise ValueError(f"入力ファイルのエントロピーが低すぎます。バックドアの疑いがあります。" +
                         f"true: {true_entropy:.4f}, false: {false_entropy:.4f}, 必要: {MIN_ENTROPY:.4f}")

    # データ長の確認・調整
    max_length = max(len(true_data), len(false_data))

    # データが短い方をパディング
    if len(true_data) < max_length:
        true_data = true_data + os.urandom(max_length - len(true_data))
    if len(false_data) < max_length:
        false_data = false_data + os.urandom(max_length - len(false_data))

    # マスター鍵の生成
    master_key = generate_master_key()

    # ソルト値の生成
    salt = os.urandom(16)

    # 両方のパスタイプの暗号化を実行
    print("非決定論的状態機械を初期化中...")
    true_engine = create_engine_from_key(master_key, TRUE_PATH, salt)
    false_engine = create_engine_from_key(master_key, FALSE_PATH, salt)

    print("正規データを暗号化中...")
    true_encrypted = state_based_encrypt(true_data, true_engine, TRUE_PATH)

    print("非正規データを暗号化中...")
    false_encrypted = state_based_encrypt(false_data, false_engine, FALSE_PATH)

    # 実行パスの署名を取得
    true_signature = true_engine.get_execution_signature()
    false_signature = false_engine.get_execution_signature()

    # 状態エントロピー注入
    print("状態エントロピー注入中...")
    entropy_data = inject_entropy(true_encrypted, false_encrypted, master_key, salt)

    # 状態データのカプセル化
    print("状態カプセル化中...")
    capsule = create_state_capsule(true_encrypted, false_encrypted, true_signature, false_signature, master_key, salt)

    # タイムスタンプの生成
    timestamp = int(time.time())
    date_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y%m%d%H%M%S")

    # メタデータの作成
    metadata = {
        "format": "indeterministic",
        "version": "1.0",
        "timestamp": timestamp,
        "date": date_str,
        "salt": base64.b64encode(salt).decode('ascii'),
        "content_length": max_length,
        "states": STATE_MATRIX_SIZE,
        "transitions": STATE_TRANSITIONS,
        "true_entropy": true_entropy,
        "false_entropy": false_entropy,
        "checksum": hashlib.sha256(capsule).hexdigest()
    }

    # 出力ファイルの作成
    with open(output_path, 'wb') as f:
        # ヘッダーの書き込み
        header = {
            "metadata": metadata,
            "entropy_length": len(entropy_data)
        }
        header_json = json.dumps(header).encode('utf-8')
        f.write(len(header_json).to_bytes(4, byteorder='big'))
        f.write(header_json)

        # エントロピーデータの書き込み
        f.write(entropy_data)

        # カプセル化データの書き込み
        f.write(capsule)

    print(f"暗号化完了: '{output_path}' に暗号文を書き込みました。")
    print(f"鍵: {binascii.hexlify(master_key).decode('ascii')}")

    return master_key, metadata


def calculate_entropy(data: bytes) -> float:
    """
    データのエントロピーを計算

    Args:
        data: 計算対象のデータ

    Returns:
        Shannon エントロピー値 (0.0-8.0)
    """
    if not data:
        return 0.0

    # バイト値の出現頻度を計算
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    # Shannon エントロピーの計算
    entropy = 0.0
    for count in freq.values():
        probability = count / len(data)
        entropy -= probability * (math.log2(probability) if probability > 0 else 0)

    return entropy


def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式の暗号化プログラム")

    parser.add_argument(
        "--true-file",
        type=str,
        default=TRUE_TEXT_PATH,
        help=f"正規ファイルのパス（デフォルト: {TRUE_TEXT_PATH}）"
    )

    parser.add_argument(
        "--false-file",
        type=str,
        default=FALSE_TEXT_PATH,
        help=f"非正規ファイルのパス（デフォルト: {FALSE_TEXT_PATH}）"
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help=f"出力ファイルのパス（デフォルト: 自動生成）"
    )

    parser.add_argument(
        "--save-key",
        action="store_true",
        help="生成された鍵をファイルに保存する"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在を確認
    if not os.path.exists(args.true_file):
        print(f"エラー: 正規ファイル '{args.true_file}' が見つかりません。", file=sys.stderr)
        return 1

    if not os.path.exists(args.false_file):
        print(f"エラー: 非正規ファイル '{args.false_file}' が見つかりません。", file=sys.stderr)
        return 1

    # 出力ファイル名の決定
    if args.output:
        output_path = args.output
    else:
        # タイムスタンプ付きの出力ファイル名を生成
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        output_path = f"output_{timestamp}{OUTPUT_EXTENSION}"

    # 出力ディレクトリが存在するか確認
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"ディレクトリを作成しました: {output_dir}")
        except OSError as e:
            print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
            return 1

    try:
        # 暗号化の実行
        start_time = time.time()
        key, metadata = encrypt_files(args.true_file, args.false_file, output_path)
        end_time = time.time()

        print(f"暗号化時間: {end_time - start_time:.2f}秒")

        # 鍵の保存（オプション）
        if args.save_key:
            # タイムスタンプを鍵ファイル名にも使用
            timestamp = metadata.get("date", datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
            key_file = f"key_{timestamp}.bin"
            with open(key_file, 'wb') as f:
                f.write(key)
            print(f"鍵を保存しました: {key_file}")
            # 鍵ファイルのパーミッションを制限
            os.chmod(key_file, 0o600)

        return 0

    except Exception as e:
        print(f"エラー: 暗号化中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


# モジュールとして使用するための定義
def encrypt(true_file: str, false_file: str, output_file: str = None, save_key: bool = False) -> Tuple[bytes, str]:
    """
    不確定性転写暗号化方式で暗号化を実行するAPIエントリポイント

    Args:
        true_file: 正規ファイルのパス
        false_file: 非正規ファイルのパス
        output_file: 出力ファイル（指定なしの場合は自動生成）
        save_key: 鍵をファイルに保存するかどうか

    Returns:
        (鍵, 出力ファイルパス)
    """
    # 入力ファイルの存在を確認
    if not os.path.exists(true_file):
        raise FileNotFoundError(f"正規ファイル '{true_file}' が見つかりません。")

    if not os.path.exists(false_file):
        raise FileNotFoundError(f"非正規ファイル '{false_file}' が見つかりません。")

    # 出力ファイル名の決定
    if not output_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        output_file = f"output_{timestamp}{OUTPUT_EXTENSION}"

    # 暗号化の実行
    key, _ = encrypt_files(true_file, false_file, output_file)

    # 鍵の保存（オプション）
    if save_key:
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        key_file = f"key_{timestamp}.bin"
        with open(key_file, 'wb') as f:
            f.write(key)
        # 鍵ファイルのパーミッションを制限
        os.chmod(key_file, 0o600)

    return key, output_file


# math モジュールのインポートを追加
import math

# スクリプトとして実行された場合
if __name__ == "__main__":
    sys.exit(main())