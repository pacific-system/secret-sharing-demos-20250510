# 不確定性転写暗号化方式 🎲 実装【子 Issue #4】：暗号化実装（encrypt.py）

お兄様！不確定性転写暗号化方式の暗号化機能を実装しましょう！状態遷移と確率的実行を組み合わせた魔法のような暗号化プログラムの完成です ✨

## 📋 タスク概要

ここまでに実装した状態遷移マトリクス生成機構と確率的実行エンジンを使用して、暗号化プログラム（`encrypt.py`）を実装します。このプログラムは、正規ファイル（true.text）と非正規ファイル（false.text）を入力として、不確定性転写暗号化方式で暗号化された単一の暗号文ファイルを生成します。

## 🔧 実装内容

`method_10_indeterministic/encrypt.py` ファイルに、暗号化機能を実装します。

### 主要な機能：

1. コマンドライン引数の処理
2. 入力ファイル読み込み
3. 状態遷移マトリクスの生成
4. 確率的実行エンジンの初期化
5. 状態遷移に基づく暗号化処理
6. 状態エントロピー注入
7. 暗号文の生成と保存

## 💻 実装手順

### 1. 必要なライブラリのインポート

`encrypt.py` の先頭に以下を記述します：

```python
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
from typing import Dict, List, Tuple, Optional, Any

# 内部モジュールのインポート
from .config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
    STATE_MATRIX_SIZE, STATE_TRANSITIONS, OUTPUT_EXTENSION
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
```

### 2. ヘルパー関数の実装

```python
def read_file(file_path: str) -> bytes:
    """
    ファイルを読み込む

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        ファイルの内容（バイト列）
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
    if HAS_CRYPTOGRAPHY:
        # AES-CTRモードで暗号化
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # PKCS7パディングを適用
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # 暗号化
        return encryptor.update(padded_data) + encryptor.finalize()
    else:
        # XORベースの簡易暗号化
        # 鍵をデータサイズに拡張
        extended_key = bytearray()
        for i in range(0, len(data), len(key)):
            extended_key.extend(hashlib.sha256(key + iv + i.to_bytes(4, 'big')).digest())

        # データとXOR
        return bytes(a ^ b for a, b in zip(data, extended_key[:len(data)]))
```

### 3. 状態ベースの暗号化関数の実装

```python
def state_based_encrypt(data: bytes, engine: ProbabilisticExecutionEngine, path_type: str) -> bytes:
    """
    状態遷移に基づく暗号化を行う

    Args:
        data: 暗号化するデータ
        engine: 確率的実行エンジン
        path_type: パスタイプ（"true" または "false"）

    Returns:
        暗号化されたデータ
    """
    # データをブロックに分割
    block_size = 64  # 暗号化ブロックサイズ
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    encrypted_blocks = []

    # エンジンを実行して状態遷移パスを取得
    path = engine.run_execution()

    # 状態遷移に基づいて各ブロックを暗号化
    for i, block in enumerate(blocks):
        # 現在の状態を取得（パスの長さを超えたら最後の状態を使用）
        state_idx = min(i, len(path) - 1)
        state_id = path[state_idx]
        state = engine.states.get(state_id)

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

    # 暗号化されたブロックを結合
    return b''.join(encrypted_blocks)
```

### 4. メイン暗号化関数の実装

```python
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

    # メタデータの作成
    metadata = {
        "format": "indeterministic",
        "version": "1.0",
        "timestamp": int(time.time()),
        "salt": base64.b64encode(salt).decode('ascii'),
        "content_length": max_length,
        "states": STATE_MATRIX_SIZE,
        "transitions": STATE_TRANSITIONS,
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
```

### 5. 状態エントロピー注入とカプセル化関数の実装

```python
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
```

### 6. コマンドライン処理の実装

```python
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
        default=f"output{OUTPUT_EXTENSION}",
        help=f"出力ファイルのパス（デフォルト: output{OUTPUT_EXTENSION}）"
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

    # 出力ディレクトリが存在するか確認
    output_dir = os.path.dirname(args.output)
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
        key, _ = encrypt_files(args.true_file, args.false_file, args.output)
        end_time = time.time()

        print(f"暗号化時間: {end_time - start_time:.2f}秒")

        # 鍵の保存（オプション）
        if args.save_key:
            key_file = f"{os.path.splitext(args.output)[0]}.key"
            with open(key_file, 'wb') as f:
                f.write(key)
            print(f"鍵を保存しました: {key_file}")

        return 0

    except Exception as e:
        print(f"エラー: 暗号化中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

## ✅ 完了条件

- [ ] ファイル読み込み機能が正しく実装されている
- [ ] 基本的な暗号化関数が実装されている（AES または XOR ベース）
- [ ] 状態遷移に基づいた暗号化処理が実装されている
- [ ] 状態エントロピー注入機能が実装されている
- [ ] 状態カプセル化機能が実装されている
- [ ] コマンドライン引数処理が実装されている
- [ ] 正規/非正規ファイルから単一の暗号文が生成され、鍵が返される
- [ ] エラー処理が適切に実装されている

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# ヘルプの表示
python -m method_10_indeterministic.encrypt --help

# デフォルト設定での暗号化
python -m method_10_indeterministic.encrypt

# カスタムファイル指定での暗号化
python -m method_10_indeterministic.encrypt --true-file path/to/true.text --false-file path/to/false.text --output custom_output.indet

# 鍵ファイルの保存
python -m method_10_indeterministic.encrypt --save-key
```

## ⏰ 想定実装時間

約 4 時間

## 📚 参考資料

- [Python の cryptography ライブラリ](https://cryptography.io/en/latest/)
- [暗号化ファイル形式の設計](https://www.ietf.org/rfc/rfc5652.txt)
- [確率的暗号化の原理](https://en.wikipedia.org/wiki/Probabilistic_encryption)
- [Python の argparse モジュール](https://docs.python.org/3/library/argparse.html)

## 💬 備考

- 実装に使用するライブラリによっては、追加のインストールが必要になる場合があります
- 特に速度が求められる場合は、`cryptography` ライブラリを使用することを推奨します
- 状態エントロピー注入と状態カプセル化は、暗号文の安全性を高めるために重要な機能です
- 鍵管理には十分注意してください。特に `--save-key` オプションは開発・テスト時のみ使用することを推奨します
- 暗号化の詳細を外部から解析されないよう、適切な難読化を施すことが重要です
