# ラビット暗号化方式 🐰 実装【子 Issue #4】：暗号化実装（encrypt.py）

お兄様！いよいよ暗号化機能を実装する時がきました！パシ子が詳しく説明しますね 💕

## 📋 タスク概要

ラビット暗号化方式の暗号化プログラム（`encrypt.py`）を実装します。このプログラムは、正規ファイル（true.text）と非正規ファイル（false.text）を同時に暗号化し、単一の暗号文ファイルを生成します。生成された暗号文は、使用する鍵によって異なる平文（true/false）に復号できるようになります。

## 🔧 実装内容

`method_6_rabbit/encrypt.py` ファイルに、暗号化機能を実装します。

### 主要な機能：

1. コマンドライン引数の処理
2. 入力ファイル（true.text/false.text）の読み込み
3. マスター鍵の生成と管理
4. 多重ストリームを使用した暗号化処理
5. メタデータと暗号化データの結合
6. 暗号文ファイルの出力

## 💻 実装手順

### 1. 必要なライブラリのインポート

`encrypt.py` の先頭に以下を記述します：

```python
#!/usr/bin/env python3
"""
ラビット暗号化方式 - 暗号化プログラム

true.textとfalse.textを入力として受け取り、
単一の暗号文ファイルを生成します。
"""

import os
import sys
import argparse
import binascii
import json
import base64
import time
from typing import Dict, Tuple, Any, Optional
import hashlib

# 内部モジュールのインポート
from .rabbit_stream import RabbitStreamGenerator
from .stream_selector import StreamSelector
from .config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
    SALT_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION
)
```

### 2. ヘルパー関数の実装

```python
def read_file(file_path: str) -> bytes:
    """
    ファイルをバイナリデータとして読み込む

    Args:
        file_path: 読み込むファイルのパス

    Returns:
        ファイルの内容（バイト列）

    Raises:
        FileNotFoundError: ファイルが存在しない場合
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise


def generate_master_key() -> bytes:
    """
    暗号化用のマスター鍵を生成

    Returns:
        16バイトのランダムなマスター鍵
    """
    return os.urandom(KEY_SIZE_BYTES)


def xor_bytes(data: bytes, stream: bytes) -> bytes:
    """
    データとストリームのXOR演算を行う

    Args:
        data: 暗号化/復号するデータ
        stream: XORするストリーム

    Returns:
        XOR演算の結果
    """
    if len(data) != len(stream):
        raise ValueError("データとストリームの長さが一致しません")

    # バイト単位のXOR演算
    return bytes(a ^ b for a, b in zip(data, stream))
```

### 3. 暗号化関数の実装

```python
def encrypt_files(true_file_path: str, false_file_path: str, output_path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    true.textとfalse.textを暗号化し、単一の暗号文ファイルを生成

    Args:
        true_file_path: 正規ファイルのパス
        false_file_path: 非正規ファイルのパス
        output_path: 出力暗号文ファイルのパス

    Returns:
        (master_key, metadata): マスター鍵とメタデータ
    """
    # ファイル読み込み
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

    # StreamSelectorの初期化
    selector = StreamSelector()
    salt = selector.get_salt()

    # 両方のパス用のストリームを生成
    streams = selector.get_streams_for_both_paths(master_key, max_length)

    # データの暗号化
    true_encrypted = xor_bytes(true_data, streams["true"])
    false_encrypted = xor_bytes(false_data, streams["false"])

    # 多重データのカプセル化
    # 注: これは両方のデータを数学的に組み合わせる重要なステップです
    capsule = create_data_capsule(true_encrypted, false_encrypted, salt)

    # メタデータの作成
    metadata = {
        "format": OUTPUT_FORMAT,
        "version": "1.0",
        "algorithm": "rabbit",
        "salt": base64.b64encode(salt).decode('ascii'),
        "timestamp": int(time.time()),
        "content_length": max_length,
        "checksum": hashlib.sha256(capsule).hexdigest()
    }

    # 出力ファイルの作成
    with open(output_path, 'wb') as f:
        # メタデータをJSONとして書き込み
        meta_json = json.dumps(metadata).encode('utf-8')
        f.write(len(meta_json).to_bytes(4, byteorder='big'))  # メタデータ長を記録
        f.write(meta_json)

        # 暗号化データを書き込み
        f.write(capsule)

    print(f"暗号化完了: '{output_path}' に暗号文を書き込みました。")
    print(f"鍵: {binascii.hexlify(master_key).decode('ascii')}")

    return master_key, metadata


def create_data_capsule(true_encrypted: bytes, false_encrypted: bytes, salt: bytes) -> bytes:
    """
    2つの暗号化データを組み合わせて単一のカプセルを作成

    これはラビット暗号化方式の核心部分であり、同一の暗号文から
    異なる平文を復元できる仕組みを数学的に実現します。

    Args:
        true_encrypted: 真のストリームで暗号化されたデータ
        false_encrypted: 偽のストリームで暗号化されたデータ
        salt: ソルト値

    Returns:
        カプセル化されたデータ
    """
    if len(true_encrypted) != len(false_encrypted):
        raise ValueError("2つの暗号化データの長さが一致しません")

    data_length = len(true_encrypted)

    # ここが鍵となる部分: 2つの暗号文を特殊な方法で結合
    # 注意: これは秘密の組み合わせ方法であり、第三者が解析しても
    # どちらが本物か判別できないようにする必要があります

    result = bytearray(data_length)

    # 組み合わせ関数（ソルトを使用して特性を変化させる）
    hash_value = hashlib.sha256(salt).digest()

    for i in range(data_length):
        # 各バイト位置でのミックス方式を決定するインデックス
        mix_index = hash_value[i % len(hash_value)] % 4

        # 複数の異なる混合方法を使用
        if mix_index == 0:
            # 方法1: 排他的論理和（XOR）ベースの混合
            result[i] = true_encrypted[i] ^ false_encrypted[i] ^ hash_value[(i * 2) % len(hash_value)]
        elif mix_index == 1:
            # 方法2: 加算ベースの混合（モジュロ演算）
            result[i] = (true_encrypted[i] + false_encrypted[i] + hash_value[(i * 3) % len(hash_value)]) % 256
        elif mix_index == 2:
            # 方法3: ビット回転ベースの混合
            rotation = hash_value[(i * 5) % len(hash_value)] % 8
            t_rotated = ((true_encrypted[i] << rotation) | (true_encrypted[i] >> (8 - rotation))) & 0xFF
            result[i] = t_rotated ^ false_encrypted[i]
        else:
            # 方法4: 差分ベースの混合
            result[i] = (true_encrypted[i] - false_encrypted[i] + 256 + hash_value[(i * 7) % len(hash_value)]) % 256

    return bytes(result)
```

### 4. メイン関数の実装

```python
def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="ラビット暗号化方式の暗号化プログラム")

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
        key, _ = encrypt_files(args.true_file, args.false_file, args.output)

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

- [ ] コマンドライン引数が適切に処理され、ヘルプが表示される
- [ ] 正規ファイル（true.text）と非正規ファイル（false.text）が正しく読み込まれる
- [ ] マスター鍵が安全に生成される
- [ ] 多重ストリームを使用した暗号化処理が実装されている
- [ ] 多重データカプセル化機能が実装されている
- [ ] メタデータと暗号化データが適切に結合される
- [ ] 暗号文ファイルが適切な形式で出力される
- [ ] エラー処理が適切に実装されている

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# ヘルプの表示
python -m method_6_rabbit.encrypt --help

# デフォルト設定での暗号化
python -m method_6_rabbit.encrypt

# カスタムファイル指定での暗号化
python -m method_6_rabbit.encrypt --true-file path/to/true.text --false-file path/to/false.text --output custom_output.enc

# 鍵ファイルの保存
python -m method_6_rabbit.encrypt --save-key
```

## ⏰ 想定実装時間

約 6 時間

## 📚 参考資料

- [Python argparse ライブラリ](https://docs.python.org/ja/3/library/argparse.html)
- [Python バイト列操作](https://docs.python.org/ja/3/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview)
- [暗号化ファイル形式の設計](https://www.ietf.org/rfc/rfc5652.txt)

## 💬 備考

- 多重データカプセル化（`create_data_capsule`関数）は、システムの安全性にとって極めて重要な部分です。この実装が解析されても、真偽の判別ができないように注意深く設計してください。
- 出力ファイル形式はメタデータと暗号化データを含む標準的な形式にしてください。メタデータには必要な情報だけを含め、余計な情報は含めないでください。
- 鍵管理は重要です。`--save-key`オプションは開発時のテスト用であり、実運用では注意して使用してください。
- エラー処理は丁寧に行い、ユーザーに分かりやすいメッセージを表示するようにしてください。
