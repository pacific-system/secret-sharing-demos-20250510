# 暗号学的ハニーポット方式 🍯 実装【子 Issue #4】：暗号化実装（encrypt.py）

お兄様！いよいよ暗号化機能を実装する時がきました！パシ子が優しく解説します 💕

## 📋 タスク概要

暗号学的ハニーポット方式の暗号化プログラム（`encrypt.py`）を実装します。このプログラムは、正規ファイル（true.text）と非正規ファイル（false.text）を入力として受け取り、ハニーポットカプセル化された暗号文を生成します。

## 🔧 実装内容

`method_7_honeypot/encrypt.py` ファイルに、暗号化機能を実装します。

### 主要な機能：

1. コマンドライン引数の処理
2. 入力ファイル（true.text/false.text）の読み込み
3. 暗号化キーの生成と管理
4. ファイル暗号化とハニーポットカプセル化
5. メタデータと暗号化データの結合
6. 暗号文ファイルとキーペアの出力

## 💻 実装手順

### 1. 必要なライブラリのインポート

`encrypt.py` の先頭に以下を記述します：

```python
#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 暗号化プログラム

true.textとfalse.textを入力として、ハニーポットカプセル化された
暗号文を生成します。これにより、同一の暗号文から鍵に応じて
異なる平文を復元できるようになります。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import time
import secrets
import binascii
from typing import Dict, Tuple, Any, Optional, List, Union
from pathlib import Path

# 内部モジュールからのインポート
from .trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, generate_honey_token,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from .config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, SYMMETRIC_KEY_SIZE,
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


def symmetric_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    対称鍵暗号を使用してデータを暗号化

    Args:
        data: 暗号化するデータ
        key: 暗号化キー

    Returns:
        (encrypted_data, iv): 暗号化されたデータと初期化ベクトル
    """
    # 実装の詳細は省略しますが、ここでは暗号ライブラリを使用して
    # AES-GCM または ChaCha20-Poly1305 などの認証付き暗号を使用することを推奨します

    # 簡易的な実装例（本番環境では適切な暗号ライブラリを使用してください）
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    # 初期化ベクトルを生成
    iv = os.urandom(16)

    # AES-CTRモードで暗号化
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # 認証タグを計算（本番環境では認証付き暗号を使用してください）
    auth_tag = hashlib.sha256(key + iv + ciphertext).digest()[:16]

    # 暗号文と認証タグを結合
    return ciphertext + auth_tag, iv
```

### 3. ハニーポットカプセル化関数の実装

```python
def create_honeypot_capsule(true_data: bytes, false_data: bytes, trapdoor_params: Dict[str, Any]) -> bytes:
    """
    真偽2つのデータからハニーポットカプセルを作成

    このカプセルは、鍵に応じて異なるデータを復元できる特殊な構造を持ちます。

    Args:
        true_data: 正規データ（暗号化済み）
        false_data: 非正規データ（暗号化済み）
        trapdoor_params: トラップドア関数のパラメータ

    Returns:
        ハニーポットカプセル
    """
    # 正規・非正規のハニートークンを生成
    true_token = generate_honey_token(KEY_TYPE_TRUE, trapdoor_params)
    false_token = generate_honey_token(KEY_TYPE_FALSE, trapdoor_params)

    # カプセルバージョン識別子
    version_marker = b"HPOT01"

    # サイズ情報を記録
    true_size = len(true_data)
    false_size = len(false_data)

    # サイズ情報をバイナリに変換
    size_info = true_size.to_bytes(4, byteorder='big') + false_size.to_bytes(4, byteorder='big')

    # データをシャッフルするためのシード
    shuffle_seed = os.urandom(16)

    # ハニーポットカプセルのヘッダー
    header = version_marker + shuffle_seed + size_info

    # トークンとデータを結合
    # 注: 実際の実装ではよりセキュアな方法でデータを組み合わることが望ましい
    combined_data = true_token + false_token + true_data + false_data

    # ヘッダーとデータを結合
    capsule = header + combined_data

    # カプセル全体のチェックサム
    checksum = hashlib.sha256(capsule).digest()

    # 最終的なカプセル
    return capsule + checksum
```

### 4. 暗号化関数の実装

```python
def encrypt_files(true_file_path: str, false_file_path: str, output_path: str) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    """
    true.textとfalse.textを暗号化し、ハニーポットカプセルを生成

    Args:
        true_file_path: 正規ファイルのパス
        false_file_path: 非正規ファイルのパス
        output_path: 出力ファイルのパス

    Returns:
        (keys, metadata): 鍵ペアとメタデータ
    """
    # ファイル読み込み
    true_data = read_file(true_file_path)
    false_data = read_file(false_file_path)

    # マスター鍵の生成
    master_key = create_master_key()

    # トラップドアパラメータの生成
    trapdoor_params = create_trapdoor_parameters(master_key)

    # 鍵ペアの導出
    keys, salt = derive_keys_from_trapdoor(trapdoor_params)

    # データの対称暗号化
    true_encrypted, true_iv = symmetric_encrypt(true_data, keys[KEY_TYPE_TRUE])
    false_encrypted, false_iv = symmetric_encrypt(false_data, keys[KEY_TYPE_FALSE])

    # ハニーポットカプセルの作成
    capsule = create_honeypot_capsule(true_encrypted, false_encrypted, trapdoor_params)

    # メタデータの作成
    timestamp = int(time.time())
    metadata = {
        "format": OUTPUT_FORMAT,
        "version": "1.0",
        "algorithm": "honeypot",
        "salt": base64.b64encode(salt).decode('ascii'),
        "true_iv": base64.b64encode(true_iv).decode('ascii'),
        "false_iv": base64.b64encode(false_iv).decode('ascii'),
        "timestamp": timestamp,
        "content_length": len(capsule),
        "checksum": hashlib.sha256(capsule).hexdigest()
    }

    # 出力ファイルの作成
    with open(output_path, 'wb') as f:
        # メタデータをJSONとして書き込み
        meta_json = json.dumps(metadata).encode('utf-8')
        f.write(len(meta_json).to_bytes(4, byteorder='big'))  # メタデータ長を記録
        f.write(meta_json)

        # カプセルを書き込み
        f.write(capsule)

    print(f"暗号化完了: '{output_path}' に暗号文を書き込みました。")

    # 鍵情報を返却
    key_info = {
        KEY_TYPE_TRUE: keys[KEY_TYPE_TRUE],
        KEY_TYPE_FALSE: keys[KEY_TYPE_FALSE],
        "master_key": master_key
    }

    return key_info, metadata
```

### 5. 鍵保存関数の実装

```python
def save_keys(key_info: Dict[str, bytes], output_dir: str, base_name: str) -> Dict[str, str]:
    """
    鍵情報をファイルに保存

    Args:
        key_info: 鍵情報辞書
        output_dir: 出力ディレクトリ
        base_name: ベースファイル名

    Returns:
        保存した鍵ファイルのパス辞書
    """
    # 出力ディレクトリを作成（存在しない場合）
    os.makedirs(output_dir, exist_ok=True)

    key_files = {}

    # 各鍵タイプについて
    for key_type, key in key_info.items():
        # 鍵ファイル名を構築
        filename = f"{base_name}.{key_type}.key"
        file_path = os.path.join(output_dir, filename)

        # 鍵を保存
        with open(file_path, 'wb') as f:
            f.write(key)

        key_files[key_type] = file_path
        print(f"{key_type}鍵を保存しました: {file_path}")

    return key_files
```

### 6. メイン関数の実装

```python
def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="暗号学的ハニーポット方式の暗号化プログラム")

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
        "--output", "-o",
        type=str,
        default=f"output{OUTPUT_EXTENSION}",
        help=f"出力ファイルのパス（デフォルト: output{OUTPUT_EXTENSION}）"
    )

    parser.add_argument(
        "--save-keys",
        action="store_true",
        help="鍵をファイルに保存する"
    )

    parser.add_argument(
        "--keys-dir",
        type=str,
        default="keys",
        help="鍵を保存するディレクトリ（デフォルト: keys）"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在を確認
    for file_path in [args.true_file, args.false_file]:
        if not os.path.exists(file_path):
            print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
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
        key_info, metadata = encrypt_files(args.true_file, args.false_file, args.output)

        # 鍵の保存（オプション）
        if args.save_keys:
            base_name = Path(args.output).stem
            save_keys(key_info, args.keys_dir, base_name)
        else:
            # 鍵を表示
            for key_type, key in key_info.items():
                if key_type != "master_key":  # マスター鍵は表示しない
                    print(f"{key_type}鍵: {binascii.hexlify(key).decode()}")

        return 0

    except Exception as e:
        print(f"エラー: 暗号化中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 7. シェバンとファイル権限の設定

`encrypt.py` ファイルに実行権限を与えます：

```bash
chmod +x method_7_honeypot/encrypt.py
```

## ✅ 完了条件

- [ ] コマンドライン引数が適切に処理され、ヘルプが表示される
- [ ] 入力ファイル（true.text/false.text）が正しく読み込まれる
- [ ] トラップドア関数を使用した鍵ペアの生成が実装されている
- [ ] 対称暗号を使用したファイル暗号化が実装されている
- [ ] ハニーポットカプセル化が実装されている
- [ ] メタデータと暗号文を含む出力ファイルが正しく作成される
- [ ] 鍵の保存機能が実装されている
- [ ] エラー処理が適切に実装されている

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# ヘルプの表示
python -m method_7_honeypot.encrypt --help

# デフォルト設定での暗号化
python -m method_7_honeypot.encrypt

# カスタムファイル指定での暗号化
python -m method_7_honeypot.encrypt --true-file path/to/true.text --false-file path/to/false.text --output custom_output.hpot

# 鍵ファイルの保存
python -m method_7_honeypot.encrypt --save-keys --keys-dir custom_keys_dir
```

## ⏰ 想定実装時間

約 5 時間

## 📚 参考資料

- [Python argparse ライブラリ](https://docs.python.org/ja/3/library/argparse.html)
- [cryptography ライブラリのドキュメント](https://cryptography.io/en/latest/)
- [AES-GCM 認証付き暗号の解説](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [暗号ファイル形式の設計](https://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html)

## 💬 備考

- ハニーポットカプセル化は、システムの核心部分です。実際の実装ではよりセキュアな方法でデータを結合することをお勧めします。
- 実装の簡素化のため、ここでは AES-CTR モードを使用していますが、本番環境では AES-GCM や ChaCha20-Poly1305 などの認証付き暗号を使用してください。
- 認証付き暗号を使用することで、完全性と真正性を確保できます。
- マスター鍵と鍵ペアの管理に注意してください。本番環境では鍵管理システムの使用を検討してください。
- メタデータには必要な情報のみを含め、機密情報は含めないでください。

疑問点や提案があればコメントしてくださいね！パシ子とレオくんが全力でサポートします！💕
