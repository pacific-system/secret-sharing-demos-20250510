# 暗号学的ハニーポット方式 🍯 実装【子 Issue #5】：復号実装（decrypt.py）

お兄様！いよいよ復号機能を実装する時がきました！パシ子が優しく解説します 💕 レオくんもワクワクしていますよ〜！

## 📋 タスク概要

暗号学的ハニーポット方式の復号プログラム（`decrypt.py`）を実装します。このプログラムは、ハニーポットカプセル化された暗号文と鍵を受け取り、鍵の種類に応じて異なる平文（true.text/false.text）を復元します。

## 🔧 実装内容

`method_7_honeypot/decrypt.py` ファイルに、復号機能を実装します。

### 主要な機能：

1. コマンドライン引数の処理
2. 暗号文ファイルの読み込みとパース
3. 鍵検証と処理経路の選択
4. ハニーポットカプセルの分解
5. 復号処理の実行
6. 復号結果の出力

## 💻 実装手順

### 1. 必要なライブラリのインポート

`decrypt.py` の先頭に以下を記述します：

```python
#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 復号プログラム

ハニーポットカプセル化された暗号文と鍵を入力として受け取り、
鍵の種類に応じて適切な平文を復元します。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import time
import binascii
from typing import Dict, Tuple, Any, Optional, List, Union, BinaryIO
from pathlib import Path

# 内部モジュールからのインポート
from .trapdoor import (
    evaluate_key_type, derive_user_key_material,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from .key_verification import (
    verify_key_and_select_path
)
from .config import (
    SYMMETRIC_KEY_SIZE, OUTPUT_EXTENSION
)
```

### 2. ヘルパー関数の実装

```python
def read_encrypted_file(file_path: str) -> Tuple[Dict[str, Any], bytes]:
    """
    暗号化されたファイルを読み込み、メタデータとカプセルを抽出

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (metadata, capsule): メタデータとカプセルのタプル

    Raises:
        ValueError: ファイル形式が不正な場合
        FileNotFoundError: ファイルが存在しない場合
    """
    try:
        with open(file_path, 'rb') as f:
            # メタデータ長を読み込み
            meta_len_bytes = f.read(4)
            if len(meta_len_bytes) != 4:
                raise ValueError("ファイル形式が不正です: メタデータ長の読み込みに失敗しました")

            meta_len = int.from_bytes(meta_len_bytes, byteorder='big')

            # メタデータを読み込み
            meta_json = f.read(meta_len)
            if len(meta_json) != meta_len:
                raise ValueError("ファイル形式が不正です: メタデータの読み込みに失敗しました")

            metadata = json.loads(meta_json.decode('utf-8'))

            # カプセルを読み込み
            capsule = f.read()

            # チェックサムを検証
            expected_checksum = metadata.get("checksum")
            if expected_checksum:
                actual_checksum = hashlib.sha256(capsule).hexdigest()
                if expected_checksum != actual_checksum:
                    raise ValueError("ファイルが破損しています: チェックサムが一致しません")

            return metadata, capsule

    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise
    except json.JSONDecodeError:
        raise ValueError("ファイル形式が不正です: メタデータの解析に失敗しました")


def extract_honeypot_capsule(capsule: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    ハニーポットカプセルを分解し、内部データを取得

    Args:
        capsule: ハニーポットカプセル

    Returns:
        (true_token, false_token, true_data, false_data): 各種データのタプル

    Raises:
        ValueError: カプセル形式が不正な場合
    """
    # バージョンマーカーを検証
    if not capsule.startswith(b"HPOT01"):
        raise ValueError("カプセル形式が不正です: 不明なバージョンマーカー")

    # ヘッダーデータを解析
    header_size = 6 + 16 + 8  # バージョン(6) + シードデータ(16) + サイズ情報(8)
    header = capsule[:header_size]

    # チェックサムを分離
    checksum = capsule[-32:]
    payload = capsule[header_size:-32]

    # サイズ情報を取得
    true_size = int.from_bytes(header[6+16:6+16+4], byteorder='big')
    false_size = int.from_bytes(header[6+16+4:6+16+8], byteorder='big')

    # トークンサイズは固定（32バイト）
    token_size = 32

    # データを分離
    true_token = payload[:token_size]
    false_token = payload[token_size:token_size*2]
    true_data = payload[token_size*2:token_size*2+true_size]
    false_data = payload[token_size*2+true_size:]

    # サイズ検証
    if len(true_data) != true_size or len(false_data) != false_size:
        raise ValueError("カプセル形式が不正です: データサイズが一致しません")

    return true_token, false_token, true_data, false_data


def symmetric_decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    対称鍵暗号を使用してデータを復号

    Args:
        encrypted_data: 暗号化されたデータ
        key: 復号キー
        iv: 初期化ベクトル

    Returns:
        復号されたデータ

    Raises:
        ValueError: 復号に失敗した場合
    """
    # 暗号文と認証タグを分離（認証タグは最後の16バイト）
    ciphertext = encrypted_data[:-16]
    auth_tag = encrypted_data[-16:]

    # 認証タグを検証
    expected_tag = hashlib.sha256(key + iv + ciphertext).digest()[:16]
    if auth_tag != expected_tag:
        raise ValueError("データの整合性検証に失敗しました")

    # 実装の詳細は省略しますが、ここでは暗号ライブラリを使用して
    # AES-CTRモードでの復号を行います
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    # AES-CTRモードで復号
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
```

### 3. 復号機能の実装

```python
def decrypt_file(encrypted_file_path: str, key: bytes, output_path: Optional[str] = None) -> Tuple[str, bytes]:
    """
    暗号化ファイルを復号

    この関数は、鍵の種類（正規/非正規）に基づいて適切な処理経路を選択し、
    対応する平文を復元します。

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        key: 復号キー
        output_path: 出力ファイルのパス（省略時は標準出力）

    Returns:
        (key_type, plaintext): 鍵タイプと復号された平文のタプル

    Raises:
        ValueError: 復号に失敗した場合
    """
    # 暗号化ファイルを読み込み
    metadata, capsule = read_encrypted_file(encrypted_file_path)

    # Base64でエンコードされたソルトを復元
    salt = base64.b64decode(metadata["salt"])

    # 鍵検証と処理経路の選択
    # 注: この部分は攻撃者からの解析に対する耐性の核心部分
    try:
        # 暗号文から抽出された情報を用いてトラップドアパラメータを復元
        # 実装の詳細は省略していますが、実際にはトラップドアパラメータの
        # 安全な復元処理が必要になります

        # 簡略化のため、ここでは鍵検証だけを行います
        from .trapdoor import create_trapdoor_parameters

        # ダミーパラメータ生成（実際の実装では暗号文から復元する）
        dummy_master_key = hashlib.sha256(capsule[:32] + salt).digest()
        trapdoor_params = create_trapdoor_parameters(dummy_master_key)

        # 鍵検証と処理経路の選択
        key_type, context = verify_key_and_select_path(key, trapdoor_params, salt)

        # ハニーポットカプセルを分解
        true_token, false_token, true_data, false_data = extract_honeypot_capsule(capsule)

        # 経路に基づいて適切なデータを選択
        if context['path'] == 'authentic':
            encrypted_data = true_data
            iv = base64.b64decode(metadata["true_iv"])
        else:
            encrypted_data = false_data
            iv = base64.b64decode(metadata["false_iv"])

        # 選択したデータを復号
        plaintext = symmetric_decrypt(encrypted_data, key, iv)

        # 結果を出力
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            print(f"復号完了: '{output_path}' に平文を書き込みました。")

        return key_type, plaintext

    except Exception as e:
        # 例外をキャッチして情報を限定
        # 攻撃者に有用な情報を与えないため、エラーメッセージは一般化する
        raise ValueError("復号に失敗しました。鍵が正しいか確認してください。")
```

### 4. 鍵読み込み関数の実装

```python
def load_key(key_path: str) -> bytes:
    """
    鍵ファイルから鍵を読み込む

    Args:
        key_path: 鍵ファイルのパス

    Returns:
        鍵データ

    Raises:
        FileNotFoundError: 鍵ファイルが存在しない場合
    """
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
            if len(key_data) != SYMMETRIC_KEY_SIZE:
                print(f"警告: 鍵のサイズが期待値と異なります: {len(key_data)} != {SYMMETRIC_KEY_SIZE}", file=sys.stderr)
            return key_data
    except FileNotFoundError:
        print(f"エラー: 鍵ファイル '{key_path}' が見つかりません。", file=sys.stderr)
        raise


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    パスワードから鍵を導出

    Args:
        password: パスワード文字列
        salt: ソルト

    Returns:
        導出された鍵
    """
    key_material, _ = derive_user_key_material(password, salt)
    return key_material
```

### 5. メイン関数の実装

```python
def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="暗号学的ハニーポット方式の復号プログラム")

    # 入力ファイル
    parser.add_argument(
        "input_file",
        type=str,
        help="復号する暗号化ファイルのパス"
    )

    # 鍵の指定（排他的引数グループ）
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--key", "-k",
        type=str,
        help="復号に使用する鍵ファイルのパス"
    )
    key_group.add_argument(
        "--password", "-p",
        type=str,
        help="復号に使用するパスワード"
    )
    key_group.add_argument(
        "--key-hex",
        type=str,
        help="復号に使用する鍵の16進数表現"
    )

    # 出力ファイル
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="復号結果を書き込むファイルのパス（省略時は標準出力）"
    )

    # 鍵タイプの出力フラグ
    parser.add_argument(
        "--show-key-type",
        action="store_true",
        help="使用した鍵の種類（正規/非正規）を表示する"
    )

    return parser.parse_args()


def main():
    """
    メイン関数
    """
    args = parse_arguments()

    # 入力ファイルの存在を確認
    if not os.path.exists(args.input_file):
        print(f"エラー: ファイル '{args.input_file}' が見つかりません。", file=sys.stderr)
        return 1

    try:
        # 鍵の取得
        key = None
        if args.key:
            # 鍵ファイルから鍵を読み込み
            key = load_key(args.key)
        elif args.password:
            # パスワードから鍵を導出するためにメタデータを一部読み込む
            with open(args.input_file, 'rb') as f:
                meta_len = int.from_bytes(f.read(4), byteorder='big')
                meta_json = f.read(meta_len).decode('utf-8')
                metadata = json.loads(meta_json)
                salt = base64.b64decode(metadata["salt"])

            # パスワードから鍵を導出
            key = derive_key_from_password(args.password, salt)
        elif args.key_hex:
            # 16進数から鍵を復元
            try:
                key = binascii.unhexlify(args.key_hex)
                if len(key) != SYMMETRIC_KEY_SIZE:
                    print(f"エラー: 鍵の長さが不正です: {len(key)} != {SYMMETRIC_KEY_SIZE}", file=sys.stderr)
                    return 1
            except binascii.Error:
                print("エラー: 不正な16進数形式です。", file=sys.stderr)
                return 1

        # 復号の実行
        key_type, plaintext = decrypt_file(args.input_file, key, args.output)

        # 鍵タイプの表示（オプション）
        if args.show_key_type:
            key_type_display = "正規" if key_type == KEY_TYPE_TRUE else "非正規"
            print(f"鍵タイプ: {key_type_display} ({key_type})")

        # 出力パスが指定されていない場合は標準出力に表示
        if not args.output:
            try:
                # テキストとして表示（UTF-8でデコード可能な場合）
                print(plaintext.decode('utf-8'))
            except UnicodeDecodeError:
                # バイナリデータの場合は16進数で表示
                print(f"バイナリデータ: {binascii.hexlify(plaintext[:64]).decode()}...")
                print(f"合計 {len(plaintext)} バイト")

        return 0

    except ValueError as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"エラー: 復号中に予期しない問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 6. シェバンとファイル権限の設定

`decrypt.py` ファイルに実行権限を与えます：

```bash
chmod +x method_7_honeypot/decrypt.py
```

## ✅ 完了条件

- [ ] コマンドライン引数が適切に処理され、ヘルプが表示される
- [ ] 暗号化ファイルを読み込み、メタデータとカプセルを分離できる
- [ ] ハニーポットカプセルから鍵の種類に応じた適切なデータを抽出できる
- [ ] 鍵検証に基づいて処理経路を選択できる
- [ ] データを正しく復号し、結果を出力できる
- [ ] 鍵ファイル、パスワード、16 進数のいずれかから鍵を取得できる
- [ ] エラー処理が適切に実装されている

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# ヘルプの表示
python -m method_7_honeypot.decrypt --help

# 鍵ファイルを使用した復号
python -m method_7_honeypot.decrypt output.hpot --key keys/output.true.key

# パスワードを使用した復号
python -m method_7_honeypot.decrypt output.hpot --password "secret_password"

# 16進数鍵を使用した復号
python -m method_7_honeypot.decrypt output.hpot --key-hex "deadbeef..."

# 出力ファイルを指定した復号
python -m method_7_honeypot.decrypt output.hpot --key keys/output.true.key --output decrypted.txt

# 鍵タイプの表示
python -m method_7_honeypot.decrypt output.hpot --key keys/output.true.key --show-key-type
```

## ⏰ 想定実装時間

約 5 時間

## 📚 参考資料

- [Python argparse ライブラリ](https://docs.python.org/ja/3/library/argparse.html)
- [cryptography ライブラリのドキュメント](https://cryptography.io/en/latest/)
- [AES の復号処理](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)
- [バイナリデータの処理](https://docs.python.org/ja/3/library/struct.html)
- [API セキュリティのベストプラクティス](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## 💬 備考

- 復号処理は、ハニーポット方式の核心部分です。攻撃者に処理経路の選択が判別されないよう注意してください。
- エラーメッセージは一般化し、攻撃者に有用な情報を与えないようにしています。
- `verify_key_and_select_path` 関数と `extract_honeypot_capsule` 関数は、システムのセキュリティに直結する重要な部分です。
- 実際の実装では、AES-GCM や ChaCha20-Poly1305 などの認証付き暗号を使用することをお勧めします。
- 認証検証に失敗した場合は、セキュリティのために残りの処理を中止し、エラーを返すべきです。

疑問点や提案があればコメントしてくださいね！パシ子とレオくんが全力でサポートします！💕
