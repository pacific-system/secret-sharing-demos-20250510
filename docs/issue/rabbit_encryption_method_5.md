# ラビット暗号化方式 🐰 実装【子 Issue #5】：復号実装（decrypt.py）

お兄様！いよいよ暗号文を読み解く復号機能を実装しましょう！パシ子がご案内します 🔓✨

## 📋 タスク概要

ラビット暗号化方式の復号プログラム（`decrypt.py`）を実装します。このプログラムは、暗号文ファイルと復号鍵を受け取り、鍵に応じて正規ファイル（true.text）または非正規ファイル（false.text）のいずれかを復元します。

## 🔧 実装内容

`method_6_rabbit/decrypt.py` ファイルに、復号機能を実装します。

### 主要な機能：

1. コマンドライン引数の処理
2. 暗号文ファイルの読み込みとメタデータ解析
3. 入力鍵の処理と種別判定
4. 多重データの解カプセル化
5. 鍵種別に基づいた適切なストリーム選択
6. 復号処理
7. 復号結果の出力

## 💻 実装手順

### 1. 必要なライブラリのインポート

`decrypt.py` の先頭に以下を記述します：

```python
#!/usr/bin/env python3
"""
ラビット暗号化方式 - 復号プログラム

暗号文ファイルと鍵を入力として受け取り、
鍵に応じて適切な平文を復元します。
"""

import os
import sys
import argparse
import binascii
import json
import base64
import hashlib
from typing import Dict, Tuple, Any, Optional, Union

# 内部モジュールのインポート
from .rabbit_stream import RabbitStreamGenerator
from .stream_selector import StreamSelector, determine_key_type_secure
from .config import KEY_SIZE_BYTES, OUTPUT_EXTENSION
```

### 2. ヘルパー関数の実装

```python
def read_encrypted_file(file_path: str) -> Tuple[Dict[str, Any], bytes]:
    """
    暗号化ファイルを読み込み、メタデータと暗号文に分離

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (metadata, ciphertext): メタデータと暗号文

    Raises:
        ValueError: ファイル形式が不正な場合
        FileNotFoundError: ファイルが見つからない場合
    """
    try:
        with open(file_path, 'rb') as f:
            # メタデータ長を読み込み
            meta_length_bytes = f.read(4)
            if len(meta_length_bytes) != 4:
                raise ValueError("ファイル形式が不正です: メタデータ長が読み込めません")

            meta_length = int.from_bytes(meta_length_bytes, byteorder='big')

            # メタデータを読み込み
            meta_json = f.read(meta_length)
            if len(meta_json) != meta_length:
                raise ValueError("ファイル形式が不正です: メタデータが完全に読み込めません")

            try:
                metadata = json.loads(meta_json)
            except json.JSONDecodeError:
                raise ValueError("ファイル形式が不正です: メタデータがJSON形式ではありません")

            # 暗号文を読み込み
            ciphertext = f.read()
            if not ciphertext:
                raise ValueError("ファイル形式が不正です: 暗号文が含まれていません")

            # メタデータのチェックサム検証
            if "checksum" in metadata:
                calculated_checksum = hashlib.sha256(ciphertext).hexdigest()
                if calculated_checksum != metadata["checksum"]:
                    raise ValueError("チェックサムが一致しません: ファイルが破損しているか改ざんされています")

            return metadata, ciphertext

    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。", file=sys.stderr)
        raise
    except Exception as e:
        print(f"エラー: ファイル '{file_path}' の読み込み中に問題が発生しました: {e}", file=sys.stderr)
        raise


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


def get_key_from_file_or_string(key_input: str) -> bytes:
    """
    ファイルパスまたは16進数文字列から鍵を取得

    Args:
        key_input: 鍵のファイルパスまたは16進数文字列

    Returns:
        鍵のバイト列

    Raises:
        ValueError: 鍵の形式が不正な場合
        FileNotFoundError: 鍵ファイルが見つからない場合
    """
    # ファイルとして読み込みを試みる
    if os.path.exists(key_input):
        try:
            with open(key_input, 'rb') as f:
                key_data = f.read()
                if len(key_data) != KEY_SIZE_BYTES:
                    raise ValueError(f"鍵ファイルのサイズが不正です: {len(key_data)}バイト (期待値: {KEY_SIZE_BYTES}バイト)")
                return key_data
        except Exception as e:
            print(f"警告: 鍵ファイルを読み込めませんでした: {e}", file=sys.stderr)
            print("16進数文字列として解釈を試みます...", file=sys.stderr)

    # 16進数文字列として解釈
    try:
        # スペースや改行を削除
        key_str = key_input.replace(" ", "").replace("\n", "").replace("\r", "")
        key_data = binascii.unhexlify(key_str)

        if len(key_data) != KEY_SIZE_BYTES:
            raise ValueError(f"鍵のサイズが不正です: {len(key_data)}バイト (期待値: {KEY_SIZE_BYTES}バイト)")

        return key_data

    except (binascii.Error, ValueError) as e:
        # 16進数として解釈できなかった場合はパスワードとして扱う
        if len(key_input) < 4:
            print("警告: 鍵が短すぎます。セキュリティのためより長い鍵を使用してください。", file=sys.stderr)

        # パスワードをUTF-8でエンコードし、SHA-256でハッシュ化
        key_data = hashlib.sha256(key_input.encode('utf-8')).digest()[:KEY_SIZE_BYTES]
        return key_data
```

### 3. 復号関数の実装

```python
def extract_from_capsule(capsule: bytes, key: Union[str, bytes], metadata: Dict[str, Any]) -> bytes:
    """
    カプセル化されたデータから平文を抽出

    Args:
        capsule: カプセル化されたデータ
        key: 復号鍵
        metadata: メタデータ

    Returns:
        復号されたデータ
    """
    # ソルトを取得
    if "salt" not in metadata:
        raise ValueError("メタデータにソルト情報がありません")

    salt = base64.b64decode(metadata["salt"])

    # 復号用のStreamSelectorを初期化
    selector = StreamSelector(salt)

    # コンテンツ長を取得
    content_length = metadata.get("content_length", len(capsule))

    # 復号用ストリームを取得（鍵種別の判定と適切なストリーム選択が自動的に行われる）
    decrypt_stream = selector.get_stream_for_decryption(key, content_length)

    # まずカプセルを解除（extract_from_capsuleの逆操作）
    decapsulated = reverse_data_capsule(capsule, salt)

    # 最終的な復号データを取得
    decrypted = xor_bytes(decapsulated, decrypt_stream)

    return decrypted


def reverse_data_capsule(capsule: bytes, salt: bytes) -> bytes:
    """
    カプセル化されたデータを元の暗号化データに戻す

    これはcreate_data_capsuleの逆操作を行います。
    鍵の種類に基づいて、正しい復号データを取り出します。

    Args:
        capsule: カプセル化されたデータ
        salt: ソルト値

    Returns:
        元の暗号化データ
    """
    data_length = len(capsule)
    result = bytearray(data_length)

    # 組み合わせ関数（ソルトを使用して特性を変化させる）
    hash_value = hashlib.sha256(salt).digest()

    # カプセル化の逆操作を行う
    for i in range(data_length):
        # 各バイト位置でのミックス方式を決定するインデックス（encrypt.pyと同じロジック）
        mix_index = hash_value[i % len(hash_value)] % 4

        # カプセル化と逆の操作で元に戻す
        if mix_index == 0:
            # 方法1（XOR）の逆操作: 再度同じ値でXORすれば元に戻る
            result[i] = capsule[i] ^ hash_value[(i * 2) % len(hash_value)]
        elif mix_index == 1:
            # 方法2（加算）の逆操作: 逆算して元に戻す
            result[i] = (capsule[i] - hash_value[(i * 3) % len(hash_value)]) % 256
        elif mix_index == 2:
            # 方法3（ビット回転）の逆操作: 逆回転させる
            rotation = hash_value[(i * 5) % len(hash_value)] % 8
            # XORの逆操作を行うための準備
            result[i] = capsule[i]  # 一時的に値を保存
        else:
            # 方法4（減算）の逆操作: 逆算して元に戻す
            result[i] = (capsule[i] - hash_value[(i * 7) % len(hash_value)] + 256) % 256

    return bytes(result)


def decrypt_file(encrypted_file_path: str, key: Union[str, bytes], output_path: Optional[str] = None) -> str:
    """
    暗号化ファイルを復号

    Args:
        encrypted_file_path: 暗号化ファイルのパス
        key: 復号鍵（文字列またはバイト列）
        output_path: 出力ファイルのパス（省略時は自動生成）

    Returns:
        復号されたファイルのパス

    Raises:
        ValueError: 復号に失敗した場合
        FileNotFoundError: ファイルが見つからない場合
    """
    # 暗号化ファイルの読み込み
    metadata, ciphertext = read_encrypted_file(encrypted_file_path)

    # 鍵をバイト列に変換
    if isinstance(key, str):
        key_bytes = get_key_from_file_or_string(key)
    else:
        key_bytes = key

    # カプセルから復号データを抽出
    decrypted_data = extract_from_capsule(ciphertext, key_bytes, metadata)

    # 出力パスが指定されていない場合は生成
    if output_path is None:
        # 鍵種別を判定してファイル名を決定
        salt = base64.b64decode(metadata["salt"])
        key_type = determine_key_type_secure(key_bytes, salt)

        # 入力ファイル名をベースに出力ファイル名を生成
        base_name = os.path.splitext(os.path.basename(encrypted_file_path))[0]
        output_path = f"{base_name}_decrypted_{key_type}.txt"

    # 復号データを出力
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"復号完了: '{output_path}' に復号データを書き込みました。")

    return output_path
```

### 4. メイン関数の実装

```python
def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="ラビット暗号化方式の復号プログラム")

    parser.add_argument(
        "encrypted_file",
        type=str,
        help="復号する暗号化ファイルのパス"
    )

    parser.add_argument(
        "--key",
        "-k",
        type=str,
        required=True,
        help="復号鍵（16進数文字列またはファイルパス）"
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
    if not os.path.exists(args.encrypted_file):
        print(f"エラー: 暗号化ファイル '{args.encrypted_file}' が見つかりません。", file=sys.stderr)
        return 1

    # 出力ディレクトリが存在するか確認（出力パスが指定されている場合）
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
        # 復号の実行
        decrypt_file(args.encrypted_file, args.key, args.output)
        return 0

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

## ✅ 完了条件

- [ ] コマンドライン引数が適切に処理され、ヘルプが表示される
- [ ] 暗号文ファイルからメタデータと暗号文が正しく分離・解析される
- [ ] 様々な形式の鍵入力（16 進数文字列、鍵ファイル、パスワード）が処理される
- [ ] 鍵種別に基づいて適切なストリームが選択される
- [ ] 多重データの解カプセル化処理が正しく実装されている
- [ ] 復号処理が正しく機能し、元のファイル内容が復元される
- [ ] エラー処理が適切に実装されている
- [ ] 出力ファイルが適切に生成される

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# ヘルプの表示
python -m method_6_rabbit.decrypt --help

# 暗号化ファイルの復号（鍵は16進数文字列で指定）
python -m method_6_rabbit.decrypt output.enc --key 0123456789abcdef0123456789abcdef

# 暗号化ファイルの復号（鍵はファイルから読み込み）
python -m method_6_rabbit.decrypt output.enc --key output.key

# 出力ファイルを指定して復号
python -m method_6_rabbit.decrypt output.enc --key output.key --output decrypted.txt

# 暗号化と復号のエンドツーエンドテスト
python -m method_6_rabbit.encrypt --save-key
python -m method_6_rabbit.decrypt output.enc --key output.key
```

## ⏰ 想定実装時間

約 6 時間

## 📚 参考資料

- [Python argparse ライブラリ](https://docs.python.org/ja/3/library/argparse.html)
- [Python バイト列操作](https://docs.python.org/ja/3/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview)
- [Python JSON 処理](https://docs.python.org/ja/3/library/json.html)

## 💬 備考

- `reverse_data_capsule`関数は`encrypt.py`の`create_data_capsule`関数と完全に対応するように実装してください。一方が変更された場合は、もう一方も同じように変更する必要があります。
- 復号処理が常に成功するとは限りません。不正な鍵や破損したファイルに対しては適切なエラーメッセージを表示するようにしてください。
- 暗号文フォーマットの変更に対応できるよう、メタデータの処理を柔軟に行ってください。
- 実際のアプリケーションでは、暗号文の整合性検証に MAC（メッセージ認証コード）などを使用することが推奨されますが、このデモでは単純なチェックサムを使用しています。
