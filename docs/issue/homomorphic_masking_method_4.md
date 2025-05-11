# 準同型暗号マスキング方式 🎭 実装【子 Issue #4】：暗号化実装（encrypt.py）

お兄様！準同型暗号マスキング方式の暗号化機能を実装していきましょう！これで魔法のような変換ができるようになりますよ〜✨

## 📋 タスク概要

準同型暗号マスキング方式の暗号化プログラム（`encrypt.py`）を実装します。このプログラムは、正規ファイル（true.text）と非正規ファイル（false.text）を暗号化し、マスク関数を適用した単一の暗号文ファイルを生成します。生成された暗号文は、使用する鍵によって異なる平文（true/false）に復号できるようになります。

## 🔧 実装内容

`method_8_homomorphic/encrypt.py` ファイルに、暗号化機能を実装します。ここでは、前タスクで実装した準同型暗号とマスク関数を組み合わせて使用します。

### 主要な機能：

1. コマンドライン引数の処理
2. 入力ファイル（true.text/false.text）の読み込み
3. 準同型暗号の初期化と鍵生成
4. 準同型暗号化と適切なマスクの適用
5. 区別不可能な暗号文の生成
6. 暗号文ファイルへの出力

## 💻 実装手順

### 1. 必要なライブラリのインポート

`encrypt.py` の先頭に以下を記述します：

```python
#!/usr/bin/env python3
"""
準同型暗号マスキング方式 - 暗号化プログラム

true.textとfalse.textを入力として受け取り、
準同型暗号を使用して暗号化し、マスク関数を適用した
単一の暗号文ファイルを生成します。
"""

import os
import sys
import argparse
import json
import hashlib
import base64
import time
import secrets
from typing import Tuple, Dict, List, Any, Optional, Union

# 内部モジュールのインポート
from .homomorphic import PaillierCryptosystem, encrypt_bytes, serialize_encrypted_data
from .crypto_mask import MaskFunctionGenerator, transform_between_true_false, create_indistinguishable_form
from .config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BITS,
    OUTPUT_FORMAT, OUTPUT_EXTENSION
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
        32バイトのランダムなマスター鍵
    """
    return secrets.token_bytes(32)


def derive_homomorphic_keys(master_key: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    マスター鍵から準同型暗号用の鍵ペアを導出

    Args:
        master_key: マスター鍵

    Returns:
        (public_key, private_key): 公開鍵と秘密鍵
    """
    # マスター鍵からシード値を生成
    seed = hashlib.sha256(master_key).digest()

    # PaillierCryptosystemのインスタンスを作成
    paillier = PaillierCryptosystem(KEY_SIZE_BITS)

    # 鍵ペアを生成（通常はランダムだが、マスター鍵から導出するため固定的）
    # 注: この実装はデモ用の簡略化されたものです
    import random
    random.seed(int.from_bytes(seed, 'big'))

    # 鍵ペアを生成
    public_key, private_key = paillier.generate_keypair()

    return public_key, private_key
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

    # データ長の確認（統計的解析防止のため同じ長さにする）
    max_length = max(len(true_data), len(false_data))

    # データが短い方をパディング
    if len(true_data) < max_length:
        # ランダムなパディングを追加（ゼロパディングよりも安全）
        true_data = true_data + secrets.token_bytes(max_length - len(true_data))

    if len(false_data) < max_length:
        false_data = false_data + secrets.token_bytes(max_length - len(false_data))

    # マスター鍵の生成
    master_key = generate_master_key()

    # 準同型暗号鍵の導出
    public_key, private_key = derive_homomorphic_keys(master_key)

    # 準同型暗号システムの初期化
    paillier = PaillierCryptosystem(KEY_SIZE_BITS)
    paillier.load_keypair(public_key, private_key)

    # マスク関数生成器の初期化
    mask_generator = MaskFunctionGenerator(paillier)
    true_mask, false_mask = mask_generator.generate_mask_pair()

    # チャンクサイズを計算（Paillier暗号の制約に基づく）
    n_bits = public_key["n"].bit_length()
    chunk_size = (n_bits - 128) // 8  # 安全マージンを考慮
    chunk_size = max(16, min(chunk_size, 256))  # 16〜256バイトの範囲に制限

    # ファイルを暗号化
    print(f"正規ファイルを暗号化しています...")
    true_encrypted = encrypt_bytes(paillier, true_data, chunk_size)

    print(f"非正規ファイルを暗号化しています...")
    false_encrypted = encrypt_bytes(paillier, false_data, chunk_size)

    # 変換処理（マスク適用）
    print("マスク関数を適用しています...")
    masked_true, masked_false = transform_between_true_false(
        paillier, true_encrypted, false_encrypted, mask_generator
    )

    # 区別不可能な形式に変換
    crypto_data = create_indistinguishable_form(
        masked_true, masked_false, true_mask, false_mask,
        {
            "original_size": max_length,
            "chunk_size": chunk_size,
            "timestamp": int(time.time())
        }
    )

    # 公開鍵情報を追加（復号時に必要）
    crypto_data["public_key"] = {
        "n": str(public_key["n"]),
        "g": str(public_key["g"])
    }

    # 出力ファイルの作成
    with open(output_path, 'w') as f:
        json.dump(crypto_data, f, indent=2)

    print(f"暗号化完了: '{output_path}' に暗号文を書き込みました。")
    print(f"マスター鍵: {base64.b64encode(master_key).decode('ascii')}")

    # メタデータ
    metadata = {
        "format": OUTPUT_FORMAT,
        "version": "1.0",
        "algorithm": "homomorphic_masked",
        "timestamp": crypto_data["timestamp"],
        "original_size": max_length,
        "chunk_size": chunk_size
    }

    return master_key, metadata


def save_key_file(key: bytes, output_path: str) -> None:
    """
    鍵をファイルに保存

    Args:
        key: 保存する鍵
        output_path: 出力ファイルパス
    """
    with open(output_path, 'wb') as f:
        f.write(key)

    print(f"鍵を保存しました: {output_path}")
```

### 4. メイン関数の実装

```python
def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(
        description="準同型暗号マスキング方式の暗号化プログラム"
    )

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
        "--save-key",
        action="store_true",
        help="生成された鍵をファイルに保存する"
    )

    parser.add_argument(
        "--key-size",
        type=int,
        default=KEY_SIZE_BITS,
        help=f"鍵サイズ（ビット）（デフォルト: {KEY_SIZE_BITS}）"
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
        print(f"準同型暗号マスキング方式で暗号化を開始します...")
        start_time = time.time()

        key, _ = encrypt_files(args.true_file, args.false_file, args.output)

        elapsed_time = time.time() - start_time
        print(f"暗号化が完了しました（所要時間: {elapsed_time:.2f}秒）")

        # 鍵の保存（オプション）
        if args.save_key:
            key_file = f"{os.path.splitext(args.output)[0]}.key"
            save_key_file(key, key_file)

        return 0

    except Exception as e:
        print(f"エラー: 暗号化中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 5. マルチプロセス対応の追加（オプション）

大きなファイルを効率的に処理するために、マルチプロセス対応を追加します：

```python
def encrypt_files_with_multiprocessing(true_file_path: str, false_file_path: str, output_path: str,
                                      num_processes: int = None) -> Tuple[bytes, Dict[str, Any]]:
    """
    マルチプロセスを使用してファイルを暗号化（大きなファイル用）

    Args:
        true_file_path: 正規ファイルのパス
        false_file_path: 非正規ファイルのパス
        output_path: 出力暗号文ファイルのパス
        num_processes: 使用するプロセス数（Noneの場合はCPUコア数）

    Returns:
        (master_key, metadata): マスター鍵とメタデータ
    """
    # マルチプロセス処理の実装
    # 注: 実際の実装では、ファイルを分割して並列処理します
    # このサンプルでは簡略化のため、通常の暗号化に委譲します

    return encrypt_files(true_file_path, false_file_path, output_path)
```

## ✅ 完了条件

- [ ] コマンドライン引数が適切に処理され、ヘルプが表示される
- [ ] 正規ファイル（true.text）と非正規ファイル（false.text）が正しく読み込まれる
- [ ] マスター鍵が安全に生成される
- [ ] 準同型暗号化とマスク適用が正しく実装されている
- [ ] 区別不可能な暗号文形式への変換が実装されている
- [ ] 暗号文ファイルが適切な形式で出力される
- [ ] エラー処理が適切に実装されている
- [ ] 鍵をファイルに保存するオプションが機能する
- [ ] 処理時間が表示される

## 🧪 テスト方法

以下のコマンドでテストを実行してください：

```bash
# ヘルプの表示
python -m method_8_homomorphic.encrypt --help

# デフォルト設定での暗号化
python -m method_8_homomorphic.encrypt

# カスタムファイル指定での暗号化
python -m method_8_homomorphic.encrypt --true-file path/to/true.text --false-file path/to/false.text --output custom_output.henc

# 鍵ファイルの保存
python -m method_8_homomorphic.encrypt --save-key
```

## ⏰ 想定実装時間

約 5 時間

## 📚 参考資料

- [Python argparse ライブラリ](https://docs.python.org/ja/3/library/argparse.html)
- [JSON 処理とシリアライゼーション](https://docs.python.org/ja/3/library/json.html)
- [秘密鍵の安全な管理](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

## 💬 備考

- 準同型暗号の処理は計算負荷が高いため、処理に時間がかかる場合があります
- 鍵サイズが大きいほど安全性が高まりますが、処理時間も増加します
- デモ用のため簡略化されたパラメータを使用していますが、実運用ではより強固なパラメータが必要です
- ファイルサイズに応じて適切なチャンクサイズを調整することが重要です
- マスター鍵から鍵ペアを導出する方法は、実際のアプリケーションでは更に検討が必要です

疑問点や提案があればコメントしてくださいね！パシ子とレオくんがお答えします！💕
