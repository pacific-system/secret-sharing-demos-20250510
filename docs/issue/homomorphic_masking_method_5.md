# 準同型暗号マスキング方式 🎭 実装【子 Issue #5】：復号実装（decrypt.py）

お兄様！準同型暗号マスキング方式の復号機能を実装しましょう！鍵に応じて異なる結果が出るという面白い仕組みですよ～ ✨

## 📋 タスク概要

準同型暗号マスキング方式の復号プログラム（`decrypt.py`）を実装します。このプログラムは、暗号化されたファイルを受け取り、与えられた鍵に応じて正規ファイル（true.text）または非正規ファイル（false.text）に復号します。ユーザーが使用する鍵によって、同じ暗号文から異なる平文を取り出すことができます。

## 🔧 実装内容

`method_8_homomorphic/decrypt.py` ファイルに、復号機能を実装します。ここでは、前タスクで実装した準同型暗号とマスク関数を組み合わせて使用します。

### 主要な機能：

1. コマンドライン引数の処理
2. 暗号文ファイルの読み込み
3. 鍵の種別判定（正規/非正規）
4. 適切なマスク関数の選択と適用
5. 準同型復号
6. 平文ファイルへの出力

## 💻 実装手順

### 1. 必要なライブラリのインポート

`decrypt.py` の先頭に以下を記述します：

```python
#!/usr/bin/env python3
"""
準同型暗号マスキング方式 - 復号プログラム

暗号化されたファイルと鍵を受け取り、
鍵に応じて正規または非正規のファイルに復号します。
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
from .homomorphic import PaillierCryptosystem, decrypt_bytes, deserialize_encrypted_data
from .crypto_mask import MaskFunctionGenerator, extract_by_key_type
from .key_analyzer import analyze_key_type
from .config import OUTPUT_EXTENSION
```

### 2. 鍵とパラメータの処理関数

```python
def derive_homomorphic_keys(master_key: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    マスター鍵から準同型暗号用の鍵ペアを導出

    暗号化時と同じ方法で鍵を導出する必要があります。

    Args:
        master_key: マスター鍵

    Returns:
        (public_key, private_key): 公開鍵と秘密鍵
    """
    # マスター鍵からシード値を生成
    seed = hashlib.sha256(master_key).digest()

    # 暗号化と同じロジックを使用して鍵を再現
    import random
    random.seed(int.from_bytes(seed, 'big'))

    # PaillierCryptosystemのインスタンスを作成
    paillier = PaillierCryptosystem()

    # 鍵ペアを生成（暗号化時と同じシードを使用するため同じ鍵が生成される）
    public_key, private_key = paillier.generate_keypair()

    return public_key, private_key


def parse_key(key_input: str) -> bytes:
    """
    さまざまな形式の鍵入力を解析してバイト列に変換

    Base64形式、16進数形式、生のバイナリファイル形式に対応。

    Args:
        key_input: 鍵（文字列またはファイルパス）

    Returns:
        鍵のバイト列

    Raises:
        ValueError: 鍵の形式が不正な場合
    """
    # ファイルからの読み込み
    if os.path.exists(key_input):
        try:
            with open(key_input, 'rb') as f:
                return f.read()
        except:
            pass

    # Base64形式
    try:
        return base64.b64decode(key_input)
    except:
        pass

    # 16進数形式
    try:
        if key_input.startswith('0x'):
            key_input = key_input[2:]
        return bytes.fromhex(key_input)
    except:
        pass

    # その他の形式
    try:
        # パスワードとして使用し、ハッシュ化して鍵に変換
        return hashlib.sha256(key_input.encode()).digest()
    except:
        raise ValueError("サポートされていない鍵形式です")
```

### 3. 復号関数の実装

```python
def decrypt_file(encrypted_file_path: str, key: bytes, output_path: str, key_type: Optional[str] = None) -> bool:
    """
    暗号化されたファイルを復号

    Args:
        encrypted_file_path: 暗号化されたファイルのパス
        key: 復号鍵
        output_path: 出力先ファイルパス
        key_type: 鍵の種類（明示的に指定する場合）。"true"または"false"

    Returns:
        復号成功の場合はTrue、失敗の場合はFalse
    """
    try:
        # 暗号化ファイルの読み込み
        with open(encrypted_file_path, 'r') as f:
            encrypted_data = json.load(f)

        # フォーマットチェック
        if encrypted_data.get("format") != "homomorphic_masked":
            print("エラー: サポートされていない暗号化形式です", file=sys.stderr)
            return False

        # 公開鍵情報を取得
        public_key_str = encrypted_data.get("public_key", {})
        if not public_key_str:
            print("エラー: 公開鍵情報が見つかりません", file=sys.stderr)
            return False

        # 公開鍵を整数に変換
        public_key = {
            "n": int(public_key_str["n"]),
            "g": int(public_key_str["g"])
        }

        # 暗号化パラメータを取得
        original_size = encrypted_data.get("original_size", 0)
        chunk_size = encrypted_data.get("chunk_size", 128)

        # 鍵の解析と種別判定
        if key_type is None:
            # 鍵解析モジュールを使用して鍵の種類を判定
            key_type = analyze_key_type(key)
            print(f"鍵を解析しました: {key_type}鍵として識別されました")
        else:
            print(f"明示的に指定された鍵タイプを使用: {key_type}")

        # 暗号文と対応するマスク情報を抽出
        chunks, mask_info = extract_by_key_type(encrypted_data, key_type)

        # 準同型暗号システムの初期化
        paillier = PaillierCryptosystem()

        # 鍵の導出と設定
        _, private_key = derive_homomorphic_keys(key)
        paillier.load_keypair(public_key, private_key)

        # マスク生成器の初期化と適用
        seed = base64.b64decode(mask_info["seed"])
        mask_generator = MaskFunctionGenerator(paillier, seed)
        true_mask, false_mask = mask_generator.generate_mask_pair()

        # 鍵タイプに応じたマスクを選択
        if key_type == "true":
            mask = true_mask
        else:
            mask = false_mask

        # マスクの除去
        print("マスク関数を除去中...")
        unmasked_chunks = mask_generator.remove_mask(chunks, mask)

        # 復号
        print("復号中...")
        decrypted_data = decrypt_bytes(paillier, unmasked_chunks, original_size, chunk_size)

        # 出力ファイルへの書き込み
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        print(f"復号が完了しました: '{output_path}'")
        return True

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False
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
        description="準同型暗号マスキング方式の復号プログラム"
    )

    parser.add_argument(
        "encrypted_file",
        type=str,
        help="復号する暗号化ファイルのパス"
    )

    parser.add_argument(
        "--key",
        type=str,
        required=True,
        help="復号鍵（Base64形式、16進数形式、またはファイルパス）"
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        help="出力ファイルのパス（省略時は自動生成）"
    )

    parser.add_argument(
        "--key-type",
        choices=["true", "false"],
        help="鍵の種類を明示的に指定（通常は自動判定）"
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

    # 鍵の解析
    try:
        key = parse_key(args.key)
    except ValueError as e:
        print(f"エラー: 鍵の解析に失敗しました: {e}", file=sys.stderr)
        return 1

    # 出力ファイル名の決定
    if args.output:
        output_path = args.output
    else:
        # 入力ファイル名から自動生成
        base_name = os.path.splitext(os.path.basename(args.encrypted_file))[0]
        output_path = f"{base_name}_decrypted.txt"

    # 出力ディレクトリが存在するか確認
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"ディレクトリを作成しました: {output_dir}")
        except OSError as e:
            print(f"エラー: 出力ディレクトリを作成できません: {e}", file=sys.stderr)
            return 1

    # 復号の実行
    print(f"準同型暗号マスキング方式で復号を開始します...")
    start_time = time.time()

    success = decrypt_file(args.encrypted_file, key, output_path, args.key_type)

    elapsed_time = time.time() - start_time

    if success:
        print(f"復号が完了しました（所要時間: {elapsed_time:.2f}秒）")
        return 0
    else:
        print(f"復号に失敗しました（所要時間: {elapsed_time:.2f}秒）", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 5. エラー耐性の強化と進捗表示

```python
def decrypt_file_with_progress(encrypted_file_path: str, key: bytes, output_path: str,
                              key_type: Optional[str] = None,
                              show_progress: bool = True) -> bool:
    """
    進捗表示付きで暗号化されたファイルを復号

    大きなファイルの復号時に進捗を表示します。

    Args:
        encrypted_file_path: 暗号化されたファイルのパス
        key: 復号鍵
        output_path: 出力先ファイルパス
        key_type: 鍵の種類（明示的に指定する場合）。"true"または"false"
        show_progress: 進捗表示を行うかどうか

    Returns:
        復号成功の場合はTrue、失敗の場合はFalse
    """
    try:
        # 暗号化ファイルの読み込み
        with open(encrypted_file_path, 'r') as f:
            encrypted_data = json.load(f)

        # 以下、decrypt_fileと同様の処理...
        # フォーマットチェック、鍵解析、準同型復号を行う

        # 暗号文と対応するマスク情報を抽出
        chunks, mask_info = extract_by_key_type(encrypted_data, key_type)

        # 進捗表示をサポート
        if show_progress:
            total_chunks = len(chunks)
            print(f"合計 {total_chunks} チャンクを処理します")

            # 進捗表示関数
            def show_chunk_progress(current, total):
                percent = (current / total) * 100
                sys.stdout.write(f"\r進捗: {percent:.1f}% ({current}/{total} チャンク)")
                sys.stdout.flush()
                if current == total:
                    sys.stdout.write("\n")

        # マスク除去と復号
        # (処理中に進捗表示を行う)

        return True

    except Exception as e:
        print(f"エラー: 復号中に問題が発生しました: {e}", file=sys.stderr)
        # エラー情報の詳細を表示
        import traceback
        traceback.print_exc()

        # リカバリー処理（部分的に復号できたデータを保存）
        try:
            if 'decrypted_data' in locals() and decrypted_data:
                recovery_path = f"{output_path}.partial"
                with open(recovery_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"部分的な復号結果を保存しました: {recovery_path}", file=sys.stderr)
        except:
            pass

        return False
```

## ✅ 完了条件

- [ ] コマンドライン引数が適切に処理され、ヘルプが表示される
- [ ] 暗号文ファイルが正しく読み込まれる
- [ ] 鍵解析機能が正しく実装されている
- [ ] 鍵の種類に応じて適切なマスク関数が選択される
- [ ] マスク関数の除去と準同型復号が正しく実装されている
- [ ] 復号されたデータが適切に出力ファイルに書き込まれる
- [ ] エラー処理が適切に実装されている
- [ ] 進捗表示機能が実装されている
- [ ] 処理時間が表示される

## 🧪 テスト方法

以下のコマンドでテストを実行してください。まず、暗号化を行ってから復号をテストします：

```bash
# 1. 暗号化を実行して鍵を取得
python -m method_8_homomorphic.encrypt --save-key

# 2. ヘルプの表示
python -m method_8_homomorphic.decrypt --help

# 3. Base64形式の鍵で復号
python -m method_8_homomorphic.decrypt output.henc --key "YOUR_BASE64_KEY"

# 4. 鍵ファイルを使用して復号
python -m method_8_homomorphic.decrypt output.henc --key output.key

# 5. 明示的に鍵タイプを指定して復号
python -m method_8_homomorphic.decrypt output.henc --key "YOUR_KEY" --key-type true
```

## ⏰ 想定実装時間

約 6 時間

## 📚 参考資料

- [Python argparse ライブラリ](https://docs.python.org/ja/3/library/argparse.html)
- [JSON 処理とシリアライゼーション](https://docs.python.org/ja/3/library/json.html)
- [秘密鍵の安全な管理](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

## 💬 備考

- 準同型暗号の処理は計算負荷が高いため、復号にも時間がかかる場合があります
- マスク関数の除去は暗号文のまま行われる特殊な処理であり、正確な実装が必要です
- 鍵の種別判定は、暗号学的な安全性を考慮して実装する必要があります
- エラー処理と進捗表示は、特に大きなファイルを処理する場合に重要です
- 実際のアプリケーションでは、より堅牢な鍵管理と認証メカニズムが必要になります

疑問点や提案があれば、いつでも連絡してくださいね〜！レオくんも一緒にお手伝いします！✨
