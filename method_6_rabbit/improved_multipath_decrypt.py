#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
改良版ラビット多重経路復号プログラム

正規キー・非正規キーの概念を排除し、
どちらのパスも同等に扱う方式。
復号結果の判定は純粋にユーザーの意図によって決まります。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import binascii
import hmac
import datetime
from typing import Tuple, Dict, Any, List, Optional, Union, Callable

# インポートエラーを回避するための処理
if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        DECRYPT_CHUNK_SIZE,
        ENCRYPTED_FILE_PATH,
        DECRYPTED_FILE_PATH,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
    from method_6_rabbit.improved_decrypt import (
        decrypt_xor,
        read_encrypted_file
    )
    from method_6_rabbit.rabbit_stream import derive_key, RabbitStreamGenerator
else:
    from .config import (
        RABBIT_KEY_SIZE,
        RABBIT_IV_SIZE,
        DECRYPT_CHUNK_SIZE,
        ENCRYPTED_FILE_PATH,
        DECRYPTED_FILE_PATH,
        KEY_DERIVATION_ITERATIONS,
        VERSION
    )
    from .improved_decrypt import (
        decrypt_xor,
        read_encrypted_file
    )
    from .rabbit_stream import derive_key, RabbitStreamGenerator

# 新しいパス定義
PATH_A = "path_a"  # 従来の "true" に相当
PATH_B = "path_b"  # 従来の "false" に相当


class MultipathDecoder:
    """
    複数の復号経路を管理し、最適な結果を選択するクラス
    """

    def __init__(self, encrypted_data: bytes, metadata: Dict[str, Any], password: str,
                 verbose: bool = False, apply_reference: bool = True):
        """
        復号機を初期化

        Args:
            encrypted_data: 暗号化データ
            metadata: メタデータ
            password: 復号パスワード
            verbose: 詳細ログを表示するか
            apply_reference: リファレンスデータを適用するか
        """
        self.encrypted_data = encrypted_data
        self.metadata = metadata
        self.password = password
        self.verbose = verbose
        self.apply_reference = apply_reference

        # メタデータから基本情報を取得
        self.salt = base64.b64decode(metadata["salt"])
        self.data_length = metadata["data_length"]

        # 復号結果の保存用
        self.decrypted_results = {}

    def decrypt_both_paths(self) -> Dict[str, Tuple[bytes, bool]]:
        """
        両方のパスで復号を試みる

        Returns:
            {パス名: (復号データ, 整合性チェック結果)}の辞書
        """
        # パスワードから鍵とIVを導出
        key, iv, _ = derive_key(self.password, self.salt)

        # ストリームジェネレータを作成
        stream_gen = RabbitStreamGenerator(key, iv)
        stream = stream_gen.generate(self.data_length)

        results = {}

        # パスAの復号
        if len(self.encrypted_data) >= self.data_length:
            path_a_encrypted = self.encrypted_data[:self.data_length]
            path_a_decrypted = decrypt_xor(path_a_encrypted, stream)
            path_a_hash = hashlib.sha256(path_a_decrypted).hexdigest()[:8]
            path_a_expected = self.metadata.get("path_a_hash", "")

            results[PATH_A] = (
                path_a_decrypted,
                path_a_hash == path_a_expected
            )

            if self.verbose:
                print(f"パスA: ハッシュ計算値={path_a_hash}, 期待値={path_a_expected}")
                print(f"パスA: 整合性チェック={'成功' if path_a_hash == path_a_expected else '失敗'}")

        # パスBの復号
        if len(self.encrypted_data) >= 2 * self.data_length:
            path_b_encrypted = self.encrypted_data[self.data_length:2 * self.data_length]
            path_b_decrypted = decrypt_xor(path_b_encrypted, stream)
            path_b_hash = hashlib.sha256(path_b_decrypted).hexdigest()[:8]
            path_b_expected = self.metadata.get("path_b_hash", "")

            results[PATH_B] = (
                path_b_decrypted,
                path_b_hash == path_b_expected
            )

            if self.verbose:
                print(f"パスB: ハッシュ計算値={path_b_hash}, 期待値={path_b_expected}")
                print(f"パスB: 整合性チェック={'成功' if path_b_hash == path_b_expected else '失敗'}")

        self.decrypted_results = results
        return results

    def get_best_result(self) -> Tuple[bytes, str]:
        """
        最適な復号結果を選択する

        Returns:
            (復号データ, パス名)
        """
        if not self.decrypted_results:
            self.decrypt_both_paths()

        # 整合性チェックに成功したパスを優先
        valid_paths = {path: data for path, (data, valid) in self.decrypted_results.items() if valid}

        if valid_paths:
            # 整合性チェックに成功したパスが複数ある場合は、パスAを優先
            if PATH_A in valid_paths:
                return valid_paths[PATH_A], PATH_A
            else:
                # 他のパスを返す
                path = next(iter(valid_paths.keys()))
                return valid_paths[path], path

        # どのパスも整合性チェックに失敗した場合、パスAのデータを返す
        if PATH_A in self.decrypted_results:
            return self.decrypted_results[PATH_A][0], f"{PATH_A}_unknown"

        # どのパスも復号できなかった場合
        raise ValueError("有効な復号結果が得られませんでした")


def save_decrypted_file(decrypted_data: bytes, output_path: str, path_type: str) -> str:
    """
    復号したデータをファイルに保存

    Args:
        decrypted_data: 復号データ
        output_path: 出力ファイルパス
        path_type: パス種別

    Returns:
        保存したファイルのパス
    """
    try:
        # 出力ファイル名にタイムスタンプとパスタイプを追加
        base, ext = os.path.splitext(output_path)
        timestamped_output_path = f"{base}_{path_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

        # 出力ディレクトリが存在することを確認
        output_dir = os.path.dirname(timestamped_output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # NULL終端文字があれば取り除く（必要な場合のみ）
        cleaned_data = decrypted_data.rstrip(b'\x00')

        with open(timestamped_output_path, 'wb') as file:
            file.write(cleaned_data)
        print(f"復号データを '{timestamped_output_path}' に保存しました")
        return timestamped_output_path
    except Exception as e:
        print(f"エラー: 復号ファイルの保存に失敗しました: {e}")
        raise


def analyze_content(data: bytes, verbose: bool = False) -> Dict[str, Any]:
    """
    復号されたデータの内容を分析

    Args:
        data: 分析するデータ
        verbose: 詳細情報を表示するか

    Returns:
        分析結果の辞書
    """
    result = {
        "file_size": len(data),
        "encoding": "unknown",
        "is_text": False,
        "text_preview": "",
        "binary_preview": "",
        "content_type": "unknown"
    }

    # 空データチェック
    if not data:
        result["content_type"] = "empty"
        return result

    # バイナリかテキストかの判定
    null_count = data.count(0)
    control_chars = sum(1 for b in data if b < 32 and b not in (9, 10, 13))  # タブ、LF、CRを除く制御文字

    # テキスト判定の基準: NULL文字が少なく、制御文字の割合が低い
    is_likely_text = (null_count < len(data) * 0.01) and (control_chars < len(data) * 0.1)

    if is_likely_text:
        result["is_text"] = True

        # エンコーディング推定
        encodings = ['utf-8', 'shift-jis', 'euc-jp', 'iso-2022-jp', 'utf-16', 'ascii']
        for enc in encodings:
            try:
                text = data.decode(enc, errors='strict')
                result["encoding"] = enc
                result["text_preview"] = text[:100] + ('...' if len(text) > 100 else '')
                result["content_type"] = "text"
                break
            except UnicodeDecodeError:
                continue

        # どのエンコーディングでも解読できない場合はバイナリとして扱う
        if result["encoding"] == "unknown":
            result["is_text"] = False

    # バイナリ判定の場合
    if not result["is_text"]:
        result["content_type"] = "binary"
        result["binary_preview"] = binascii.hexlify(data[:50]).decode('ascii')

    # 詳細ログ表示
    if verbose:
        print("\n=== コンテンツ分析 ===")
        print(f"ファイルサイズ: {result['file_size']} バイト")
        print(f"コンテンツタイプ: {result['content_type']}")
        if result["is_text"]:
            print(f"エンコーディング: {result['encoding']}")
            print(f"テキストプレビュー: {result['text_preview']}")
        else:
            print(f"バイナリプレビュー: {result['binary_preview']}")

    return result


def parse_arguments() -> argparse.Namespace:
    """コマンドライン引数を解析"""
    parser = argparse.ArgumentParser(
        description="改良版Rabbit多重経路復号ツール - どちらのパスも同等に扱う",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-i", "--input",
        default=ENCRYPTED_FILE_PATH,
        help="暗号化ファイルのパス"
    )

    parser.add_argument(
        "-o", "--output",
        default=DECRYPTED_FILE_PATH,
        help="復号ファイルの出力先"
    )

    parser.add_argument(
        "-p", "--password",
        required=True,
        help="復号パスワード"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細なログ出力"
    )

    parser.add_argument(
        "--analyze",
        action="store_true",
        help="復号データの詳細分析を実行"
    )

    parser.add_argument(
        "--force-path-a",
        action="store_true",
        help="強制的にパスAのデータを使用"
    )

    parser.add_argument(
        "--force-path-b",
        action="store_true",
        help="強制的にパスBのデータを使用"
    )

    return parser.parse_args()


def main():
    """メイン関数"""
    # 引数解析
    args = parse_arguments()

    print(f"暗号化ファイル '{args.input}' を読み込んでいます...")
    encrypted_data, metadata = read_encrypted_file(args.input)

    # 多重経路復号を実行
    print("複数の復号経路を試行しています...")
    decoder = MultipathDecoder(
        encrypted_data,
        metadata,
        args.password,
        verbose=args.verbose
    )

    # 復号を実行
    all_results = decoder.decrypt_both_paths()

    # ユーザーが特定のパスを指定した場合はそちらを優先
    if args.force_path_a and PATH_A in all_results:
        decrypted_data, path_type = all_results[PATH_A][0], PATH_A
        print(f"ユーザー指定により強制的にパスAのデータを使用します")
    elif args.force_path_b and PATH_B in all_results:
        decrypted_data, path_type = all_results[PATH_B][0], PATH_B
        print(f"ユーザー指定により強制的にパスBのデータを使用します")
    else:
        # 自動選択
        decrypted_data, path_type = decoder.get_best_result()
        print(f"最適な復号経路として {path_type} を選択しました")

    # データ分析
    if args.analyze or args.verbose:
        analysis = analyze_content(decrypted_data, verbose=args.verbose)

    # 復号データを保存
    if args.output:
        save_decrypted_file(decrypted_data, args.output, path_type)

    print("\n復号が完了しました！")
    print("このプログラムは「正規」「非正規」の区別をしておらず、どちらが重要なデータかはユーザーの意図によって決まります。")
    print("これにより、復号されたファイルが「本物」か「偽物」かを攻撃者が判断することはできません。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n処理が中断されました")
        sys.exit(1)
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        if os.environ.get('DEBUG') == '1':
            import traceback
            traceback.print_exc()
        sys.exit(1)