#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - メインプログラム

暗号化と復号の両方を統合的に実行するためのインターフェース

注意: このファイルには example.py の機能が統合されています。
example.py は今後のメンテナンスで削除される予定のため、
このファイル (main.py) の使用を推奨します。
"""

import os
import sys
import datetime
import argparse
import time
import binascii
import hashlib
from typing import Tuple, Optional, Dict, Any

# モジュールのインポート
try:
    # スクリプトとして直接実行された場合
    from encrypt import encrypt
    from decrypt import decrypt
except ImportError:
    # モジュールとしてインポートされた場合
    try:
        from .encrypt import encrypt
        from .decrypt import decrypt
    except ImportError:
        print("エラー: encrypt.py または decrypt.py のインポートに失敗しました。")
        sys.exit(1)

# 共通設定
OUTPUT_DIR = "test_output"
DEFAULT_KEY = b"P4SSH4=S3cR3tK3Y"  # テスト用デフォルト鍵


def test_encrypt_decrypt(true_file: str, false_file: str, verbose: bool = False) -> Dict[str, Any]:
    """
    暗号化と復号のテストを実行

    Args:
        true_file: 正規テキストファイルのパス
        false_file: 非正規テキストファイルのパス
        verbose: 詳細な出力を表示するかどうか

    Returns:
        テスト結果を含む辞書
    """
    # 結果を格納する辞書を初期化
    results = {}

    # 出力ディレクトリの作成
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    # タイムスタンプを生成
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"indeterministic_test_{timestamp}.indet")

    try:
        print(f"[1] 暗号化テスト: {true_file} + {false_file} -> {output_file}")

        # 暗号化と時間計測
        start_time = time.time()
        key, _ = encrypt(true_file, false_file, output_file)
        encryption_time = time.time() - start_time
        results["encryption_time"] = encryption_time

        # 入力ファイルの読み取り（比較用）
        with open(true_file, 'rb') as f:
            true_content = f.read()
            results["original_true_size"] = len(true_content)
        with open(false_file, 'rb') as f:
            false_content = f.read()
            results["original_false_size"] = len(false_content)

        # 暗号化ファイルサイズ
        results["encrypted_size"] = os.path.getsize(output_file)
        results["expansion_ratio"] = results["encrypted_size"] / (results["original_true_size"] + results["original_false_size"])

        # 正規鍵での復号と時間計測
        true_output = os.path.join(OUTPUT_DIR, f"true_decrypted_{timestamp}.txt")
        print(f"[2] 正規鍵での復号テスト: {output_file} -> {true_output}")

        start_time = time.time()
        decrypt(output_file, key, true_output)
        true_decryption_time = time.time() - start_time
        results["true_decryption_time"] = true_decryption_time

        # 復号結果の確認
        with open(true_output, 'rb') as f:
            true_decrypted = f.read()
            if verbose:
                print(f"正規復号結果: {true_decrypted.decode('utf-8', errors='replace')[:100]}...")

        # 非正規鍵の生成（元の鍵を少し変更）
        false_key = bytearray(key)
        false_key[0] ^= 0xFF  # 最初のバイトを反転
        false_key = bytes(false_key)

        # 非正規鍵での復号と時間計測
        false_output = os.path.join(OUTPUT_DIR, f"false_decrypted_{timestamp}.txt")
        print(f"[3] 非正規鍵での復号テスト: {output_file} -> {false_output}")

        start_time = time.time()
        decrypt(output_file, false_key, false_output)
        false_decryption_time = time.time() - start_time
        results["false_decryption_time"] = false_decryption_time

        # 復号結果の確認
        with open(false_output, 'rb') as f:
            false_decrypted = f.read()
            if verbose:
                print(f"非正規復号結果: {false_decrypted.decode('utf-8', errors='replace')[:100]}...")

        # 結果の検証
        true_match = true_content in true_decrypted
        false_match = false_content in false_decrypted

        # コンタミネーション検査を追加
        no_contamination = true_content not in false_decrypted and false_content not in true_decrypted

        results["true_match"] = true_match
        results["false_match"] = false_match
        results["no_contamination"] = no_contamination
        results["true_key"] = key.hex()
        results["false_key"] = false_key.hex()

        # サマリー表示
        display_summary(results, verbose)

        return results

    except Exception as e:
        print(f"テスト中にエラーが発生しました: {e}", file=sys.stderr)
        if verbose:
            import traceback
            traceback.print_exc()
        return {"error": str(e), "success": False}


def display_summary(results: Dict[str, Any], verbose: bool = False):
    """
    テスト結果のサマリーを表示

    Args:
        results: テスト結果の辞書
        verbose: 詳細情報を表示するかどうか
    """
    print("\n=== テスト結果サマリー ===")
    print(f"暗号化時間: {results.get('encryption_time', 0):.2f}秒")
    print(f"正規復号時間: {results.get('true_decryption_time', 0):.2f}秒")
    print(f"非正規復号時間: {results.get('false_decryption_time', 0):.2f}秒")

    if verbose:
        print(f"\n暗号化ファイルサイズ: {results.get('encrypted_size', 0)} バイト")
        print(f"オリジナル正規ファイルサイズ: {results.get('original_true_size', 0)} バイト")
        print(f"オリジナル非正規ファイルサイズ: {results.get('original_false_size', 0)} バイト")
        print(f"サイズ拡大率: {results.get('expansion_ratio', 0):.2f}倍")

    # 成功/失敗の表示
    print(f"\n正規鍵での復号: {'成功' if results.get('true_match', False) else '失敗'}")
    print(f"非正規鍵での復号: {'成功' if results.get('false_match', False) else '失敗'}")
    print(f"テキスト間のコンタミネーションなし: {'はい' if results.get('no_contamination', False) else 'いいえ'}")

    all_tests_passed = (results.get('true_match', False) and
                        results.get('false_match', False) and
                        results.get('no_contamination', False))
    print(f"\n全てのテストに合格: {'はい' if all_tests_passed else 'いいえ'}")


def main() -> int:
    """
    メイン関数

    Returns:
        終了コード
    """
    # コマンドライン引数の解析
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式")

    # サブコマンドの設定
    subparsers = parser.add_subparsers(dest='command', help='サブコマンド')

    # encrypt コマンド
    encrypt_parser = subparsers.add_parser('encrypt', help='暗号化')
    encrypt_parser.add_argument('true_file', help='正規テキストファイルのパス')
    encrypt_parser.add_argument('false_file', help='非正規テキストファイルのパス')
    encrypt_parser.add_argument('output', help='出力ファイルのパス')
    encrypt_parser.add_argument('--save-key', '-s', action='store_true', help='鍵をファイルに保存')
    encrypt_parser.add_argument('--verbose', '-v', action='store_true', help='詳細な出力を表示')

    # decrypt コマンド
    decrypt_parser = subparsers.add_parser('decrypt', help='復号')
    decrypt_parser.add_argument('encrypted_file', help='暗号化ファイルのパス')
    decrypt_parser.add_argument('key', help='復号鍵（16進数）')
    decrypt_parser.add_argument('output_file', help='出力ファイルのパス')
    decrypt_parser.add_argument('--verbose', '-v', action='store_true', help='詳細な出力を表示')

    # test コマンド
    test_parser = subparsers.add_parser('test', help='暗号化・復号のテスト')
    test_parser.add_argument('--true-file', default="common/true-false-text/true.text", help='正規テキストファイルのパス')
    test_parser.add_argument('--false-file', default="common/true-false-text/false.text", help='非正規テキストファイルのパス')
    test_parser.add_argument('--verbose', '-v', action='store_true', help='詳細な出力を表示')

    args = parser.parse_args()

    # コマンドが指定されていない場合はヘルプを表示
    if not args.command:
        parser.print_help()
        return 1

    # コマンドに応じた処理
    if args.command == 'encrypt':
        try:
            start_time = time.time() if args.verbose else None
            key, output_path = encrypt(args.true_file, args.false_file, args.output, args.save_key)

            if args.verbose and start_time:
                elapsed = time.time() - start_time
                print(f"暗号化処理時間: {elapsed:.2f}秒")
                print(f"暗号化ファイルサイズ: {os.path.getsize(output_path)} バイト")

            print(f"暗号化が完了しました: {output_path}")
            print(f"鍵: {key.hex()}")
            return 0
        except Exception as e:
            print(f"暗号化エラー: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    elif args.command == 'decrypt':
        try:
            # 16進数文字列から鍵をバイト列に変換
            try:
                key = bytes.fromhex(args.key)
            except ValueError:
                print("エラー: 鍵は有効な16進数文字列である必要があります", file=sys.stderr)
                return 1

            start_time = time.time() if args.verbose else None
            success = decrypt(args.encrypted_file, key, args.output_file)

            if args.verbose and start_time:
                elapsed = time.time() - start_time
                print(f"復号処理時間: {elapsed:.2f}秒")
                if os.path.exists(args.output_file):
                    print(f"復号ファイルサイズ: {os.path.getsize(args.output_file)} バイト")
                    # 復号結果の一部を表示
                    try:
                        with open(args.output_file, 'rb') as f:
                            content = f.read(100)  # 最初の100バイトを読み込み
                            print(f"復号結果の一部: {content.decode('utf-8', errors='replace')}")
                    except Exception as read_error:
                        print(f"復号ファイルの読み取りエラー: {read_error}", file=sys.stderr)

            if success:
                print(f"復号が完了しました: {args.output_file}")
                return 0
            else:
                print("復号に失敗しました", file=sys.stderr)
                return 1
        except Exception as e:
            print(f"復号エラー: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    elif args.command == 'test':
        print("------ 不確定性転写暗号化方式のテスト ------\n")

        # テストケースの実行
        results = test_encrypt_decrypt(args.true_file, args.false_file, args.verbose)

        success = (results.get('true_match', False) and
                  results.get('false_match', False) and
                  results.get('no_contamination', False))

        if success:
            print("\nテストは正常に完了しました！")
            return 0
        else:
            print("\nテストは失敗しました。", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())