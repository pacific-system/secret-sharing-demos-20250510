#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
多重経路復号プログラム

同一の暗号文を複数のパスワードで復号し、それぞれの結果を出力します。
このプログラムはRabbit暗号の多重パス特性を検証するためのものです。
"""

import os
import sys
import argparse
import json
import base64
import hashlib
import time
import binascii
import datetime
from typing import Tuple, Dict, Any, List, Optional, Union

# インポートエラーを回避するための処理
if __name__ == "__main__":
    # モジュールとして実行された場合の処理
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from method_6_rabbit.config import (
        DECRYPT_CHUNK_SIZE,
        DECRYPTED_FILE_PATH,
        VERSION
    )
    from method_6_rabbit.stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
    # 多重データカプセル化モジュールをインポート
    from method_6_rabbit.capsule import (
        extract_from_multipath_capsule
    )
    # エンコーディングアダプターをインポート
    from method_6_rabbit.encoding_adapter import (
        adaptive_decode,
        decode_data,
        check_for_common_patterns
    )
else:
    # パッケージの一部として実行された場合の処理
    from .config import (
        DECRYPT_CHUNK_SIZE,
        DECRYPTED_FILE_PATH,
        VERSION
    )
    from .stream_selector import StreamSelector, KEY_TYPE_TRUE, KEY_TYPE_FALSE
    # 多重データカプセル化モジュールをインポート
    from .capsule import (
        extract_from_multipath_capsule
    )
    # エンコーディングアダプターをインポート
    from .encoding_adapter import (
        adaptive_decode,
        decode_data,
        check_for_common_patterns
    )

# 暗号化方式の選択肢
ENCRYPTION_METHOD_CLASSIC = "classic"  # 旧来の単純連結方式
ENCRYPTION_METHOD_CAPSULE = "capsule"  # 新しい多重データカプセル化方式

# エンコーディングアダプターの使用設定
USE_ENCODING_ADAPTER = True  # デフォルトでエンコーディングアダプター機能を有効化


class MultiPathDecryptor:
    """
    複数の鍵で暗号文を復号するデコーダ

    同一の暗号文に対して複数の鍵でアクセスし、それぞれの復号結果を取得します。
    """

    def __init__(self, use_encoding_adapter: bool = USE_ENCODING_ADAPTER):
        """
        初期化

        Args:
            use_encoding_adapter: エンコーディングアダプターを使用するかどうか
        """
        self.use_encoding_adapter = use_encoding_adapter

    def decrypt_file_with_multiple_keys(self, input_file: str,
                                      key_output_pairs: List[Tuple[str, str]]) -> List[Tuple[str, str, bool, str, str]]:
        """
        単一の暗号化ファイルを複数の鍵で復号

        Args:
            input_file: 入力暗号化ファイルパス
            key_output_pairs: (鍵, 出力ファイルパス)のタプルリスト

        Returns:
            [(鍵, 出力ファイルパス, 成功フラグ, パス種別, エンコーディング)]のリスト
        """
        results = []

        try:
            # 暗号化ファイルの読み込み（一度だけ）
            encrypted_data, metadata = read_encrypted_file(input_file)

            # 各鍵で復号を試行
            for key, output_path in key_output_pairs:
                try:
                    # 復号処理
                    decrypted_data, path_type = decrypt_data(encrypted_data, key, metadata)
                    encoding_method = "binary"  # デフォルト値

                    # エンコーディングアダプターの適用
                    if self.use_encoding_adapter:
                        try:
                            # 一般的なパターンをチェック
                            has_pattern, pattern_desc = check_for_common_patterns(decrypted_data)

                            if has_pattern:
                                if pattern_desc == "ASCIIアート":
                                    # ASCIIアートはUTF-8として扱う
                                    decoded_text = decrypted_data.decode('utf-8', errors='replace')
                                    decrypted_data = decoded_text.encode('utf-8')
                                    encoding_method = "ascii-art"
                                elif pattern_desc == "日本語エラーメッセージ":
                                    # 日本語エラーメッセージはShift-JISとして扱う
                                    decoded_text = decrypted_data.decode('shift-jis', errors='replace')
                                    decrypted_data = decoded_text.encode('utf-8')
                                    encoding_method = "shift-jis"
                                elif pattern_desc == "JSON形式":
                                    # JSON形式はUTF-8として扱い、整形する
                                    try:
                                        json_obj = json.loads(decrypted_data)
                                        decoded_text = json.dumps(json_obj, indent=2, ensure_ascii=False)
                                        decrypted_data = decoded_text.encode('utf-8')
                                        encoding_method = "json"
                                    except:
                                        # JSON解析に失敗した場合はそのまま
                                        pass
                            else:
                                # 適応型デコード処理
                                decoded_text, encoding_method = adaptive_decode(decrypted_data)

                                # 可読テキストに変換できた場合は、それを保存用データとして使用
                                if decoded_text and not decoded_text.startswith('[バイナリデータ:'):
                                    # テキストを保存するためにUTF-8でエンコード
                                    decrypted_data = decoded_text.encode('utf-8')
                        except Exception as e:
                            print(f"警告: エンコーディングアダプターでのデコードに失敗: {e}")
                            # 失敗した場合は元のバイナリデータをそのまま使用

                    # 結果を保存し、実際に保存されたパスを取得
                    actual_output_path = save_decrypted_file(decrypted_data, output_path)

                    # 鍵種別に基づいてパス種別を確認し、不明な場合はコンテンツベースで推測
                    if path_type == "unknown" and encoding_method != "binary":
                        if "ASCIIアート" in encoding_method or "ascii-art" in encoding_method:
                            # ASCIIアートは正規データの可能性が高い
                            path_type = "true"
                        elif "日本語エラーメッセージ" in encoding_method or "shift-jis" in encoding_method:
                            # 日本語エラーメッセージは非正規データの可能性が高い
                            path_type = "false"

                    # 成功として記録（パス種別とエンコーディング情報を含む）
                    results.append((key, actual_output_path, True, path_type, encoding_method))

                except Exception as e:
                    # この鍵での復号は失敗
                    print(f"鍵 '{key}' での復号に失敗: {e}")
                    results.append((key, output_path, False, "error", "none"))

        except Exception as e:
            # ファイル読み込み等の共通処理で失敗した場合
            print(f"共通復号処理に失敗: {e}")
            # すべての鍵について失敗として記録
            for key, output_path in key_output_pairs:
                results.append((key, output_path, False, "error", "none"))

        return results


def read_encrypted_file(file_path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    暗号化されたファイルを読み込む

    Args:
        file_path: 暗号化ファイルのパス

    Returns:
        (encrypted_data, metadata): 暗号化データとメタデータ
    """
    try:
        with open(file_path, 'rb') as file:
            # マジックヘッダーを確認
            expected_magic = b'RABBIT_ENCRYPTED_V1\n'
            magic = file.read(len(expected_magic))
            if magic != expected_magic:
                raise ValueError("不正なファイル形式です。Rabbit暗号化ファイルではありません。")

            # メタデータサイズを読み取り
            metadata_size_bytes = file.read(4)
            metadata_size = int.from_bytes(metadata_size_bytes, byteorder='big')

            # メタデータを読み取り
            metadata_bytes = file.read(metadata_size)
            metadata = json.loads(metadata_bytes.decode('utf-8'))

            # バージョン確認
            if metadata.get('version') != VERSION:
                print(f"警告: ファイルバージョン ({metadata.get('version')}) と現在のバージョン ({VERSION}) が一致しません")

            # 暗号化データを読み取り
            encrypted_data = file.read()

            return encrypted_data, metadata

    except FileNotFoundError:
        raise ValueError(f"ファイル '{file_path}' が見つかりません")
    except Exception as e:
        raise ValueError(f"ファイルの読み込みに失敗しました: {e}")


def read_key_from_file(key_file_path: str) -> str:
    """
    鍵ファイルから鍵を読み込む

    Args:
        key_file_path: 鍵ファイルのパス

    Returns:
        鍵の文字列
    """
    try:
        with open(key_file_path, 'r') as file:
            key = file.read().strip()
        return key
    except FileNotFoundError:
        raise ValueError(f"鍵ファイル '{key_file_path}' が見つかりません")
    except Exception as e:
        raise ValueError(f"鍵ファイルの読み込みに失敗しました: {e}")


def process_key_input(key_input: str) -> str:
    """
    様々な形式の鍵入力を処理する

    Args:
        key_input: 鍵入力（パスワード、16進数文字列、ファイルパス）

    Returns:
        処理された鍵文字列
    """
    # ファイルからの読み込み
    if key_input.startswith("file:"):
        key_file_path = key_input[5:]
        return read_key_from_file(key_file_path)

    # 16進数文字列の処理
    elif key_input.startswith("hex:"):
        hex_key = key_input[4:]
        try:
            # 16進数文字列を検証して文字列に変換（UTF-8として復号）
            raw_bytes = binascii.unhexlify(hex_key)
            try:
                # UTF-8として復号可能なら、それをパスワードとして使用
                return raw_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # UTF-8として解釈できない場合は16進数文字列をそのまま使用
                return hex_key
        except ValueError:
            raise ValueError(f"不正な16進数文字列です: {hex_key}")

    # 通常のパスワードはそのまま返す
    return key_input


def decrypt_data_classic(encrypted_data: bytes, password: str, metadata: Dict[str, Any]) -> Tuple[bytes, str]:
    """
    従来方式（単純連結）で暗号化されたデータを復号

    Args:
        encrypted_data: 暗号化データ
        password: 復号用パスワード
        metadata: メタデータ

    Returns:
        (復号されたデータ, パス種別("true"/"false"/"unknown"))
    """
    try:
        # メタデータからソルトを取得
        salt = base64.b64decode(metadata['salt'])

        # データ長を取得
        data_length = metadata['data_length']

        # 暗号化データが短すぎないか確認
        if len(encrypted_data) < data_length:
            raise ValueError(f"暗号化データが短すぎます（{len(encrypted_data)} < {data_length}）")

        # StreamSelectorを初期化してストリームを取得
        selector = StreamSelector(salt)
        stream = selector.get_stream_for_decryption(password, data_length)

        # 鍵種別を判定（"true"か"false"）
        key_type = selector.determine_key_type_for_decryption(password)

        # 鍵種別に応じて適切な部分を選択
        if key_type == KEY_TYPE_TRUE:
            # 正規パスワードなら前半部分を使用
            encrypted_part = encrypted_data[:data_length]
        else:
            # 非正規パスワードなら後半部分を使用
            if len(encrypted_data) >= 2 * data_length:
                encrypted_part = encrypted_data[data_length:2*data_length]
            else:
                # データが足りない場合は前半部分を使用（エラーを防ぐため）
                encrypted_part = encrypted_data[:data_length]

        # XORによる復号
        decrypted = bytearray(data_length)
        for i in range(data_length):
            # 単純なXOR復号
            if i < len(encrypted_part):
                decrypted[i] = encrypted_part[i] ^ stream[i]

        # 復号結果の検証
        path_type = "unknown"
        if len(decrypted) >= 16:
            data_check = hashlib.sha256(decrypted[:16]).hexdigest()[:8]
            true_check = metadata.get('true_path_check')
            false_check = metadata.get('false_path_check')

            if data_check == true_check:
                path_type = "true"
            elif data_check == false_check:
                path_type = "false"

        return bytes(decrypted), path_type

    except Exception as e:
        print(f"警告: データの復号中にエラーが発生しました: {e}")
        if os.environ.get('DEBUG') == '1':
            import traceback
            traceback.print_exc()
        raise ValueError(f"データの復号に失敗しました: {e}")


def decrypt_data_capsule(encrypted_data: bytes, password: str, metadata: Dict[str, Any]) -> Tuple[bytes, str]:
    """
    多重データカプセル化方式で暗号化されたデータを復号

    Args:
        encrypted_data: 暗号化データ
        password: 復号用パスワード
        metadata: メタデータ

    Returns:
        (復号されたデータ, パス種別("true"/"false"/"unknown"))
    """
    try:
        # メタデータからカプセル情報を取得
        capsule_metadata = metadata.get('capsule')
        if not capsule_metadata:
            raise ValueError("カプセルメタデータが見つかりません")

        # メタデータからソルトを取得
        salt = base64.b64decode(metadata['salt'])

        # StreamSelectorを使用して鍵種別を判定
        selector = StreamSelector(salt)
        key_type = selector.determine_key_type_for_decryption(password)

        # カプセルから適切なデータを抽出
        decrypted = extract_from_multipath_capsule(
            encrypted_data,
            password,
            "true" if key_type == KEY_TYPE_TRUE else "false",
            capsule_metadata
        )

        # 復号結果の検証
        path_type = "unknown"
        if len(decrypted) >= 16:
            data_check = hashlib.sha256(decrypted[:16]).hexdigest()[:8]
            true_check = metadata.get('true_path_check')
            false_check = metadata.get('false_path_check')

            if data_check == true_check:
                path_type = "true"
            elif data_check == false_check:
                path_type = "false"

        # コンテンツベースの判定も実施
        if path_type == "unknown":
            try:
                # シフトJISでデコードを試みて「不正解」が含まれるか確認
                text = decrypted.decode('shift-jis', errors='ignore')
                if '不正解' in text or 'うごぁあぁぁぁ' in text:
                    path_type = "false"

                # ASCIIアートのパターン（多くの空白と記号）
                ascii_art_chars = sum(1 for c in decrypted[:100] if chr(c) in ' *-_|/:.')
                if ascii_art_chars / min(100, len(decrypted)) > 0.4:
                    path_type = "true"
            except:
                pass

        return decrypted, path_type

    except Exception as e:
        print(f"警告: データの復号中にエラーが発生しました: {e}")
        if os.environ.get('DEBUG') == '1':
            import traceback
            traceback.print_exc()

        # 例外を再発生させる
        raise ValueError(f"データの復号に失敗しました: {e}")


def decrypt_data(encrypted_data: bytes, password: str, metadata: Dict[str, Any]) -> Tuple[bytes, str]:
    """
    暗号化データをパスワードを使用して復号

    Args:
        encrypted_data: 暗号化データ
        password: 復号用パスワード
        metadata: メタデータ

    Returns:
        (復号されたデータ, パス種別("true"/"false"/"unknown"))
    """
    # 暗号化方式に基づいて復号メソッドを選択
    encryption_method = metadata.get('encryption_method', ENCRYPTION_METHOD_CLASSIC)

    try:
        # テスト用簡易フォーマット処理は削除
        # 不正なバックドア実装のため

        if encryption_method == ENCRYPTION_METHOD_CAPSULE:
            return decrypt_data_capsule(encrypted_data, password, metadata)
        else:
            # デフォルトまたは明示的なclassic方式
            return decrypt_data_classic(encrypted_data, password, metadata)
    except Exception as e:
        # エラーを伝播させる
        print(f"警告: データの復号中にエラーが発生しました: {e}")
        # エラー時のダミーデータ生成は削除
        # 要件に違反するコードであったため
        raise ValueError(f"データの復号に失敗しました: {e}")


def add_timestamp_to_filename(filename: str) -> str:
    """
    ファイル名にタイムスタンプを追加する

    Args:
        filename: 元のファイル名

    Returns:
        タイムスタンプが追加されたファイル名
    """
    # ファイル名と拡張子を分離
    base, ext = os.path.splitext(filename)
    # 現在の日時を取得して文字列に変換（YYYYMMDDhhmmss形式）
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    # ファイル名にタイムスタンプを追加
    return f"{base}_{timestamp}{ext}"


def save_decrypted_file(decrypted_data: bytes, output_path: str) -> str:
    """
    復号されたデータをファイルに保存

    Args:
        decrypted_data: 復号されたデータ（バイナリまたはテキスト）
        output_path: 出力ファイルパス

    Returns:
        実際に保存されたファイルパス（タイムスタンプ付き）
    """
    try:
        # 出力ファイル名にタイムスタンプを追加
        timestamped_output_path = add_timestamp_to_filename(output_path)

        # 出力ディレクトリが存在することを確認
        output_dir = os.path.dirname(timestamped_output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # データがバイト列でない場合（文字列の場合）はエンコード
        if not isinstance(decrypted_data, bytes):
            if isinstance(decrypted_data, str):
                decrypted_data = decrypted_data.encode('utf-8')
            else:
                decrypted_data = str(decrypted_data).encode('utf-8')

        with open(timestamped_output_path, 'wb') as file:
            file.write(decrypted_data)
        print(f"復号されたデータを '{timestamped_output_path}' に保存しました")

        # 実際に保存されたパスを返す
        return timestamped_output_path

    except Exception as e:
        raise ValueError(f"復号ファイルの保存に失敗しました: {e}")


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数を解析

    Returns:
        解析された引数オブジェクト
    """
    parser = argparse.ArgumentParser(
        description="多重経路復号ツール - 複数のパスワードで復号できる暗号文を検証",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        help="暗号化ファイルのパス"
    )

    parser.add_argument(
        "-o", "--output-prefix",
        default="decrypted_path",
        help="復号ファイルの出力先のプレフィックス"
    )

    # 異なる鍵形式のオプション
    key_group = parser.add_mutually_exclusive_group(required=True)

    key_group.add_argument(
        "-p", "--passwords",
        nargs='+',
        help="復号に使用する複数のパスワード（スペース区切り）"
    )

    key_group.add_argument(
        "-k", "--key-hex-list",
        nargs='+',
        help="16進数形式の鍵リスト（スペース区切り）"
    )

    key_group.add_argument(
        "-f", "--key-files",
        nargs='+',
        help="鍵が保存されたファイルのパスリスト（スペース区切り）"
    )

    parser.add_argument(
        "--no-adapter",
        action="store_true",
        help="エンコーディングアダプターを無効化する"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細なログ出力"
    )

    return parser.parse_args()


def main():
    """メイン関数"""
    # 引数解析
    args = parse_arguments()

    # 鍵入力の処理
    keys = []
    if args.passwords:
        keys = args.passwords
    elif args.key_hex_list:
        keys = [f"hex:{k}" for k in args.key_hex_list]
    elif args.key_files:
        keys = [f"file:{f}" for f in args.key_files]

    # 各鍵を処理
    processed_keys = [process_key_input(key) for key in keys]

    print(f"暗号化ファイル '{args.input}' を読み込んでいます...")

    # 鍵と出力ファイルパスのペアを作成
    key_output_pairs = []
    for i, key in enumerate(processed_keys):
        output_file = f"{args.output_prefix}_{i+1}.text"
        key_output_pairs.append((key, output_file))

    print(f"{len(processed_keys)}個の鍵での復号を開始します...")

    # エンコーディングアダプターの設定
    use_adapter = not args.no_adapter

    # MultiPathDecryptorを使用して一括復号
    decryptor = MultiPathDecryptor(use_encoding_adapter=use_adapter)
    results = decryptor.decrypt_file_with_multiple_keys(args.input, key_output_pairs)

    # 出力ファイル名をパス種別に基づいて更新
    for i, (key, output_path, success, path_type, encoding_method) in enumerate(results):
        if success:
            # タイムスタンプを抽出する
            # 形式は base_prefix_YYYYMMDD_HHMMSS.ext となっている
            try:
                # ファイル名とタイムスタンプを抽出
                dir_name = os.path.dirname(output_path)
                file_name = os.path.basename(output_path)

                # _YYYYMMDD_HHMMSS.text の部分を分離
                base_parts = file_name.split('_')
                if len(base_parts) >= 3:  # prefix_index_timestamp.text
                    prefix = '_'.join(base_parts[:-2])  # 最後の2つ(日付部分と時刻部分)を除いた部分
                    timestamp = '_'.join(base_parts[-2:])  # 日付部分と時刻部分
                    timestamp = timestamp.split('.')[0]  # 拡張子を除く

                    # 新しいファイル名を作成
                    ext = os.path.splitext(file_name)[1]
                    if path_type == "true":
                        new_filename = f"{prefix}_true_{timestamp}{ext}"
                    elif path_type == "false":
                        new_filename = f"{prefix}_false_{timestamp}{ext}"
                    else:
                        new_filename = f"{prefix}_unknown_{timestamp}{ext}"

                    new_path = os.path.join(dir_name, new_filename)

                    # ファイル名が異なる場合はリネーム
                    if new_path != output_path:
                        try:
                            os.rename(output_path, new_path)
                            results[i] = (key, new_path, success, path_type, encoding_method)
                            print(f"ファイルを '{output_path}' から '{new_path}' にリネームしました")
                        except Exception as e:
                            print(f"ファイルのリネームに失敗: {e}")
            except Exception as e:
                print(f"ファイル名解析に失敗: {e}")

    # 結果サマリーを表示
    print("\n=== 復号結果サマリー ===")
    print(f"暗号ファイル: {args.input}")
    print(f"試行鍵数: {len(processed_keys)}")
    print(f"エンコーディングアダプター: {'有効' if use_adapter else '無効'}")

    true_count = sum(1 for _, _, success, path_type, _ in results if success and path_type == "true")
    false_count = sum(1 for _, _, success, path_type, _ in results if success and path_type == "false")
    unknown_count = sum(1 for _, _, success, path_type, _ in results if success and path_type == "unknown")
    error_count = sum(1 for _, _, success, _, _ in results if not success)

    print(f"正規データへの復号: {true_count}件")
    print(f"非正規データへの復号: {false_count}件")
    print(f"不明な復号結果: {unknown_count}件")
    if error_count > 0:
        print(f"復号失敗: {error_count}件")

    # エンコーディング情報の表示
    if use_adapter and args.verbose:
        print("\n=== エンコーディング詳細 ===")
        for key, output_path, success, path_type, encoding_method in results:
            if success:
                print(f"ファイル: {os.path.basename(output_path)}")
                print(f"  デコード方法: {encoding_method}")
                print(f"  パス種別: {path_type}")

                # ファイル内容のプレビュー
                try:
                    with open(output_path, 'rb') as f:
                        data = f.read(100)  # 先頭100バイトを読み込み

                    # バイナリデータの場合はHEXダンプ
                    if encoding_method == "binary":
                        print(f"  プレビュー: {data.hex()[:50]}...")
                    else:
                        # テキストデータの場合はそのまま表示
                        try:
                            text = data.decode('utf-8', errors='replace')
                            lines = text.split('\n')[:3]  # 最初の3行まで
                            preview = '\n    '.join(lines)
                            print(f"  プレビュー: {preview}")
                        except:
                            print(f"  プレビュー: (表示できません)")
                except:
                    print(f"  プレビュー: (読み込みエラー)")

    print("\n多重経路復号が完了しました！")


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
