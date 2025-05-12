#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式のデータアダプタモジュール

このモジュールは、テキストやバイナリなどの異なるデータ形式間の
変換を行うアダプタ機能を提供します。暗号化前のデータ変換と
復号後のデータ変換を一貫して行い、異なるデータ形式を適切に
処理できるようにします。
"""

import base64
import json
import struct
from typing import Tuple, Dict, Any, Optional, Union, List


class DataAdapter:
    """
    データ変換のためのベースアダプタクラス

    異なるデータ形式間の変換を管理します。
    """

    @staticmethod
    def detect_data_type(data: bytes) -> str:
        """
        バイナリデータからデータ形式を自動検出

        Args:
            data: 分析するバイトデータ

        Returns:
            検出されたデータ形式 ('text', 'binary', 'json', 'base64', 'unknown')
        """
        # テキストデータの検出
        if TextAdapter.is_text(data):
            try:
                # JSONの検出
                json.loads(data.decode('utf-8'))
                return 'json'
            except (json.JSONDecodeError, UnicodeDecodeError):
                return 'text'

        # Base64データの検出
        if Base64Adapter.is_base64(data):
            return 'base64'

        # その他はバイナリとして扱う
        return 'binary'

    @staticmethod
    def get_adapter(data_type: str) -> 'DataAdapter':
        """
        データ形式に基づいて適切なアダプタを取得

        Args:
            data_type: データ形式名

        Returns:
            対応するアダプタインスタンス

        Raises:
            ValueError: サポートされていないデータ形式が指定された場合
        """
        adapters = {
            'text': TextAdapter(),
            'binary': BinaryAdapter(),
            'json': JSONAdapter(),
            'base64': Base64Adapter()
        }

        adapter = adapters.get(data_type)
        if adapter is None:
            raise ValueError(f"サポートされていないデータ形式です: {data_type}")

        return adapter


class BinaryAdapter(DataAdapter):
    """
    バイナリデータのアダプタ

    バイナリデータは変換なしでそのまま処理されます。
    """

    def to_processable(self, data: bytes) -> bytes:
        """
        処理可能な形式に変換（バイナリはそのまま）

        Args:
            data: 変換する元データ

        Returns:
            変換後のデータ
        """
        return data

    def from_processable(self, data: bytes) -> bytes:
        """
        処理後のデータを元の形式に戻す（バイナリはそのまま）

        Args:
            data: 変換するデータ

        Returns:
            変換後のデータ
        """
        return data


class TextAdapter(DataAdapter):
    """
    テキストデータのアダプタ

    文字列データとバイナリデータの間で変換を行います。
    エンコーディング情報も保持します。
    多段式エンコーディング変換（utf8 -> latin1 -> base64）を実装し、
    テキスト復号時のエンコーディング問題を解決します。
    """

    def __init__(self, encoding: str = 'utf-8'):
        """
        初期化

        Args:
            encoding: テキストエンコーディング（デフォルト: UTF-8）
        """
        self.encoding = encoding

    @staticmethod
    def is_text(data: bytes, threshold: float = 0.8) -> bool:
        """
        データがテキストかどうかを判定

        Args:
            data: 判定するデータ
            threshold: テキストと判断する閾値（0.0-1.0）

        Returns:
            テキストの場合はTrue
        """
        if not data:
            return False

        # ASCII範囲の表示可能文字と制御文字（改行、タブなど）の数をカウント
        printable_count = sum(1 for b in data if (32 <= b <= 126) or b in (9, 10, 13))
        text_ratio = printable_count / len(data)

        # 閾値を超えていればテキストと判断
        if text_ratio >= threshold:
            # UTF-8としてデコードを試みる
            try:
                data.decode('utf-8')
                return True
            except UnicodeDecodeError:
                # 他のエンコーディングを試す
                for enc in ['utf-16', 'latin-1', 'shift-jis', 'euc-jp']:
                    try:
                        data.decode(enc)
                        return True
                    except (UnicodeDecodeError, LookupError):
                        continue

        return False

    def detect_encoding(self, data: bytes) -> str:
        """
        テキストデータのエンコーディングを検出

        Args:
            data: 検出するテキストデータ

        Returns:
            検出されたエンコーディング
        """
        # よく使われるエンコーディング順に試す
        encodings = ['utf-8', 'utf-16', 'latin-1', 'shift-jis', 'euc-jp']

        for enc in encodings:
            try:
                data.decode(enc)
                return enc
            except (UnicodeDecodeError, LookupError):
                continue

        # デフォルトは安全なUTF-8
        return 'utf-8'

    def apply_multi_stage_encoding(self, text: str) -> bytes:
        """
        多段式エンコーディング変換を適用

        テキストに対して utf8 -> latin1 -> base64 の多段変換を行います。

        Args:
            text: 元のテキスト

        Returns:
            多段エンコーディングされたデータ
        """
        print(f"[DEBUG] 多段エンコーディング開始: '{text[:30]}'... (長さ: {len(text)})")

        # ステップ1: UTF-8でエンコード
        utf8_data = text.encode('utf-8')
        print(f"[DEBUG] UTF-8エンコード後: {len(utf8_data)}バイト")

        # ステップ2: latin-1としてデコードし、再度エンコード（安全なバイト変換）
        latin1_text = utf8_data.decode('latin-1')
        latin1_data = latin1_text.encode('latin-1')
        print(f"[DEBUG] Latin-1変換後: {len(latin1_data)}バイト")

        # ステップ3: Base64エンコード
        base64_data = base64.b64encode(latin1_data)
        print(f"[DEBUG] Base64エンコード後: {len(base64_data)}バイト")

        # ヘッダーを追加（変換方法を記録）
        result = b'TXT-MULTI:utf8-latin1-base64:' + base64_data
        print(f"[DEBUG] 最終結果 (先頭30バイト): {result[:30]}")

        return result

    def reverse_multi_stage_encoding(self, data: bytes) -> str:
        """
        多段式エンコーディング変換の逆変換を適用

        base64 -> latin1 -> utf8 の逆変換を行います。

        Args:
            data: 多段エンコーディングされたデータ

        Returns:
            元のテキスト
        """
        print(f"[DEBUG] 多段エンコーディング逆変換開始: {data[:30]}...")

        # ヘッダー部分を削除
        if not data.startswith(b'TXT-MULTI:'):
            raise ValueError("多段エンコーディングのヘッダーがありません")

        header_end = data.find(b':', 10)  # 'TXT-MULTI:' の後のコロンを検索
        if header_end < 0:
            raise ValueError("無効な多段エンコーディングフォーマット")

        # エンコーディング情報を取得
        encoding_info = data[10:header_end].decode('ascii')
        print(f"[DEBUG] エンコーディング情報: {encoding_info}")

        # エンコーディング方式の検証
        if encoding_info != 'utf8-latin1-base64':
            raise ValueError(f"サポートされていないエンコーディング方式: {encoding_info}")

        # Base64部分を取得
        base64_data = data[header_end+1:]
        print(f"[DEBUG] Base64データサイズ: {len(base64_data)}バイト")

        # ステップ1: Base64デコード
        latin1_data = base64.b64decode(base64_data)
        print(f"[DEBUG] Base64デコード後: {len(latin1_data)}バイト")

        # ステップ2: latin-1としてデコード
        latin1_text = latin1_data.decode('latin-1')

        # ステップ3: UTF-8として解釈
        utf8_data = latin1_text.encode('latin-1')
        text = utf8_data.decode('utf-8')
        print(f"[DEBUG] UTF-8デコード後: '{text[:30]}'... (長さ: {len(text)})")

        return text

    def to_processable(self, data: bytes) -> bytes:
        """
        処理可能な形式に変換

        テキストデータを処理するため、多段式エンコーディング変換を
        適用し、バイト列に変換します。

        Args:
            data: 変換する元データ

        Returns:
            変換後のデータ
        """
        # エンコーディングの検出
        encoding = self.detect_encoding(data)
        print(f"[DEBUG] 検出されたエンコーディング: {encoding}")

        # 現在のエンコーディングでデコード
        try:
            text = data.decode(encoding)
            print(f"[DEBUG] デコードされたテキスト（先頭30文字）: {text[:30]}")

            # 多段式エンコーディング変換を適用
            return self.apply_multi_stage_encoding(text)

        except UnicodeDecodeError as e:
            print(f"[DEBUG] テキストデコードエラー: {e}")
            # デコードエラーの場合はラテン1（バイナリ互換）でエンコード
            self.encoding = 'latin-1'
            text = data.decode('latin-1')

            # 多段式エンコーディング変換を適用
            return self.apply_multi_stage_encoding(text)

    def from_processable(self, data: bytes) -> Union[str, bytes]:
        """
        処理後のデータを元の形式に戻す

        多段式エンコーディングを逆変換してテキストに戻します。

        Args:
            data: 変換するデータ

        Returns:
            元のテキストデータ（文字列）
        """
        # 多段式エンコーディングのチェック
        if data.startswith(b'TXT-MULTI:'):
            try:
                return self.reverse_multi_stage_encoding(data)
            except Exception as e:
                print(f"[DEBUG] 多段エンコーディング逆変換エラー: {e}")

        # 従来のフォーマットのチェック
        if data.startswith(b'TXT:'):
            try:
                # エンコーディング情報を取得
                header_end = data.find(b':', 4)
                if header_end > 4:
                    # エンコーディング名を取得
                    encoding = data[4:header_end].decode('ascii')
                    print(f"[DEBUG] 復号時のエンコーディング: {encoding}")

                    # コンテンツ部分の取得
                    content = data[header_end+1:]

                    # UTF-8でエンコードされているのでUTF-8でデコード
                    text = content.decode('utf-8')

                    return text
                else:
                    print("[DEBUG] 無効なヘッダー形式: コロンが見つかりません")
            except Exception as e:
                print(f"[DEBUG] テキスト復元エラー: {e}")

        # マジックバイトがない場合か、エラーが発生した場合は
        # テキストへの変換を試みる
        try:
            for encoding in ['utf-8', 'latin-1', 'shift-jis', 'euc-jp']:
                try:
                    text = data.decode(encoding)
                    print(f"[DEBUG] {encoding}でデコード成功")
                    return text
                except UnicodeDecodeError:
                    continue

            # どのエンコーディングでもデコードできない場合、latin-1で強制デコード
            print("[DEBUG] 強制的にlatin-1でデコード")
            return data.decode('latin-1')

        except Exception as e:
            print(f"[DEBUG] テキスト変換最終エラー: {e}")
            # すべての変換が失敗した場合はバイナリをそのまま返す
            return data


class JSONAdapter(DataAdapter):
    """
    JSONデータのアダプタ

    JSONとバイナリデータの間で変換を行います。
    """

    def to_processable(self, data: bytes) -> bytes:
        """
        処理可能な形式に変換

        JSONデータをバイナリデータに変換します。

        Args:
            data: 変換する元データ

        Returns:
            変換後のデータ
        """
        # JSONタイプを示すヘッダを追加
        header = b'JSON:'
        return header + data

    def from_processable(self, data: bytes) -> bytes:
        """
        処理後のデータを元の形式に戻す

        バイナリデータをJSONデータに変換します。

        Args:
            data: 変換するデータ

        Returns:
            元のJSONデータ
        """
        # ヘッダが存在する場合は削除
        if data.startswith(b'JSON:'):
            return data[5:]
        return data


class Base64Adapter(DataAdapter):
    """
    Base64データのアダプタ

    Base64エンコードされたデータとバイナリデータの間で変換を行います。
    """

    @staticmethod
    def is_base64(data: bytes) -> bool:
        """
        データがBase64エンコードされているかどうかを判定

        Args:
            data: 判定するデータ

        Returns:
            Base64の場合はTrue
        """
        # Base64の有効文字のみで構成されているか確認
        if not data:
            return False

        # Base64でデコード可能か試す
        try:
            # 改行を削除して標準的なBase64文字セットかチェック
            cleaned = data.decode('ascii').strip().replace('\n', '')
            valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            if not all(c in valid_chars for c in cleaned):
                return False

            # 実際にデコードしてみる
            base64.b64decode(cleaned)
            return True
        except Exception:
            return False

    def to_processable(self, data: bytes) -> bytes:
        """
        処理可能な形式に変換

        Base64データをバイナリデータに変換します。

        Args:
            data: 変換する元データ

        Returns:
            変換後のデータ
        """
        # Base64タイプを示すヘッダを追加
        header = b'B64:'
        return header + data

    def from_processable(self, data: bytes) -> bytes:
        """
        処理後のデータを元の形式に戻す

        バイナリデータをBase64データに変換します。

        Args:
            data: 変換するデータ

        Returns:
            元のBase64データ
        """
        # ヘッダが存在する場合は削除
        if data.startswith(b'B64:'):
            return data[4:]
        return data


def process_data_for_encryption(data: bytes, force_type: Optional[str] = None) -> Tuple[bytes, str]:
    """
    暗号化前にデータを処理し、適切な形式に変換

    Args:
        data: 処理するデータ
        force_type: 強制的に指定するデータタイプ（省略時は自動検出）

    Returns:
        (処理されたデータ, データタイプ): 変換後のデータとデータタイプの組
    """
    # データタイプの判定または強制指定
    data_type = force_type or DataAdapter.detect_data_type(data)

    print(f"[DEBUG] 暗号化前: データタイプ={data_type}, サイズ={len(data)}バイト")
    if data_type == 'text':
        print(f"[DEBUG] テキスト内容: {data[:min(30, len(data))]}...")

    # 適切なアダプタの取得と変換
    adapter = DataAdapter.get_adapter(data_type)
    processed_data = adapter.to_processable(data)

    print(f"[DEBUG] 変換後: サイズ={len(processed_data)}バイト")
    if len(processed_data) > 0:
        print(f"[DEBUG] 変換後先頭バイト: {processed_data[:min(20, len(processed_data))]}")

    return processed_data, data_type


def process_data_after_decryption(data: bytes, data_type: str) -> Union[str, bytes]:
    """
    復号後にデータを処理し、元の形式に変換

    Args:
        data: 処理するデータ
        data_type: データのタイプ

    Returns:
        元の形式に変換されたデータ
    """
    print(f"[DEBUG] 復号後: データタイプ={data_type}, サイズ={len(data)}バイト")
    if len(data) > 0:
        print(f"[DEBUG] 復号後先頭バイト: {data[:min(20, len(data))]}")

    # 適切なアダプタの取得と変換
    adapter = DataAdapter.get_adapter(data_type)
    result = adapter.from_processable(data)

    print(f"[DEBUG] 変換後: 型={type(result)}, サイズ={len(result) if hasattr(result, '__len__') else 'N/A'}")
    if isinstance(result, bytes) and len(result) > 0:
        print(f"[DEBUG] 変換後先頭バイト: {result[:min(20, len(result))]}")
    elif isinstance(result, str) and len(result) > 0:
        print(f"[DEBUG] 変換後先頭文字: {result[:min(30, len(result))]}")

    return result


if __name__ == "__main__":
    # 簡単なテスト
    test_text = "これはテストテキストです。".encode('utf-8')
    test_binary = b'\x00\x01\x02\x03\x04\xFF'
    test_json = b'{"name": "test", "value": 123}'

    # テキストデータの処理
    print("--- テキストデータのテスト ---")
    processed_text, type_text = process_data_for_encryption(test_text)
    print(f"元データ: {test_text}")
    print(f"処理後: {processed_text}")
    print(f"タイプ: {type_text}")
    restored_text = process_data_after_decryption(processed_text, type_text)
    print(f"復元後: {restored_text}")
    print(f"元に戻ったか: {test_text.decode('utf-8') == restored_text}")

    # バイナリデータの処理
    print("\n--- バイナリデータのテスト ---")
    processed_binary, type_binary = process_data_for_encryption(test_binary)
    print(f"元データ: {test_binary}")
    print(f"処理後: {processed_binary}")
    print(f"タイプ: {type_binary}")
    restored_binary = process_data_after_decryption(processed_binary, type_binary)
    print(f"復元後: {restored_binary}")
    print(f"元に戻ったか: {test_binary == restored_binary}")