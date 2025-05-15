#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式のデータアダプターモジュール

このモジュールは、さまざまな形式のデータ（テキスト、JSON、バイナリなど）を
暗号化・復号に適したフォーマットに変換するためのアダプターを提供します。
"""

import os
import sys
import json
import base64
import binascii
import io
import csv
import re
from typing import Dict, List, Tuple, Any, Optional, Union, BinaryIO

class DataAdapter:
    """
    データタイプのアダプターの基底クラス

    このクラスは、さまざまな形式のデータを暗号化・復号に適した
    形式に変換するための基本機能を提供します。
    """

    @staticmethod
    def detect_data_type(data: bytes) -> str:
        """
        データ形式を自動検出

        Args:
            data: 検出するデータ

        Returns:
            検出されたデータタイプ ('text', 'json', 'csv', 'binary', 'base64')
        """
        if data is None or len(data) == 0:
            return 'binary'

        # マーカーが付いている場合はそれで判断
        try:
            header = data[:20].decode('utf-8', errors='ignore')
            if header.startswith('TEXT:'):
                return 'text'
            elif header.startswith('JSON:'):
                return 'json'
            elif header.startswith('CSV:'):
                return 'csv'
        except UnicodeDecodeError:
            pass  # デコードエラーの場合は次の判定に進む

        # ファイル内容からの判定
        try:
            # まずUTF-8としてデコードを試みる
            text = data.decode('utf-8', errors='strict')

            # JSONとして解析できるか試みる
            try:
                json.loads(text)
                return 'json'
            except json.JSONDecodeError:
                pass

            # CSV形式かどうかをチェック
            try:
                lines = text.splitlines()
                if len(lines) > 0:
                    # 最初の数行をCSVとして解析
                    fields = next(csv.reader([lines[0]]))
                    if len(fields) > 1:  # 複数のフィールドがあればCSVの可能性
                        # 2行目以降も同じフィールド数かをチェック
                        if len(lines) > 1:
                            fields2 = next(csv.reader([lines[1]]))
                            if abs(len(fields) - len(fields2)) <= 1:  # フィールド数がほぼ同じ
                                return 'csv'
            except Exception:
                pass

            # それ以外はテキスト
            return 'text'

        except UnicodeDecodeError:
            # UTF-8でデコードできない場合はバイナリ
            return 'binary'

    @staticmethod
    def get_adapter(data_type: str) -> 'DataAdapter':
        """
        指定されたデータタイプのアダプターを取得

        Args:
            data_type: データタイプ

        Returns:
            アダプターのインスタンス
        """
        adapters = {
            'text': TextAdapter(),
            'json': JsonAdapter(),
            'csv': CsvAdapter(),
            'binary': BinaryAdapter(),
            'base64': Base64Adapter(),
            'auto': DataAdapter()
        }

        return adapters.get(data_type, BinaryAdapter())

    def prepare_for_encryption(self, data: bytes) -> Tuple[bytes, str]:
        """
        暗号化のためのデータ準備（自動検出）

        Args:
            data: 準備するデータ

        Returns:
            (処理済みデータ, データタイプ)
        """
        # データタイプを検出
        data_type = self.detect_data_type(data)

        # 適切なアダプターを使用
        adapter = self.get_adapter(data_type)
        return adapter.prepare_for_encryption(data)

    def process_after_decryption(self, data: bytes, original_type: str) -> Union[bytes, str]:
        """
        復号後のデータ処理（自動検出）

        Args:
            data: 処理するデータ
            original_type: 元のデータタイプ

        Returns:
            処理済みデータ
        """
        # 適切なアダプターを使用
        adapter = self.get_adapter(original_type)
        return adapter.process_after_decryption(data, original_type)


class TextAdapter(DataAdapter):
    """テキストデータ用アダプター"""

    def prepare_for_encryption(self, data: bytes) -> Tuple[bytes, str]:
        """
        テキストデータを暗号化用に準備

        Args:
            data: 準備するデータ

        Returns:
            (処理済みデータ, データタイプ)
        """
        # まずデータがバイナリかどうかを確認し、変換
        if not isinstance(data, bytes):
            try:
                data = str(data).encode('utf-8')
            except UnicodeEncodeError:
                # UTF-8で変換できない場合はLatin-1を試す
                data = str(data).encode('latin-1')

        try:
            # UTF-8でデコードを試みる
            text = data.decode('utf-8')

            # マーカーを追加
            marked_text = f"TEXT:UTF8:{text}"

            # UTF-8でエンコード
            encoded = marked_text.encode('utf-8')

            print(f"テキストデータをUTF-8で準備: {len(data)}バイト → {len(encoded)}バイト")

            return encoded, 'text'
        except UnicodeDecodeError:
            # UTF-8でないエンコーディングの処理
            try:
                # エンコーディングの自動検出処理
                encoding = self._detect_encoding(data)

                if encoding and encoding != 'utf-8':
                    # 指定されたエンコーディングでデコード
                    text = data.decode(encoding)

                    # マーカーを追加（エンコーディング情報を含む）
                    marked_text = f"TEXT:{encoding.upper()}:{text}"

                    # UTF-8でエンコード（統一エンコーディング）
                    encoded = marked_text.encode('utf-8')

                    print(f"テキストデータを{encoding}から変換: {len(data)}バイト → {len(encoded)}バイト")

                    return encoded, 'text'

                # 検出できない場合はLatin-1を試みる
                text = data.decode('latin-1')
                marked_text = f"TEXT:LATIN1:{text}"
                encoded = marked_text.encode('utf-8')

                print(f"テキストデータをLatin-1で処理: {len(data)}バイト → {len(encoded)}バイト")

                return encoded, 'text'
            except Exception as e:
                print(f"テキスト処理エラー: {e}")

                # 多段階エンコーディングを使用
                encoded = self.multi_stage_encoding_binary(data)

                print(f"テキストデータを多段階エンコード: {len(data)}バイト → {len(encoded)}バイト")

                return encoded, 'text'

    def _detect_encoding(self, data: bytes) -> Optional[str]:
        """
        テキストのエンコーディングを検出

        Args:
            data: 検出するデータ

        Returns:
            検出されたエンコーディング名、検出できない場合はNone
        """
        # 優先順位の高いエンコーディングから試す
        encodings = ['utf-8', 'shift-jis', 'euc-jp', 'iso-2022-jp', 'latin-1']

        # BOMでUTF-8が明示されているか確認
        if data.startswith(b'\xef\xbb\xbf'):
            return 'utf-8'

        for enc in encodings:
            try:
                data.decode(enc)
                return enc
            except UnicodeDecodeError:
                continue

        return None

    def multi_stage_encoding(self, text: str) -> bytes:
        """
        テキストを複数段階でエンコード（より堅牢に）

        Args:
            text: エンコードするテキスト

        Returns:
            エンコードされたバイト列
        """
        # 1. UTF-8エンコード
        utf8_bytes = text.encode('utf-8')

        # 2. エンコードされたバイト列をBase64エンコード
        base64_bytes = base64.b64encode(utf8_bytes)

        # 3. Base64文字列にマーカーを追加してUTF-8エンコード
        marked_text = f"TXT-MULTI:{base64_bytes.decode('ascii')}"
        result = marked_text.encode('utf-8')

        return result

    def multi_stage_encoding_binary(self, data: bytes) -> bytes:
        """
        バイナリデータを複数段階でエンコード（テキスト変換失敗時のフォールバック）

        Args:
            data: エンコードするバイナリデータ

        Returns:
            エンコードされたバイト列
        """
        # 1. バイナリデータをBase64エンコード
        base64_bytes = base64.b64encode(data)

        # 2. Base64文字列にマーカーを追加してUTF-8エンコード
        marked_text = f"TXT-BIN:{base64_bytes.decode('ascii')}"
        result = marked_text.encode('utf-8')

        return result

    def reverse_multi_stage_encoding(self, data: bytes) -> str:
        """
        複数段階エンコードを逆変換

        Args:
            data: 逆変換するデータ

        Returns:
            元のテキスト
        """
        try:
            # バイト列をUTF-8でデコード
            text = data.decode('utf-8')

            # マーカーを確認
            if not text.startswith("TXT-MULTI:"):
                raise ValueError("Invalid multi-stage encoded data")

            # マーカーを削除
            base64_str = text[len("TXT-MULTI:"):]

            # Base64デコード
            utf8_bytes = base64.b64decode(base64_str)

            # UTF-8デコード
            original_text = utf8_bytes.decode('utf-8')

            return original_text
        except Exception as e:
            print(f"複数段階エンコード逆変換エラー: {e}")
            # エラーが発生した場合は元のデータをそのまま返す
            if isinstance(data, bytes):
                return data.decode('utf-8', errors='replace')
            return str(data)

    def reverse_multi_stage_encoding_binary(self, data: bytes) -> bytes:
        """
        バイナリ用の複数段階エンコードを逆変換

        Args:
            data: 逆変換するデータ

        Returns:
            元のバイナリデータ
        """
        try:
            # UTF-8でデコード
            text = data.decode('utf-8')

            # マーカーを確認
            if not text.startswith("TXT-BIN:"):
                raise ValueError("Invalid binary multi-stage encoded data")

            # マーカーを削除
            base64_str = text[len("TXT-BIN:"):]

            # Base64デコード
            original_binary = base64.b64decode(base64_str)

            return original_binary
        except Exception as e:
            print(f"バイナリ複数段階エンコード逆変換エラー: {e}")
            # エラーが発生した場合は元のデータをそのまま返す
            return data

    def process_after_decryption(self, data: bytes, original_type: str) -> str:
        """
        復号後のテキストデータ処理

        Args:
            data: 処理するデータ
            original_type: 元のデータタイプ

        Returns:
            処理済みテキスト
        """
        if not data:
            return ""

        print(f"テキスト処理を開始: データ長={len(data)}バイト")
        # 先頭部分をチェック
        if len(data) > 20:
            print(f"データ先頭: {data[:20]}")

        # 末尾の部分をチェック
        if len(data) > 20:
            print(f"データ末尾: {data[-20:]}")

        # 先頭のヌルバイトをトリム（末尾のヌルバイトは残す）
        data = data.lstrip(b'\x00')
        if len(data) == 0:
            print("警告: データがすべてヌルバイトでした")
            return ""

        # 新しいマーカー形式を優先的に処理
        try:
            # まずUTF-8でデコード
            text = data.decode('utf-8', errors='replace')

            # 新しいマーカー形式を検索
            markers = [
                "TEXT:UTF8:",
                "TEXT:LATIN1:",
                "TEXT:SHIFT-JIS:",
                "TEXT:EUC-JP:",
                "TEXT:ISO-2022-JP:"
            ]

            for marker in markers:
                marker_pos = text.find(marker)
                if marker_pos >= 0:
                    print(f"マーカー '{marker}' を検出")
                    # マーカー以降のテキストを取得
                    text_content = text[marker_pos + len(marker):]

                    # エンコーディング情報を抽出
                    encoding = marker.split(':')[1].lower()

                    if encoding == 'utf8':
                        # UTF-8はそのまま
                        return text_content
                    else:
                        # 他のエンコーディングは適切に処理
                        try:
                            # 一度エンコードしてから指定のエンコーディングでデコード
                            result = text_content.encode('utf-8').decode(encoding, errors='replace')
                            return result
                        except Exception as e:
                            print(f"エンコーディング変換エラー({encoding}): {e}")
                            return text_content

            # 旧マーカー形式のサポート（後方互換性）
            old_markers = [
                "TXT:",
                "TXT-UTF-8:",
                "TXT-LATIN1:",
                "TXT-SHIFT-JIS:",
                "TXT-EUC-JP:",
                "TXT-ISO-2022-JP:",
                "TXT-MULTI:",
                "TXT-BIN:"
            ]

            for marker in old_markers:
                marker_pos = text.find(marker)
                if marker_pos >= 0:
                    print(f"旧マーカー '{marker}' を検出 - 後方互換処理")
                    # マーカー以降のテキストを取得
                    text_content = text[marker_pos + len(marker):]

                    # マーカーに応じて処理
                    if marker == "TXT-MULTI:":
                        text_content = self.reverse_multi_stage_encoding(text_content.encode('utf-8'))
                    elif marker == "TXT-BIN:":
                        bin_content = self.reverse_multi_stage_encoding_binary(text_content.encode('utf-8'))
                        text_content = bin_content.decode('utf-8', errors='replace')

                    return text_content

            # マーカーが見つからなかった場合、そのままのテキストをチェック
            if text.strip():
                # テキストらしき内容があれば、そのまま返す
                print("マーカーなしテキストを検出")
                return text

        except Exception as e:
            print(f"テキスト処理中にエラー: {e}")
            import traceback
            traceback.print_exc()

        # すべての方法が失敗した場合、UTF-8でデコード（置換モード）
        try:
            result = data.decode('utf-8', errors='replace')
            return result
        except Exception as e:
            print(f"最終エラー: {e}")
            # エラーが発生した場合は空文字列を返す
            return ""


class JsonAdapter(DataAdapter):
    """JSONデータ用アダプター"""

    def prepare_for_encryption(self, data: bytes) -> Tuple[bytes, str]:
        """
        JSONデータを暗号化用に準備

        Args:
            data: 準備するデータ

        Returns:
            (処理済みデータ, データタイプ)
        """
        try:
            # JSON文字列として解析
            if isinstance(data, bytes):
                json_str = data.decode('utf-8')
            else:
                json_str = data

            json_obj = json.loads(json_str)

            # 整形してマーカーを追加
            formatted_json = json.dumps(json_obj, ensure_ascii=False, indent=2)
            marked_json = f"JSON:{formatted_json}"

            return marked_json.encode('utf-8'), 'json'
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"JSONデータ解析エラー: {e}")
            # JSONとして扱えない場合はテキストとして扱う
            return TextAdapter().prepare_for_encryption(data)

    def process_after_decryption(self, data: bytes, original_type: str) -> str:
        """
        復号後のJSONデータ処理

        Args:
            data: 処理するデータ
            original_type: 元のデータタイプ

        Returns:
            処理済みJSON文字列
        """
        try:
            # バイト列を文字列に変換
            if isinstance(data, bytes):
                # 先頭のヌルバイトのみを削除（末尾は保持）
                data = data.lstrip(b'\x00')
                data_str = data.decode('utf-8', errors='replace')
            else:
                # 文字列の場合は先頭のヌルバイトのみを削除
                data_str = str(data).lstrip('\x00')

            # マーカーのチェック
            json_marker = "JSON:"
            if json_marker in data_str:
                # マーカー位置を検出
                marker_pos = data_str.find(json_marker)
                # マーカー以降のデータを取得
                json_data = data_str[marker_pos + len(json_marker):]

                # 先頭と末尾の空白文字を削除
                json_data = json_data.strip()

                try:
                    # JSONとして解析できるか確認
                    json_obj = json.loads(json_data)
                    # フォーマットして返す（整形済みJSONとして）
                    return json.dumps(json_obj, ensure_ascii=False, indent=2)
                except json.JSONDecodeError as e:
                    print(f"JSON解析エラー: {e}, 文字列をそのまま返します")
                    return json_data
            else:
                # マーカーがない場合は、JSONとして解析を試みる
                try:
                    # 制御文字などを含む場合がある可能性があるため、正規表現でクリーンアップ
                    # ヌルバイトやその他の制御文字を削除（JSONで許容されない文字）
                    cleaned_str = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', data_str)
                    json_obj = json.loads(cleaned_str)
                    return json.dumps(json_obj, ensure_ascii=False, indent=2)
                except json.JSONDecodeError:
                    # JSON解析できない場合は、元の文字列を返す
                    print(f"マーカーなしでJSONとして解析できませんでした。テキストとして処理します")
                    # テキストアダプタに処理を委譲
                    return TextAdapter().process_after_decryption(data, original_type)
        except Exception as e:
            print(f"JSONデータ処理中にエラーが発生しました: {e}")
            # エラーが発生した場合もテキストとして処理
            return TextAdapter().process_after_decryption(data, original_type)


class CsvAdapter(DataAdapter):
    """CSVデータ用アダプター"""

    def prepare_for_encryption(self, data: bytes) -> Tuple[bytes, str]:
        """
        CSVデータを暗号化用に準備

        Args:
            data: 準備するデータ

        Returns:
            (処理済みデータ, データタイプ)
        """
        try:
            # CSV文字列として解析
            if isinstance(data, bytes):
                csv_str = data.decode('utf-8')
            else:
                csv_str = data

            # CSVのマーカーを付与
            marked_csv = f"CSV:{csv_str}"

            return marked_csv.encode('utf-8'), 'csv'
        except UnicodeDecodeError as e:
            print(f"CSVデータ解析エラー: {e}")
            # CSVとして扱えない場合はテキストとして扱う
            return TextAdapter().prepare_for_encryption(data)

    def process_after_decryption(self, data: bytes, original_type: str) -> str:
        """
        復号後のCSVデータ処理

        Args:
            data: 処理するデータ
            original_type: 元のデータタイプ

        Returns:
            処理済みCSV文字列
        """
        try:
            # バイト列を文字列に変換
            if isinstance(data, bytes):
                # 先頭のヌルバイトをトリム（末尾は保持）
                data = data.lstrip(b'\x00')
                data_str = data.decode('utf-8', errors='replace')
            else:
                data_str = str(data).lstrip('\x00')

            # マーカーのチェック
            csv_marker = "CSV:"
            if csv_marker in data_str:
                # マーカー位置を検出
                marker_pos = data_str.find(csv_marker)
                # マーカー以降のデータを取得
                csv_data = data_str[marker_pos + len(csv_marker):]

                # 改行の正規化（改行コードを統一）
                csv_data = csv_data.replace('\r\n', '\n').replace('\r', '\n')

                # CSVとして解析できるか確認
                try:
                    import csv
                    import io
                    # CSVとしての検証（読み込みテスト）
                    csv_reader = csv.reader(io.StringIO(csv_data))
                    # 先頭数行を読み込んで検証
                    rows = []
                    for i, row in enumerate(csv_reader):
                        if i < 5:  # 最初の5行だけ確認
                            rows.append(row)

                    if rows:
                        print(f"CSVデータを検証: {len(rows)}行のデータを確認")

                    # 検証後の元のデータを返す（変更しない）
                    return csv_data
                except Exception as e:
                    print(f"CSV検証エラー: {e}, テキストとして処理します")
                    # CSVとして解析できなかったが、マーカーがあるのでCSVとして返す
                    return csv_data
            else:
                # マーカーがない場合でも、テキストデータとして返す
                print(f"CSVマーカーが見つかりませんでした。テキストとして処理します")

                # 改行の正規化（改行コードを統一）
                data_str = data_str.replace('\r\n', '\n').replace('\r', '\n')

                return data_str
        except Exception as e:
            print(f"CSVデータ処理中にエラーが発生: {e}")
            # エラーが発生した場合もテキストとして処理
            return TextAdapter().process_after_decryption(data, original_type)


class BinaryAdapter(DataAdapter):
    """バイナリデータ用アダプター"""

    def prepare_for_encryption(self, data: bytes) -> Tuple[bytes, str]:
        """
        バイナリデータを暗号化用に準備

        Args:
            data: 準備するデータ

        Returns:
            (処理済みデータ, データタイプ)
        """
        # バイナリデータはそのまま返す
        if isinstance(data, bytes):
            return data, 'binary'
        else:
            # バイト列でない場合は変換
            return str(data).encode('utf-8'), 'binary'

    def process_after_decryption(self, data: bytes, original_type: str) -> bytes:
        """
        復号後のバイナリデータ処理

        Args:
            data: 処理するデータ
            original_type: 元のデータタイプ

        Returns:
            処理済みバイナリデータ
        """
        # バイナリデータはそのまま返す
        return data


class Base64Adapter(DataAdapter):
    """Base64データ用アダプター"""

    def prepare_for_encryption(self, data: bytes) -> Tuple[bytes, str]:
        """
        Base64データを暗号化用に準備

        Args:
            data: 準備するデータ

        Returns:
            (処理済みデータ, データタイプ)
        """
        try:
            # データがBase64でデコードできるか確認
            decoded = base64.b64decode(data)

            # デコードした結果にマーカーを追加してエンコード
            marked_data = b"B64:" + data

            return marked_data, 'base64'
        except binascii.Error:
            # Base64でない場合はバイナリとして扱う
            return data, 'binary'

    def process_after_decryption(self, data: bytes, original_type: str) -> bytes:
        """
        復号後のBase64データ処理

        Args:
            data: 処理するデータ
            original_type: 元のデータタイプ

        Returns:
            処理済みBase64データ
        """
        try:
            # データがBase64マーカーで始まるかチェック
            if data.startswith(b"B64:"):
                # マーカーを削除
                base64_data = data[4:]

                # Base64デコードを試みる
                try:
                    decoded = base64.b64decode(base64_data)
                    return decoded
                except binascii.Error:
                    # デコードエラーの場合はマーカーを削除したデータを返す
                    return base64_data
            else:
                # マーカーがなければそのまま返す
                return data
        except Exception as e:
            print(f"Base64処理エラー: {e}")
            # エラーが発生した場合は元のデータをそのまま返す
            return data


def process_data_for_encryption(data: Union[bytes, str], data_type: str = 'auto') -> Tuple[bytes, str]:
    """
    暗号化のためのデータ処理

    Args:
        data: 処理するデータ
        data_type: データタイプ ('auto', 'text', 'json', 'csv', 'binary')

    Returns:
        (処理されたデータ, データタイプ)
    """
    # データがバイト列でない場合、バイト列に変換
    if not isinstance(data, bytes):
        data = str(data).encode('utf-8')

    # データタイプの自動検出
    if data_type == 'auto':
        data_type = DataAdapter.detect_data_type(data)
        print(f"データタイプを自動検出: {data_type}")

    # 適切なアダプターを選択
    adapter = DataAdapter.get_adapter(data_type)
    processed_data, final_type = adapter.prepare_for_encryption(data)

    print(f"データ処理完了: タイプ={final_type}, サイズ={len(processed_data)}バイト")

    # データタイプマーカーの確認（デバッグ用）
    if isinstance(processed_data, bytes) and len(processed_data) > 5:
        # 最初の16バイトをデコードして表示（マーカーチェック用）
        try:
            header_str = processed_data[:16].decode('utf-8', errors='replace')
            print(f"データヘッダー: {header_str}")
        except UnicodeDecodeError:
            print("データヘッダーはバイナリで表示できません")

    return processed_data, final_type


def process_data_after_decryption(data: bytes, data_type: str = 'auto') -> Union[bytes, str]:
    """
    復号後のデータ処理

    Args:
        data: 処理するデータ (bytes)
        data_type: データタイプ ('auto', 'text', 'json', 'csv', 'binary')

    Returns:
        処理されたデータ
    """
    if data is None or len(data) == 0:
        print("警告: 復号データが空です")
        return b'' if data_type == 'binary' else ''

    # データがバイト列でない場合はエラー
    if not isinstance(data, bytes):
        print(f"警告: 復号データがバイト列ではありません ({type(data)})")
        # 文字列の場合はバイト列に変換
        if isinstance(data, str):
            data = data.encode('utf-8')
        else:
            # その他の型は文字列に変換してからバイト列に
            data = str(data).encode('utf-8')

    # デバッグ情報
    print(f"復号後データ処理: タイプ={data_type}, サイズ={len(data)}バイト")
    if len(data) > 20:
        print(f"データ先頭バイト: {data[:20]}")
        print(f"データ末尾バイト: {data[-20:]}")

    # データタイプのマーカーチェック（自動検出モードの場合）
    detected_type = data_type
    if data_type == 'auto':
        # マーカーによるデータタイプ検出の試み
        try:
            # 最初の数バイトを文字列としてデコード
            header = data[:20].decode('utf-8', errors='replace')

            # 既知のマーカーをチェック
            if header.startswith('TEXT:'):
                detected_type = 'text'
                print(f"マーカーからデータタイプを検出: {detected_type}")
            elif header.startswith('JSON:'):
                detected_type = 'json'
                print(f"マーカーからデータタイプを検出: {detected_type}")
            elif header.startswith('CSV:'):
                detected_type = 'csv'
                print(f"マーカーからデータタイプを検出: {detected_type}")
            else:
                # マーカーがない場合はデータ内容から推測
                detected_type = DataAdapter.detect_data_type(data)
                print(f"データ内容からタイプを推測: {detected_type}")
        except Exception as e:
            print(f"データタイプ検出エラー: {e}")
            detected_type = 'binary'  # デフォルトはバイナリ

    # 適切なアダプターで処理
    adapter = DataAdapter.get_adapter(detected_type)
    processed_data = adapter.process_after_decryption(data, detected_type)

    # 結果の型確認（デバッグ用）
    result_type = type(processed_data).__name__
    print(f"処理結果: タイプ={result_type}, サイズ={len(processed_data) if hasattr(processed_data, '__len__') else 'unknown'}")

    # テキスト系データの場合は文字列を返し、バイナリデータの場合はバイト列を返す
    if isinstance(processed_data, str) and detected_type == 'binary':
        # バイナリデータなのに文字列が返された場合はバイト列に変換
        try:
            return processed_data.encode('utf-8')
        except UnicodeEncodeError:
            print("警告: バイナリデータへの変換エラー")
            return processed_data.encode('utf-8', errors='replace')
    elif isinstance(processed_data, bytes) and detected_type in ['text', 'json', 'csv']:
        # テキスト系なのにバイト列が返された場合は文字列に変換
        try:
            return processed_data.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            print("警告: テキストデータへの変換エラー")
            return processed_data.decode('utf-8', errors='replace')

    return processed_data


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