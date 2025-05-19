#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式のデータ形式アダプター

このモジュールは、異なるデータ形式（テキスト、JSON、バイナリなど）を
準同型暗号で処理できる形式に変換するアダプター機能を提供します。
また、復号後のデータを元の形式に戻す機能も提供します。
"""

import base64
import json
import os
import sys
import hashlib
import datetime
from typing import Tuple, Union, Dict, Any, Optional

# デバッグモード（True：詳細情報を表示、False：最小限の情報を表示）
DEBUG_MODE = True

# データ形式を表すマーカー
TEXT_MARKER = "TEXT:UTF8:"
JSON_MARKER = "JSON:UTF8:"
CSV_MARKER = "CSV:UTF8:"
BINARY_MARKER = "BINARY:"
DEBUG_MARKER = "DEBUG:INFO:"

def enable_debug_mode(enable: bool = True) -> None:
    """デバッグモードを有効/無効にする"""
    global DEBUG_MODE
    DEBUG_MODE = enable
    print(f"デバッグモード: {'有効' if DEBUG_MODE else '無効'}")

def debug_log(message: str, force: bool = False) -> None:
    """デバッグ情報をログに出力"""
    if DEBUG_MODE or force:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[DEBUG {timestamp}] {message}")

def process_data_for_encryption(data: Union[bytes, str], data_type: str = "auto") -> Tuple[bytes, str]:
    """
    暗号化前のデータ処理

    データを準同型暗号で処理できる形式に変換します。
    データ形式に応じた前処理と適切なマーカーの追加を行います。

    Args:
        data: 処理するデータ（バイト列または文字列）
        data_type: データ形式（"auto", "text", "json", "csv", "binary"）

    Returns:
        (処理後のバイト列, 判定されたデータ形式)
    """
    # データをバイト列に変換（文字列の場合）
    if not isinstance(data, bytes):
        try:
            data = data.encode("utf-8")
        except AttributeError:
            data = str(data).encode("utf-8")

    # オリジナルデータの基本情報（デバッグと復号に役立つ）
    data_info = {
        "size": len(data),
        "hash": hashlib.sha256(data).hexdigest()[:16],  # 最初の16文字のみ
        "timestamp": datetime.datetime.now().isoformat()
    }

    # データ形式の自動判定（auto指定時）
    final_data_type = data_type
    if data_type == "auto":
        # データの内容から形式を推測
        try:
            # UTF-8テキストとしてデコードしてみる
            text = data.decode("utf-8")

            # JSONかどうかを判定
            try:
                json.loads(text)
                final_data_type = "json"
            except json.JSONDecodeError:
                # CSVかどうかを簡易判定（カンマを含み、改行もある）
                if "," in text and "\n" in text:
                    final_data_type = "csv"
                else:
                    final_data_type = "text"
        except UnicodeDecodeError:
            # UTF-8としてデコードできない場合はバイナリとみなす
            final_data_type = "binary"

    # データ形式に応じた処理
    processed_data = None

    if final_data_type == "text":
        # テキストデータの処理
        if isinstance(data, str):
            text = data
        else:
            text = data.decode("utf-8", errors="replace")

        # テキストの詳細情報を保存
        data_info["format"] = "text"
        data_info["encoding"] = "utf-8"
        data_info["length"] = len(text)
        if len(text) > 50:
            data_info["preview"] = text[:50] + "..."
        else:
            data_info["preview"] = text

        # マーカーとデバッグ情報を付けてBase64エンコード
        debug_info = json.dumps(data_info).encode("utf-8")
        debug_b64 = base64.b64encode(debug_info).decode("ascii")

        # テキストをUTF-8エンコード→Base64エンコード
        text_bytes = text.encode("utf-8")
        b64_text = base64.b64encode(text_bytes).decode("ascii")

        # マーカー + デバッグ情報 + データを連結
        processed_text = f"{TEXT_MARKER}{DEBUG_MARKER}{debug_b64}:{b64_text}"
        processed_data = processed_text.encode("utf-8")

    elif final_data_type == "json":
        # JSONデータの処理
        if isinstance(data, str):
            text = data
        else:
            text = data.decode("utf-8", errors="replace")

        # JSONの詳細情報を保存
        data_info["format"] = "json"
        data_info["encoding"] = "utf-8"
        try:
            json_obj = json.loads(text)
            if isinstance(json_obj, dict):
                data_info["keys"] = list(json_obj.keys())[:10]  # 最初の10個のキーのみ
            data_info["structure"] = type(json_obj).__name__
        except json.JSONDecodeError:
            data_info["error"] = "Invalid JSON"

        # マーカーとデバッグ情報を付けてBase64エンコード
        debug_info = json.dumps(data_info).encode("utf-8")
        debug_b64 = base64.b64encode(debug_info).decode("ascii")

        # JSONをUTF-8エンコード→Base64エンコード
        json_bytes = text.encode("utf-8")
        b64_json = base64.b64encode(json_bytes).decode("ascii")

        # マーカー + デバッグ情報 + データを連結
        processed_text = f"{JSON_MARKER}{DEBUG_MARKER}{debug_b64}:{b64_json}"
        processed_data = processed_text.encode("utf-8")

    elif final_data_type == "csv":
        # CSVデータの処理
        if isinstance(data, str):
            text = data
        else:
            text = data.decode("utf-8", errors="replace")

        # CSVの詳細情報を保存
        data_info["format"] = "csv"
        data_info["encoding"] = "utf-8"
        data_info["lines"] = text.count("\n") + 1

        # マーカーとデバッグ情報を付けてBase64エンコード
        debug_info = json.dumps(data_info).encode("utf-8")
        debug_b64 = base64.b64encode(debug_info).decode("ascii")

        # CSVをUTF-8エンコード→Base64エンコード
        csv_bytes = text.encode("utf-8")
        b64_csv = base64.b64encode(csv_bytes).decode("ascii")

        # マーカー + デバッグ情報 + データを連結
        processed_text = f"{CSV_MARKER}{DEBUG_MARKER}{debug_b64}:{b64_csv}"
        processed_data = processed_text.encode("utf-8")

    else:  # binary
        # バイナリデータの処理
        # バイナリデータの詳細情報を保存
        data_info["format"] = "binary"
        data_info["size"] = len(data)

        # マーカーとデバッグ情報を付けてBase64エンコード
        debug_info = json.dumps(data_info).encode("utf-8")
        debug_b64 = base64.b64encode(debug_info).decode("ascii")

        # バイナリデータをBase64エンコード
        b64_binary = base64.b64encode(data).decode("ascii")

        # マーカー + デバッグ情報 + データを連結
        processed_text = f"{BINARY_MARKER}{DEBUG_MARKER}{debug_b64}:{b64_binary}"
        processed_data = processed_text.encode("utf-8")

    # デバッグ情報の出力
    if DEBUG_MODE:
        debug_log(f"データタイプ: {final_data_type}")
        debug_log(f"元のサイズ: {len(data)} バイト")
        debug_log(f"処理後サイズ: {len(processed_data)} バイト")
        debug_log(f"データ情報: {data_info}")

    return processed_data, final_data_type

def process_data_after_decryption(data: bytes, data_type: str = "auto") -> Union[bytes, str]:
    """
    復号後のデータ処理

    復号されたデータを元の形式に戻します。
    マーカーを検出して適切な変換処理を行います。

    Args:
        data: 復号後のバイト列
        data_type: 想定されるデータ形式（省略可）

    Returns:
        変換後のデータ（文字列またはバイト列）
    """
    if data is None:
        debug_log("復号データがNoneです", force=True)
        return ""

    # バイト列を文字列に変換（可能であれば）
    try:
        decoded_text = data.decode("utf-8", errors="replace")
    except Exception as e:
        debug_log(f"UTF-8デコード失敗: {e}")
        # バイト列のままで処理を続行
        decoded_text = None

    # マーカーに基づいた処理
    if decoded_text:
        debug_data = None

        # テキストマーカーの検出
        if decoded_text.startswith(TEXT_MARKER):
            debug_log("テキストマーカーを検出")
            content = decoded_text[len(TEXT_MARKER):]

            # デバッグ情報の抽出
            if DEBUG_MARKER in content:
                debug_marker_pos = content.find(DEBUG_MARKER) + len(DEBUG_MARKER)
                sep_pos = content.find(":", debug_marker_pos)
                if sep_pos > 0:
                    debug_b64 = content[debug_marker_pos:sep_pos]
                    content = content[sep_pos+1:]
                    try:
                        debug_data = json.loads(base64.b64decode(debug_b64).decode("utf-8"))
                        debug_log(f"復号されたデータ情報: {debug_data}")
                    except Exception as e:
                        debug_log(f"デバッグ情報の解析に失敗: {e}")

            # Base64デコード
            try:
                text_bytes = base64.b64decode(content)
                final_text = text_bytes.decode("utf-8")
                debug_log(f"テキストの復号に成功（{len(final_text)}文字）")
                return final_text
            except Exception as e:
                debug_log(f"テキストのデコードに失敗: {e}")

        # JSONマーカーの検出
        elif decoded_text.startswith(JSON_MARKER):
            debug_log("JSONマーカーを検出")
            content = decoded_text[len(JSON_MARKER):]

            # デバッグ情報の抽出
            if DEBUG_MARKER in content:
                debug_marker_pos = content.find(DEBUG_MARKER) + len(DEBUG_MARKER)
                sep_pos = content.find(":", debug_marker_pos)
                if sep_pos > 0:
                    debug_b64 = content[debug_marker_pos:sep_pos]
                    content = content[sep_pos+1:]
                    try:
                        debug_data = json.loads(base64.b64decode(debug_b64).decode("utf-8"))
                        debug_log(f"復号されたJSONデータ情報: {debug_data}")
                    except Exception as e:
                        debug_log(f"デバッグ情報の解析に失敗: {e}")

            # Base64デコード
            try:
                json_bytes = base64.b64decode(content)
                json_text = json_bytes.decode("utf-8")

                # JSON形式の検証（オプション）
                try:
                    json.loads(json_text)
                    debug_log("有効なJSON形式を確認")
                except json.JSONDecodeError:
                    debug_log("警告: 復号されたデータは有効なJSON形式ではありません")

                debug_log(f"JSONの復号に成功（{len(json_text)}文字）")
                return json_text
            except Exception as e:
                debug_log(f"JSONのデコードに失敗: {e}")

        # CSVマーカーの検出
        elif decoded_text.startswith(CSV_MARKER):
            debug_log("CSVマーカーを検出")
            content = decoded_text[len(CSV_MARKER):]

            # デバッグ情報の抽出
            if DEBUG_MARKER in content:
                debug_marker_pos = content.find(DEBUG_MARKER) + len(DEBUG_MARKER)
                sep_pos = content.find(":", debug_marker_pos)
                if sep_pos > 0:
                    debug_b64 = content[debug_marker_pos:sep_pos]
                    content = content[sep_pos+1:]
                    try:
                        debug_data = json.loads(base64.b64decode(debug_b64).decode("utf-8"))
                        debug_log(f"復号されたCSVデータ情報: {debug_data}")
                    except Exception as e:
                        debug_log(f"デバッグ情報の解析に失敗: {e}")

            # Base64デコード
            try:
                csv_bytes = base64.b64decode(content)
                csv_text = csv_bytes.decode("utf-8")
                debug_log(f"CSVの復号に成功（{len(csv_text)}文字）")
                return csv_text
            except Exception as e:
                debug_log(f"CSVのデコードに失敗: {e}")

        # バイナリマーカーの検出
        elif decoded_text.startswith(BINARY_MARKER):
            debug_log("バイナリマーカーを検出")
            content = decoded_text[len(BINARY_MARKER):]

            # デバッグ情報の抽出
            if DEBUG_MARKER in content:
                debug_marker_pos = content.find(DEBUG_MARKER) + len(DEBUG_MARKER)
                sep_pos = content.find(":", debug_marker_pos)
                if sep_pos > 0:
                    debug_b64 = content[debug_marker_pos:sep_pos]
                    content = content[sep_pos+1:]
                    try:
                        debug_data = json.loads(base64.b64decode(debug_b64).decode("utf-8"))
                        debug_log(f"復号されたバイナリデータ情報: {debug_data}")
                    except Exception as e:
                        debug_log(f"デバッグ情報の解析に失敗: {e}")

            # Base64デコード
            try:
                binary_data = base64.b64decode(content)
                debug_log(f"バイナリデータの復号に成功（{len(binary_data)}バイト）")
                return binary_data
            except Exception as e:
                debug_log(f"バイナリデータのデコードに失敗: {e}")

        # マーカーがない場合、データタイプに応じた処理
        else:
            debug_log("マーカーなしのデータを処理します")
            if data_type in ["text", "json", "csv"]:
                # UTF-8テキストとして返す
                return decoded_text.strip()
            else:
                # バイナリデータとして返す
                return data

    # テキストに変換できなかった場合、バイナリデータとして返す
    debug_log("テキストとして変換できません、バイナリとして処理します")
    return data

def get_original_data_info(data: bytes) -> Optional[Dict[str, Any]]:
    """
    暗号化データから元の情報を抽出する（ユーザー向け）

    Args:
        data: 暗号化されたデータまたは復号されたデータ

    Returns:
        元のデータに関する情報辞書（見つからない場合はNone）
    """
    try:
        # バイト列を文字列に変換
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                debug_log("テキスト変換に失敗、バイナリデータとして処理")
                return None
        else:
            text = str(data)

        # 各マーカーをチェック
        markers = [TEXT_MARKER, JSON_MARKER, CSV_MARKER, BINARY_MARKER]

        for marker in markers:
            if marker in text:
                content = text[text.find(marker) + len(marker):]

                # デバッグ情報を探す
                if DEBUG_MARKER in content:
                    debug_marker_pos = content.find(DEBUG_MARKER) + len(DEBUG_MARKER)
                    sep_pos = content.find(":", debug_marker_pos)

                    if sep_pos > 0:
                        debug_b64 = content[debug_marker_pos:sep_pos]
                        try:
                            debug_data = json.loads(base64.b64decode(debug_b64).decode("utf-8"))
                            return debug_data
                        except Exception as e:
                            debug_log(f"デバッグ情報の抽出に失敗: {e}")

        return None

    except Exception as e:
        debug_log(f"データ情報の抽出に失敗: {e}")
        return None

def display_data_info(data: Union[bytes, str], detailed: bool = False) -> None:
    """
    データに関する情報を表示する（ユーザー向け）

    Args:
        data: 暗号化または復号データ
        detailed: 詳細情報を表示するかどうか
    """
    info = get_original_data_info(data)

    if info:
        print("\n===== データ情報 =====")
        print(f"形式: {info.get('format', '不明')}")
        print(f"サイズ: {info.get('size', 0)} バイト")

        if "hash" in info:
            print(f"ハッシュ: {info['hash']}")

        if "timestamp" in info:
            print(f"タイムスタンプ: {info['timestamp']}")

        # データ形式別の詳細情報
        if info.get("format") == "text":
            print(f"エンコーディング: {info.get('encoding', '不明')}")
            if "preview" in info:
                print(f"プレビュー: {info['preview']}")

        elif info.get("format") == "json":
            if "structure" in info:
                print(f"構造: {info['structure']}")
            if "keys" in info and detailed:
                print(f"キー: {', '.join(info['keys'])}")

        elif info.get("format") == "csv":
            if "lines" in info:
                print(f"行数: {info['lines']}")

        print("======================\n")
    else:
        print("\n情報: データから元の情報を抽出できませんでした。")

# 以前のコードから移行したメソッドをグローバル関数として修正
def multi_stage_encoding(text: str) -> bytes:
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

def multi_stage_encoding_binary(data: bytes) -> bytes:
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

def process_after_decryption(text: str) -> str:
    """
    復号後のテキストを処理する

    Args:
        text: 復号されたテキスト

    Returns:
        処理後のテキスト
    """
    # マーカーが見つからなかった場合、そのままのテキストをチェック
    if text.strip():
        # テキストらしき内容があれば、そのまま返す
        debug_log("マーカーなしテキストを検出")
        return text
    else:
        return ""

# テスト用コード
if __name__ == "__main__":
    # テスト関数
    def test_encoding_decoding():
        print("暗号化前/復号後データ処理のテスト")

        # テキストデータのテスト
        print("\n--- テキストデータテスト ---")
        test_text = "これはテストテキストです。UTF-8エンコーディングのテキストを処理します。"
        processed, dtype = process_data_for_encryption(test_text, "text")
        print(f"処理後データタイプ: {dtype}")
        print(f"処理後サイズ: {len(processed)} バイト")

        restored = process_data_after_decryption(processed)
        print(f"復元結果: {restored == test_text}")
        if restored != test_text:
            print(f"元のテキスト: {test_text}")
            print(f"復元されたテキスト: {restored}")

        # 元データ情報の表示
        display_data_info(processed)

        # JSONデータのテスト
        print("\n--- JSONデータテスト ---")
        test_json = """{"name": "テスト", "value": 123, "items": ["one", "two", "three"]}"""
        processed, dtype = process_data_for_encryption(test_json, "json")
        print(f"処理後データタイプ: {dtype}")
        print(f"処理後サイズ: {len(processed)} バイト")

        restored = process_data_after_decryption(processed)
        print(f"復元結果: {restored == test_json}")

        # 元データ情報の表示
        display_data_info(processed, detailed=True)

        # バイナリデータのテスト
        print("\n--- バイナリデータテスト ---")
        test_binary = bytes([0, 1, 2, 3, 255, 254, 253, 252])
        processed, dtype = process_data_for_encryption(test_binary, "binary")
        print(f"処理後データタイプ: {dtype}")
        print(f"処理後サイズ: {len(processed)} バイト")

        restored = process_data_after_decryption(processed)
        print(f"復元結果: {restored == test_binary}")

        # 元データ情報の表示
        display_data_info(processed)

    # テスト実行
    test_encoding_decoding()