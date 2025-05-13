#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
エンコーディングアダプターモジュール

多重経路復号で得られたバイナリデータを適切なエンコーディングに変換し、
可読性のあるテキストに変換する機能を提供します。
"""

import os
import sys
import base64
import re
import json
import hashlib
import binascii
import chardet
import math
from typing import List, Dict, Any, Tuple, Optional, Union

# インポートエラーを回避するための処理
if __name__ == "__main__":
    # モジュールとして実行された場合の処理
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
else:
    pass  # パッケージの一部として実行された場合

# サポートされているエンコーディングのリスト
SUPPORTED_ENCODINGS = [
    'utf-8',
    'latin-1',
    'utf-16',
    'utf-16-be',
    'utf-16-le',
    'ascii',
    'cp1252',
    'shift-jis',
    'euc-jp',
    'iso-2022-jp'
]

# バイナリデータの特性マッチングパターン
BINARY_PATTERNS = {
    'zip': rb'^PK\x03\x04',
    'pdf': rb'^%PDF',
    'png': rb'^\x89PNG\r\n\x1a\n',
    'jpeg': rb'^\xff\xd8\xff',
    'gif': rb'^GIF8[79]a',
    'bmp': rb'^BM',
    'base64': rb'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
}

# XOR暗号化されたデータの特定に役立つパターン
XOR_PATTERNS = [
    (b'true.text', 0.6),   # 'true.text'文字列が含まれる可能性がある場合の閾値
    (b'false.text', 0.6),  # 'false.text'文字列が含まれる可能性がある場合の閾値
    (b'ASCII', 0.7),       # ASCIIアートが含まれている可能性
]


def detect_encoding(data: bytes) -> str:
    """
    データのエンコーディングを検出

    Args:
        data: 検出対象のバイナリデータ

    Returns:
        検出されたエンコーディング名
    """
    if not data:
        return 'binary'

    # Null文字が含まれていたらバイナリデータの可能性が高い
    if b'\x00' in data[:1024]:
        return 'binary'

    # まずはバイナリファイルタイプの検出
    for file_type, pattern in BINARY_PATTERNS.items():
        if re.match(pattern, data[:20]):
            return file_type

    # chardetを使用したエンコーディング検出を試みる
    try:
        detected = chardet.detect(data)
        if detected['confidence'] > 0.7:
            return detected['encoding']
    except:
        pass

    # テキストエンコーディングの検出
    for encoding in SUPPORTED_ENCODINGS:
        try:
            text = data.decode(encoding)
            # ASCII可読文字の割合を確認
            printable_ratio = sum(c.isprintable() for c in text) / len(text)
            if printable_ratio > 0.8:  # 80%以上が可読文字なら有効と判断
                return encoding
        except UnicodeDecodeError:
            # デコードエラーの場合は次のエンコーディングを試す
            continue

    # どのエンコーディングにも該当しない場合はバイナリデータと判断
    try:
        # Base64エンコーディングの可能性をチェック
        base64.b64decode(data)
        return 'base64'
    except:
        pass

    return 'binary'


def decode_data(data: bytes, detected_encoding: str = None) -> Tuple[str, str]:
    """
    データを適切なエンコーディングでデコード

    Args:
        data: デコード対象のバイナリデータ
        detected_encoding: 検出済みのエンコーディング（指定がなければ自動検出）

    Returns:
        (デコードされたテキスト, 使用されたエンコーディング)
    """
    if not data:
        return "", "empty"

    # エンコーディングが指定されていない場合は自動検出
    if not detected_encoding:
        detected_encoding = detect_encoding(data)

    # 特殊ケース: Base64
    if detected_encoding == 'base64':
        try:
            decoded_data = base64.b64decode(data)
            inner_encoding = detect_encoding(decoded_data)
            if inner_encoding != 'binary':
                inner_text, _ = decode_data(decoded_data, inner_encoding)
                return inner_text, f"base64+{inner_encoding}"
            else:
                return f"[Base64エンコードデータ: {len(decoded_data)}バイト]", "base64"
        except:
            pass  # Base64デコードに失敗した場合は次の処理に進む

    # テキストエンコーディングの場合
    if detected_encoding in SUPPORTED_ENCODINGS:
        try:
            return data.decode(detected_encoding), detected_encoding
        except UnicodeDecodeError:
            pass  # デコードに失敗した場合は次の処理に進む

    # XORで暗号化されたデータの場合は、特徴的なパターンを探す
    for pattern, threshold in XOR_PATTERNS:
        # 部分一致する場合もあるため、パターンの一部でも含まれていないか確認
        for i in range(len(pattern)):
            sub_pattern = pattern[i:i+3]  # 3文字以上のパターンで検索
            if len(sub_pattern) < 3:
                continue

            if sub_pattern in data:
                # XOR暗号化されたデータとして扱う
                return xor_analyze(data, pattern), "xor-encrypted"

    # バイナリデータの場合はヘキサダンプを提供
    if detected_encoding == 'binary' or detected_encoding in BINARY_PATTERNS:
        preview_size = min(100, len(data))
        hex_dump = data[:preview_size].hex()
        file_type_msg = f"[{detected_encoding}]" if detected_encoding in BINARY_PATTERNS else ""
        return f"{file_type_msg}[バイナリデータ: {len(data)}バイト] 先頭{preview_size}バイト: {hex_dump}...", "binary"

    # 最終手段として、latin-1でデコード（latin-1はどんなバイナリデータでもデコード可能）
    return data.decode('latin-1', errors='replace'), "latin-1-fallback"


def xor_analyze(data: bytes, possible_pattern: bytes) -> str:
    """
    XOR暗号化されたデータの分析を試みる

    Args:
        data: 分析対象のデータ
        possible_pattern: 可能性のあるパターン

    Returns:
        分析結果のテキスト
    """
    # 簡易解析のみ実施
    preview_size = min(256, len(data))
    hex_dump = data[:preview_size].hex()

    # 正規/非正規キーのいずれかで暗号化されたデータと推測できる場合
    if b'true' in possible_pattern:
        return f"[XOR暗号化データ: 正規キーで復号された可能性あり] {len(data)}バイト\n" \
               f"HEXダンプ: {hex_dump[:100]}..."
    elif b'false' in possible_pattern:
        return f"[XOR暗号化データ: 非正規キーで復号された可能性あり] {len(data)}バイト\n" \
               f"HEXダンプ: {hex_dump[:100]}..."
    elif b'ASCII' in possible_pattern:
        return f"[XOR暗号化データ: ASCIIアートの可能性あり] {len(data)}バイト\n" \
               f"HEXダンプ: {hex_dump[:100]}..."
    else:
        return f"[XOR暗号化データ] {len(data)}バイト\n" \
               f"HEXダンプ: {hex_dump[:100]}..."


def is_readable_text(text: str, threshold: float = 0.9) -> bool:
    """
    テキストが可読か判定

    Args:
        text: 判定対象のテキスト
        threshold: 可読文字の閾値（0.0～1.0）

    Returns:
        可読であればTrue、そうでなければFalse
    """
    if not text:
        return False

    # 空白類文字とASCII可読文字をカウント
    total_chars = len(text)
    readable_chars = sum(1 for c in text if c.isprintable() or c.isspace())

    # 可読文字の割合が閾値以上であれば可読と判定
    return (readable_chars / total_chars) >= threshold


def check_for_common_patterns(data: bytes) -> Tuple[bool, str]:
    """
    データに特定のパターンがあるか確認

    Args:
        data: チェック対象のデータ

    Returns:
        (パターンが見つかったかどうか, パターン説明)
    """
    # 特に多重経路復号で復号された形式を検出

    # ASCIIアートのパターン（多くの空白と記号）
    if b' ' * 10 in data and sum(c in b' *-_|/:.' for c in data[:100]) / min(100, len(data)) > 0.4:
        return True, "ASCIIアート"

    # 日本語（シフトJIS）のパターン
    try:
        text = data.decode('shift-jis', errors='ignore')
        if '不正解' in text or 'うごぁあぁぁぁ' in text or 'ﾉ"′∧∧∧∧' in text:
            return True, "日本語エラーメッセージ"
    except:
        pass

    # JSON形式のパターン
    if data.startswith(b'{') and data.endswith(b'}'):
        try:
            json.loads(data)
            return True, "JSON形式"
        except:
            pass

    return False, ""


def bit_pattern_analysis(data: bytes, block_size: int = 100) -> Tuple[float, str]:
    """
    ビットパターン分析

    Args:
        data: 分析対象のデータ
        block_size: 分析ブロックサイズ

    Returns:
        (エントロピー値, 分析コメント)
    """
    if not data:
        return 0.0, "データなし"

    # 先頭部分のみ分析
    sample = data[:block_size]

    # バイト値の分布を集計
    byte_counts = {}
    for b in sample:
        byte_counts[b] = byte_counts.get(b, 0) + 1

    # シャノンエントロピーの計算
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(sample)
        entropy -= probability * (math.log(probability) / math.log(256))

    # エントロピー値に基づくコメント
    if entropy > 0.95:
        return entropy, "暗号化またはランダムデータの可能性大"
    elif entropy > 0.8:
        return entropy, "圧縮または暗号化されている可能性あり"
    elif entropy > 0.6:
        return entropy, "テキストと非テキストの混合データの可能性"
    else:
        return entropy, "規則性の強いデータまたはテキストの可能性"


def adaptive_decode(data: bytes) -> Tuple[str, str]:
    """
    様々な復号方法を試して最適な方法を選択

    Args:
        data: デコード対象のバイナリデータ

    Returns:
        (デコードされたテキスト, 使用したデコード方法の説明)
    """
    # 特殊パターンの確認
    has_pattern, pattern_desc = check_for_common_patterns(data)
    if has_pattern:
        try:
            # 既知パターンに基づき適切なエンコーディングで復号
            if pattern_desc == "ASCIIアート":
                return data.decode('utf-8', errors='replace'), "ascii-art"
            elif pattern_desc == "日本語エラーメッセージ":
                return data.decode('shift-jis', errors='replace'), "shift-jis"
            elif pattern_desc == "JSON形式":
                json_obj = json.loads(data)
                return json.dumps(json_obj, indent=2, ensure_ascii=False), "json"
        except:
            pass

    # 初期状態：直接デコード試行
    encoding = detect_encoding(data)
    text, method = decode_data(data, encoding)

    # 適切なテキストが得られればそのまま返す
    if is_readable_text(text):
        return text, method

    # Base64デコードの試行
    try:
        decoded = base64.b64decode(data)
        b64_encoding = detect_encoding(decoded)
        b64_text, b64_method = decode_data(decoded, b64_encoding)

        if is_readable_text(b64_text):
            return b64_text, f"base64+{b64_method}"
    except:
        pass

    # UTF-16のBOM有無バリエーションを試す
    for utf16_variant in ['utf-16', 'utf-16-be', 'utf-16-le']:
        try:
            utf16_text = data.decode(utf16_variant)
            if is_readable_text(utf16_text):
                return utf16_text, utf16_variant
        except:
            continue

    # XOR復号の試行（一般的なキーパターンで）
    common_xor_keys = [0x00, 0xFF, 0x55, 0xAA]
    for key in common_xor_keys:
        try:
            xor_data = bytes(b ^ key for b in data)
            xor_encoding = detect_encoding(xor_data)
            if xor_encoding != 'binary':
                xor_text, _ = decode_data(xor_data, xor_encoding)
                if is_readable_text(xor_text):
                    return xor_text, f"xor-{key:02X}+{xor_encoding}"
        except:
            continue

    # JSONのデコードを試行
    if data.startswith(b'{') and data.endswith(b'}'):
        try:
            json_obj = json.loads(data)
            return json.dumps(json_obj, indent=2, ensure_ascii=False), 'json'
        except:
            pass

    # 最終的に最初の結果を返す
    return text, method


def decode_file(file_path: str) -> Tuple[str, str]:
    """
    ファイルを読み込み、適応的にデコード

    Args:
        file_path: デコード対象のファイルパス

    Returns:
        (デコードされたテキスト, 使用したデコード方法)
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        return adaptive_decode(data)
    except Exception as e:
        return f"ファイルの読み込みに失敗しました: {str(e)}", "error"


def main():
    """メイン関数"""
    if len(sys.argv) < 2:
        print("使用方法: python encoding_adapter.py <ファイルパス>")
        sys.exit(1)

    file_path = sys.argv[1]
    decoded_text, method = decode_file(file_path)

    print(f"ファイル: {file_path}")
    print(f"デコード方法: {method}")
    print("=" * 40)
    print(decoded_text)


if __name__ == "__main__":
    main()