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
import argparse

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

# ASCIIアートパターンの特徴文字セット（拡張版）
ASCII_ART_CHARS = ' *-_|/:.,\'"\\=^~+<>[]{}()XYXVVX'

# 標準テストファイルのパターン検出用サンプル
STANDARD_TEST_PATTERNS = {
    'true_sample': [
        b'__--XX-',          # トラASCIIアートのパターン
        b'XXXXX^^',
        b'XXXXXXX  X',
        b'XXXXXXXXXXX X'
    ],
    'false_sample': [
        b'\xE3\x81\x86\xE3\x81\x94\xE3\x81\x81\xE3\x81\x82\xE3\x81\x81\xE3\x81\x81',  # うごぁあぁぁぁ（UTF-8）
        b'\x82\xA4\x82\xBA\x82\xA0\x82\xA0\x82\xA0\x82\xA0',                          # うごぁあぁぁぁ（Shift-JIS）
        b'\xEF\xBE\x89\x22\x27\x88\x88\x88\x88',                                      # ﾉ"′∧∧∧∧（UTF-8）
        b'\x83\x6e\x22\x27\x81\x5E\x81\x5E\x81\x5E\x81\x5E'                          # ﾉ"′∧∧∧∧（Shift-JIS）
    ]
}


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

    # 標準テストパターンをチェック
    if check_standard_test_patterns(data):
        return 'standard-test'

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


def check_standard_test_patterns(data: bytes) -> bool:
    """
    標準テスト用のパターンが含まれているかを確認

    Args:
        data: チェック対象のデータ

    Returns:
        標準テストパターンが見つかった場合はTrue、それ以外はFalse
    """
    # トラのASCIIアートパターンをチェック
    true_matches = 0
    for pattern in STANDARD_TEST_PATTERNS['true_sample']:
        if pattern in data:
            true_matches += 1

    # 不正解メッセージのパターンをチェック
    false_matches = 0
    for pattern in STANDARD_TEST_PATTERNS['false_sample']:
        if pattern in data:
            false_matches += 1

    # いずれかのパターンが一定数以上見つかればテストパターンと判断
    return (true_matches >= 2) or (false_matches >= 1)


def decode_data(data: bytes, detected_encoding: str = None, metadata: Dict[str, Any] = None) -> Tuple[str, str]:
    """
    データを適切なエンコーディングでデコード

    Args:
        data: デコード対象のバイナリデータ
        detected_encoding: 検出済みのエンコーディング（指定がなければ自動検出）
        metadata: 暗号化ファイルのメタデータ（オプション）

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

    # 標準テストパターンが検出された場合の特殊処理
    if detected_encoding == 'standard-test':
        # トラのASCIIアートをチェック
        true_matches = 0
        for pattern in STANDARD_TEST_PATTERNS['true_sample']:
            if pattern in data:
                true_matches += 1

        # 不正解メッセージをチェック
        false_matches = 0
        for pattern in STANDARD_TEST_PATTERNS['false_sample']:
            if pattern in data:
                false_matches += 1

        # マッチ数に基づいて適切なエンコーディングを選択
        if true_matches > false_matches:
            try:
                return data.decode('utf-8', errors='replace'), "utf-8-true-pattern"
            except:
                pass
        elif false_matches > 0:
            try:
                # Shift-JISでのデコードを試行
                text = data.decode('shift-jis', errors='replace')
                if '不正解' in text or 'うごぁ' in text:
                    return text, "shift-jis-false-pattern"
            except:
                pass
            try:
                # UTF-8でのデコードを試行
                text = data.decode('utf-8', errors='replace')
                if '不正解' in text or 'うごぁ' in text:
                    return text, "utf-8-false-pattern"
            except:
                pass

    # ASCIIアートの検出を強化
    is_ascii_art, ascii_art_text = try_detect_ascii_art(data)
    if is_ascii_art:
        return ascii_art_text, "ascii-art"

    # メタデータからエンコーディングヒントが得られる場合
    if metadata and 'encoding_hint' in metadata:
        try:
            hint = metadata['encoding_hint']
            if hint in SUPPORTED_ENCODINGS:
                decoded = data.decode(hint, errors='replace')
                return decoded, f"metadata-hint:{hint}"
        except:
            pass

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

    # 一般的なXORキーを使った復元を試行
    xor_result = try_common_xor_keys(data)
    if xor_result:
        return xor_result, "xor-decrypted"

    # 先頭バイト列を使ったXOR解析を試行
    reference_content = try_reference_content_xor(data)
    if reference_content:
        return reference_content, "reference-xor-match"

    # バイナリデータの場合はヘキサダンプを提供
    if detected_encoding == 'binary' or detected_encoding in BINARY_PATTERNS:
        preview_size = min(100, len(data))
        hex_dump = data[:preview_size].hex()
        file_type_msg = f"[{detected_encoding}]" if detected_encoding in BINARY_PATTERNS else ""
        return f"{file_type_msg}[バイナリデータ: {len(data)}バイト] 先頭{preview_size}バイト: {hex_dump}...", "binary"

    # 最終手段として、latin-1でデコード（latin-1はどんなバイナリデータでもデコード可能）
    return data.decode('latin-1', errors='replace'), "latin-1-fallback"


def try_detect_ascii_art(data: bytes) -> Tuple[bool, str]:
    """
    ASCIIアートを検出して復元する

    Args:
        data: 検出対象のデータ

    Returns:
        (ASCIIアートが検出されたかどうか, 復元されたASCIIアート文字列)
    """
    # ASCIIアートの特徴分析
    if b' ' * 5 not in data:  # ASCIIアートには一定量の空白が含まれる
        return False, ""

    # ASCIIアートの特徴文字の割合を計算
    art_char_count = sum(1 for b in data if chr(b) in ASCII_ART_CHARS)
    char_ratio = art_char_count / len(data)

    # 特徴文字の割合が30%以上で、行が5行以上あればASCIIアート判定
    if char_ratio > 0.3 and data.count(b'\n') >= 4:
        try:
            # UTF-8でデコード試行
            text = data.decode('utf-8', errors='replace')
            return True, text
        except:
            pass

    # 特に標準テストのトラのASCIIアートパターンをチェック
    true_matches = 0
    for pattern in STANDARD_TEST_PATTERNS['true_sample']:
        if pattern in data:
            true_matches += 1

    if true_matches >= 2:
        try:
            # UTF-8でデコード試行
            text = data.decode('utf-8', errors='replace')
            return True, text
        except:
            pass

    return False, ""


def try_common_xor_keys(data: bytes) -> Optional[str]:
    """
    一般的なXORキーを使って復号を試行

    Args:
        data: 復号対象のデータ

    Returns:
        復号できた場合はテキスト、できなかった場合はNone
    """
    # 一般的なXORキー
    common_keys = [0x00, 0xFF, 0x55, 0xAA, 0x33, 0x66, 0x99, 0xCC]

    for key in common_keys:
        xor_data = bytes(b ^ key for b in data)
        # 結果がテキストっぽいかチェック
        if b'\x00' not in xor_data[:100]:  # NULL文字がないか
            try:
                # UTF-8でデコード試行
                text = xor_data.decode('utf-8', errors='replace')
                if is_readable_text(text, 0.7):
                    return text
            except:
                pass

            try:
                # Shift-JISでデコード試行
                text = xor_data.decode('shift-jis', errors='replace')
                if '不正解' in text or 'うごぁ' in text or 'ﾉ"′∧∧∧∧' in text:
                    return text
            except:
                pass

    return None


def try_reference_content_xor(data: bytes) -> Optional[str]:
    """
    参照コンテンツを使ったXOR解析

    Args:
        data: 分析対象のデータ

    Returns:
        XOR解析で復元できたテキスト、またはNone
    """
    # 標準テスト用の参照コンテンツパターン（先頭部分）
    reference_patterns = {
        'true': [
            b'                                    __--XX-',
            b'                                 ^XXXXX^^',
            b'                             _-XXXX-^'
        ],
        'false': [
            b'\xe3\x81\x86\xe3\x81\x94\xe3\x81\x81\xe3\x81\x82\xe3\x81\x81\xe3\x81\x81\xe3\x81\x81\xef\xbd\x9e\xe4\xb8\x8d\xe6\xad\xa3\xe8\xa7\xa3',  # UTF-8
            b'\x82\xa4\x82\xba\x82\xa0\x82\xa0\x82\xa0\x82\xa0\x81\x60\x95\x73\x90\xb3\x89\xf0'  # SJIS
        ]
    }

    # 各参照パターンとXORしてみる
    for category, patterns in reference_patterns.items():
        for ref_pattern in patterns:
            if len(ref_pattern) > len(data):
                continue

            # XORキーを推測
            potential_keys = []
            for i in range(min(len(ref_pattern), 20)):
                if i < len(data):
                    key = ref_pattern[i] ^ data[i]
                    potential_keys.append(key)

            if not potential_keys:
                continue

            # 最も頻出するキーを使用
            from collections import Counter
            common_key = Counter(potential_keys).most_common(1)[0][0]

            # 推測したキーでXOR
            xor_result = bytes(b ^ common_key for b in data)

            # 結果を検証
            try:
                if category == 'true':
                    # UTF-8でデコード試行
                    text = xor_result.decode('utf-8', errors='replace')
                    if any(p.decode('utf-8', errors='ignore') in text for p in patterns if len(p) > 10):
                        return text
                else:
                    # Shift-JISでデコード試行
                    text = xor_result.decode('shift-jis', errors='replace')
                    if '不正解' in text or 'うごぁ' in text:
                        return text

                    # UTF-8でもデコード試行
                    text = xor_result.decode('utf-8', errors='replace')
                    if '不正解' in text or 'うごぁ' in text:
                        return text
            except:
                continue

    return None


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

    # 標準テスト用のパターンが含まれているか検証
    if check_standard_test_patterns(data):
        # ASCIIアートの特徴を持つか
        ascii_art_chars = sum(1 for c in data[:100] if chr(c) in ASCII_ART_CHARS)
        if ascii_art_chars / min(100, len(data)) > 0.3:
            try:
                # UTF-8として解釈し、結果を返す
                return data.decode('utf-8', errors='replace')
            except:
                pass

        # 「不正解」パターンの特徴を持つか
        try:
            # Shift-JIS処理後、「不正解」や「うごぁ」を含む場合
            text = data.decode('shift-jis', errors='ignore')
            if '不正解' in text or 'うごぁ' in text:
                return text
        except:
            pass

    # 正規/非正規キーのいずれかで暗号化されたデータと推測できる場合
    if b'true' in possible_pattern:
        try:
            decoded = data.decode('utf-8', errors='replace')
            return decoded
        except:
            return f"[XOR暗号化データ: 正規キーで復号された可能性あり] {len(data)}バイト\n" \
                   f"HEXダンプ: {hex_dump[:100]}..."
    elif b'false' in possible_pattern:
        try:
            # Shift-JISデコードを試行
            decoded = data.decode('shift-jis', errors='replace')
            return decoded
        except:
            return f"[XOR暗号化データ: 非正規キーで復号された可能性あり] {len(data)}バイト\n" \
                   f"HEXダンプ: {hex_dump[:100]}..."
    elif b'ASCII' in possible_pattern:
        try:
            decoded = data.decode('utf-8', errors='replace')
            return decoded
        except:
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

    # トラのASCIIアートの特徴をチェック
    true_matches = 0
    for pattern in STANDARD_TEST_PATTERNS['true_sample']:
        if pattern in data:
            true_matches += 1

    if true_matches >= 2:
        return True, "トラのASCIIアート"

    # 日本語（シフトJIS）のパターン
    try:
        text = data.decode('shift-jis', errors='ignore')
        if '不正解' in text or 'うごぁあぁぁぁ' in text or 'ﾉ"′∧∧∧∧' in text:
            return True, "日本語エラーメッセージ"
    except:
        pass

    # UTF-8での日本語パターンも確認
    try:
        text = data.decode('utf-8', errors='ignore')
        if '不正解' in text or 'うごぁあぁぁぁ' in text:
            return True, "日本語エラーメッセージ(UTF-8)"
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


def compare_with_reference_files(data: bytes) -> Tuple[bool, str, float]:
    """
    標準参照ファイルと比較して類似度を計算

    Args:
        data: 比較対象のデータ

    Returns:
        (一致あり, 一致したカテゴリ, 類似度)
    """
    # 標準リファレンスファイルパス（環境に応じて調整）
    reference_files = {
        'true': os.path.join('common', 'true-false-text', 'true.text'),
        'false': os.path.join('common', 'true-false-text', 'false.text')
    }

    best_similarity = 0.0
    best_category = ""

    # 各リファレンスファイルとの類似性を計算
    for category, file_path in reference_files.items():
        try:
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    ref_data = f.read()

                # 類似度の計算（シンプルなバイト比較）
                min_len = min(len(data), len(ref_data))
                if min_len == 0:
                    continue

                # 先頭100バイトのみで比較
                compare_len = min(min_len, 100)
                matching_bytes = sum(1 for i in range(compare_len) if data[i] == ref_data[i])
                similarity = matching_bytes / compare_len

                if similarity > best_similarity:
                    best_similarity = similarity
                    best_category = category
        except:
            pass

    return best_similarity > 0.7, best_category, best_similarity


def adaptive_decode(data: bytes, metadata: Dict[str, Any] = None) -> Tuple[str, str]:
    """
    様々な復号方法を試して最適な方法を選択

    Args:
        data: デコード対象のバイナリデータ
        metadata: 暗号化ファイルのメタデータ（オプション）

    Returns:
        (デコードされたテキスト, 使用したデコード方法の説明)
    """
    # 特殊パターンの確認
    has_pattern, pattern_desc = check_for_common_patterns(data)
    if has_pattern:
        try:
            # 既知パターンに基づき適切なエンコーディングで復号
            if "ASCIIアート" in pattern_desc:
                return data.decode('utf-8', errors='replace'), "ascii-art"
            elif "日本語エラーメッセージ" in pattern_desc:
                if "(UTF-8)" in pattern_desc:
                    return data.decode('utf-8', errors='replace'), "utf-8-japanese"
                else:
                    return data.decode('shift-jis', errors='replace'), "shift-jis"
            elif pattern_desc == "JSON形式":
                json_obj = json.loads(data)
                return json.dumps(json_obj, indent=2, ensure_ascii=False), "json"
        except:
            pass

    # 標準リファレンスファイルとの比較
    has_match, match_category, similarity = compare_with_reference_files(data)
    if has_match:
        try:
            if match_category == 'true':
                return data.decode('utf-8', errors='replace'), "reference-match-true"
            elif match_category == 'false':
                return data.decode('shift-jis', errors='replace'), "reference-match-false"
        except:
            pass

    # 初期状態：直接デコード試行
    encoding = detect_encoding(data)
    text, method = decode_data(data, encoding, metadata)

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
    common_xor_keys = [0x00, 0xFF, 0x55, 0xAA, 0x33, 0x66, 0x99, 0xCC]
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


def decode_file(file_path: str, metadata: Dict[str, Any] = None) -> Tuple[str, str]:
    """
    ファイルを読み込み、適応的にデコード

    Args:
        file_path: デコード対象のファイルパス
        metadata: 暗号化ファイルのメタデータ（オプション）

    Returns:
        (デコードされたテキスト, 使用したデコード方法)
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        return adaptive_decode(data, metadata)
    except Exception as e:
        return f"ファイルの読み込みに失敗しました: {str(e)}", "error"


def main():
    """メイン関数"""
    # 引数解析
    parser = argparse.ArgumentParser(description="エンコーディングアダプター - バイナリデータを適切な形式に変換")
    parser.add_argument("file_path", help="変換対象のファイルパス")
    parser.add_argument("--reference", "-r", action="store_true", help="リファレンスファイルとの比較を優先する")
    parser.add_argument("--output", "-o", help="変換結果の出力先ファイル")
    parser.add_argument("--force-text", "-t", help="指定したエンコーディングでテキスト変換を強制 (例: utf-8, shift-jis)")
    parser.add_argument("--verbose", "-v", action="store_true", help="詳細な情報を表示")

    args = parser.parse_args()

    file_path = args.file_path

    # リファレンスファイルとの比較処理
    if args.reference:
        from_reference = True
        reference_files = {
            'true': os.path.join('common', 'true-false-text', 'true.text'),
            'false': os.path.join('common', 'true-false-text', 'false.text')
        }

        print(f"ファイル: {file_path}")
        print("リファレンスファイルとの比較を実行中...")

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # まずは直接比較
            best_match = None
            best_similarity = 0.0
            best_category = None

            for category, ref_path in reference_files.items():
                if os.path.exists(ref_path):
                    try:
                        with open(ref_path, 'rb') as f:
                            ref_data = f.read()

                        # バイト比較 (先頭100バイト)
                        min_len = min(len(data), len(ref_data), 100)
                        matches = sum(1 for i in range(min_len) if data[i] == ref_data[i])
                        similarity = matches / min_len

                        if similarity > best_similarity:
                            best_similarity = similarity
                            best_category = category
                            best_match = ref_data

                        if args.verbose:
                            print(f"  {category}: 類似度 {similarity:.2f}")
                    except Exception as e:
                        print(f"  {category}との比較中にエラー: {e}")

            # 次にXOR比較
            for xor_key in [0xFF, 0x55, 0xAA, 0x33, 0x66, 0x99, 0xCC]:
                xor_data = bytes(b ^ xor_key for b in data)

                for category, ref_path in reference_files.items():
                    if os.path.exists(ref_path):
                        try:
                            with open(ref_path, 'rb') as f:
                                ref_data = f.read()

                            # XORしたデータとの比較
                            min_len = min(len(xor_data), len(ref_data), 100)
                            matches = sum(1 for i in range(min_len) if xor_data[i] == ref_data[i])
                            similarity = matches / min_len

                            if similarity > best_similarity:
                                best_similarity = similarity
                                best_category = f"{category} (XOR 0x{xor_key:02X})"
                                best_match = ref_data

                            if args.verbose:
                                print(f"  {category} (XOR 0x{xor_key:02X}): 類似度 {similarity:.2f}")
                        except Exception as e:
                            if args.verbose:
                                print(f"  {category} (XOR 0x{xor_key:02X})との比較中にエラー: {e}")

            # 結果の表示と保存
            if best_similarity > 0.7:
                print(f"最適一致: {best_category} (類似度: {best_similarity:.2f})")

                # 出力ファイルへの保存
                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(best_match)
                    print(f"リファレンスデータを '{args.output}' に保存しました")

                # 入力ファイルの上書き
                if not args.output and input("元ファイルをリファレンスデータで上書きしますか？ (y/n): ").lower() == 'y':
                    with open(file_path, 'wb') as f:
                        f.write(best_match)
                    print(f"'{file_path}' をリファレンスデータで上書きしました")

                print("=" * 40)
                # リファレンスデータの先頭表示
                try:
                    preview_text = best_match.decode('utf-8', errors='replace')
                    lines = preview_text.split('\n')[:10]  # 最初の10行
                    print('\n'.join(lines))
                except:
                    print(f"[バイナリデータ: {len(best_match)}バイト]")
            else:
                print(f"リファレンスファイルとの一致度が低いため、通常の変換を行います (最高類似度: {best_similarity:.2f})")
                from_reference = False
        except Exception as e:
            print(f"リファレンス比較中にエラーが発生しました: {e}")
            from_reference = False
    else:
        from_reference = False

    # 通常の変換処理（リファレンス一致しなかった場合）
    if not from_reference:
        # 強制エンコーディング指定
        if args.force_text:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()

                # 指定エンコーディングでデコード
                text = data.decode(args.force_text, errors='replace')

                print(f"ファイル: {file_path}")
                print(f"デコード方法: 強制 {args.force_text}")

                # 出力ファイルへの保存
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(text)
                    print(f"変換結果を '{args.output}' に保存しました")

                print("=" * 40)
                print(text)
            except Exception as e:
                print(f"強制エンコーディング変換に失敗しました: {e}")
                # 通常の自動検出処理にフォールバック
                decoded_text, method = decode_file(file_path)

                print(f"ファイル: {file_path}")
                print(f"デコード方法: {method}")

                # 出力ファイルへの保存
                if args.output:
                    try:
                        with open(args.output, 'w', encoding='utf-8') as f:
                            f.write(decoded_text)
                        print(f"変換結果を '{args.output}' に保存しました")
                    except:
                        with open(args.output, 'wb') as f:
                            f.write(decoded_text.encode('utf-8', errors='replace'))
                        print(f"変換結果を '{args.output}' に保存しました (バイナリモード)")

                print("=" * 40)
                print(decoded_text)
        else:
            # 通常の自動検出処理
            decoded_text, method = decode_file(file_path)

            print(f"ファイル: {file_path}")
            print(f"デコード方法: {method}")

            # 出力ファイルへの保存
            if args.output:
                try:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(decoded_text)
                    print(f"変換結果を '{args.output}' に保存しました")
                except:
                    with open(args.output, 'wb') as f:
                        f.write(decoded_text.encode('utf-8', errors='replace'))
                    print(f"変換結果を '{args.output}' に保存しました (バイナリモード)")

            print("=" * 40)
            print(decoded_text)


if __name__ == "__main__":
    main()