#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
エンコーディングアダプタ

バイナリデータを適切なエンコーディングで表示するための変換ユーティリティ
"""

import argparse
import base64
import binascii
import chardet
import json
import os
import re
import sys
from typing import Dict, Tuple, Any, Optional

# バイナリファイルのパターン
BINARY_PATTERNS = {
    'PDF': rb'^%PDF-\d+\.\d+',
    'JPEG': rb'^\xff\xd8\xff',
    'PNG': rb'^\x89PNG\r\n\x1a\n',
    'GIF': rb'^GIF8[79]a',
    'ZIP': rb'^PK\x03\x04',
    'GZIP': rb'^\x1f\x8b\x08',
    'RAR': rb'^Rar!\x1a\x07',
    'TAR': rb'^\x75\x73\x74\x61\x72',
    'EXE': rb'^MZ'
}

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
    'iso-2022-jp',
    'windows-1252',  # 欧米系
    'gbk',           # 中国語
    'big5',          # 繁体字中国語
    'koi8-r'         # ロシア語
]

# 各言語に特徴的な文字パターン（ヒューリスティック検出用）
LANGUAGE_PATTERNS = {
    'jp': (r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FFF]', ['shift-jis', 'euc-jp', 'utf-8']),  # 日本語
    'cn': (r'[\u4E00-\u9FFF]', ['gbk', 'big5', 'utf-8']),  # 中国語
    'kr': (r'[\uAC00-\uD7AF]', ['euc-kr', 'utf-8']),  # 韓国語
    'ru': (r'[\u0400-\u04FF]', ['koi8-r', 'windows-1251', 'utf-8']),  # ロシア語
    'ascii_art': (r'[X\*\-\_\|\/\\:\.]{4,}', ['utf-8', 'ascii']),  # ASCIIアート
}

# リファレンスファイルのキャッシュ
REFERENCE_DATA_CACHE = {}


def detect_encoding(data: bytes) -> str:
    """
    バイナリデータのエンコーディングを検出

    Args:
        data: エンコーディングを検出するバイナリデータ

    Returns:
        検出されたエンコーディング。検出できない場合は 'binary'
    """
    # データサイズが小さすぎる場合はバイナリとみなす
    if len(data) < 8:
        return 'binary'

    # chardetでエンコーディングを検出（信頼度も考慮）
    try:
        result = chardet.detect(data)
        encoding = result['encoding']
        confidence = result['confidence']

        # 特定のエンコーディングでサンプルデコードしてみる
        for enc in ['utf-8', 'shift-jis', 'euc-jp', 'latin-1']:
            try:
                sample = data[:min(100, len(data))].decode(enc)
                # 可読性チェック（制御文字が多すぎないか）
                printable_chars = sum(1 for c in sample if c.isprintable() or c.isspace())
                if printable_chars / len(sample) > 0.8:
                    return enc
            except UnicodeDecodeError:
                pass

        # chardet結果の信頼性が高い場合はその結果を使用
        if encoding and confidence > 0.7:
            return encoding

    except Exception:
        pass

    # エンコーディングを特定できなかった場合はバイナリとみなす
    return 'binary'


def check_for_common_patterns(data: bytes) -> Tuple[bool, str]:
    """
    一般的なパターンを確認

    Args:
        data: 検査対象のバイナリデータ

    Returns:
        (パターン検出結果, パターン説明)
    """
    # ASCIIアートのパターン
    ascii_art_patterns = [
        b'XXXXX',
        b'__--XX--__',
        b'\\    /',
        b'/    \\',
        b'|    |',
    ]

    for pattern in ascii_art_patterns:
        if pattern in data:
            return True, "ASCIIアート"

    # 日本語エラーメッセージのパターン
    jp_error_patterns = [
        b'\xe4\xb8\x8d\xe6\xad\xa3\xe8\xa7\xa3',  # UTF-8 "不正解"
        b'\x95\x73\x90\xb3\x89\xf0',  # Shift-JIS "不正解"
        b'\x82\xa4\x82\xb2\x82\xa9',  # Shift-JIS "うごか" (うごぁっ！)
    ]

    for pattern in jp_error_patterns:
        if pattern in data:
            if b'\xe4\xb8\x8d' in data:
                return True, "日本語エラーメッセージ (UTF-8)"
            else:
                return True, "日本語エラーメッセージ (Shift-JIS)"

    # JSONフォーマットのチェック
    if data.startswith(b'{') and data.endswith(b'}'):
        try:
            json.loads(data)
            return True, "JSON形式"
        except json.JSONDecodeError:
            pass

    return False, ""


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

    # キャッシュしたリファレンスデータを取得または読み込み
    reference_data = {}
    for category, file_path in reference_files.items():
        try:
            if category in REFERENCE_DATA_CACHE:
                ref_data = REFERENCE_DATA_CACHE[category]
            elif os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    ref_data = f.read()
                REFERENCE_DATA_CACHE[category] = ref_data
            else:
                continue

            reference_data[category] = ref_data
        except Exception as e:
            print(f"リファレンスファイル読込エラー: {e}")

    # リファレンスデータがない場合
    if not reference_data:
        return False, "", 0.0

    # 各リファレンスファイルとの類似性を計算
    for category, ref_data in reference_data.items():
        # サイズチェック - あまりにもサイズが違う場合はスキップ
        size_ratio = min(len(data), len(ref_data)) / max(len(data), len(ref_data))
        if size_ratio < 0.3:  # サイズが70%以上違う場合はスキップ
            print(f"サイズ比が小さすぎるためスキップ: {category} ({size_ratio:.2f})")
            continue

        # バイト一致率
        min_len = min(len(data), len(ref_data))
        if min_len > 0:
            # 先頭と末尾のサンプルデータを取得
            sample_size = min(100, min_len // 3)
            head_match = sum(1 for i in range(sample_size) if data[i] == ref_data[i]) / sample_size

            # 中間部のサンプルを取得
            mid_start = min_len // 2 - sample_size // 2
            mid_match = sum(1 for i in range(sample_size) if
                           mid_start + i < min_len and
                           data[mid_start + i] == ref_data[mid_start + i]) / sample_size

            # 末尾部のサンプルを取得
            tail_start = max(0, min_len - sample_size)
            tail_match = sum(1 for i in range(sample_size) if
                           tail_start + i < min_len and
                           data[tail_start + i] == ref_data[tail_start + i]) / sample_size

            # 重み付き平均
            similarity = (head_match * 0.5) + (mid_match * 0.3) + (tail_match * 0.2)

            if similarity > best_similarity:
                best_similarity = similarity
                best_category = category

    # 結果返却
    match_threshold = 0.6  # 類似度の閾値
    if best_similarity >= match_threshold:
        print(f"リファレンス一致: カテゴリ={best_category}, 類似度={best_similarity:.2f}")
        return True, best_category, best_similarity
    else:
        print(f"リファレンス不一致: 最高類似度={best_similarity:.2f}, カテゴリ={best_category}")
        return False, best_category, best_similarity


def is_readable_text(text: str, threshold: float = 0.9) -> bool:
    """
    テキストが人間に読みやすいかどうかを判定

    Args:
        text: 判定対象のテキスト
        threshold: 可読性の閾値 (0.0～1.0)

    Returns:
        読みやすいテキストの場合はTrue
    """
    if not text:
        return False

    # 文字ごとにカウント
    printable_count = sum(1 for c in text if c.isprintable() or c.isspace())

    # 可読文字の割合が閾値以上なら可読とみなす
    ratio = printable_count / len(text)
    return ratio >= threshold


def decode_data(data: bytes, detected_encoding: str = None, metadata: Dict[str, Any] = None) -> Tuple[str, str]:
    """
    データを適切なエンコーディングでデコード

    Args:
        data: デコード対象のバイナリデータ
        detected_encoding: 検出されたエンコーディング（オプション）
        metadata: 追加のメタデータ（オプション）

    Returns:
        (デコードされたテキスト, 使用されたエンコーディング)
    """
    if not data:
        return "", "empty"

    # エンコーディングが指定されていない場合は検出
    encoding = detected_encoding or detect_encoding(data)

    # バイナリデータの場合は人間可読な説明を返す
    if encoding == 'binary':
        return f"[バイナリデータ: {len(data)}バイト]", "binary"

    # Base64エンコーディングの場合はデコード
    if encoding == 'base64':
        try:
            decoded = base64.b64decode(data)
            base64_encoding = detect_encoding(decoded)
            if base64_encoding != 'binary':
                return decoded.decode(base64_encoding, errors='replace'), f"base64+{base64_encoding}"
            else:
                return f"[Base64エンコードされたバイナリデータ: {len(decoded)}バイト]", "base64+binary"
        except:
            pass  # Base64デコードに失敗した場合は次の処理に進む

    # テキストエンコーディングとしてデコード
    try:
        return data.decode(encoding, errors='replace'), encoding
    except UnicodeDecodeError:
        # 最終手段として、latin-1でデコード（latin-1はどんなバイナリデータでもデコード可能）
        return data.decode('latin-1', errors='replace'), 'latin-1-fallback'


def adaptive_decode(data: bytes, metadata: Dict[str, Any] = None) -> Tuple[str, str]:
    """
    様々な復号方法を試して最適な方法を選択

    Args:
        data: デコード対象のバイナリデータ
        metadata: 暗号化ファイルのメタデータ（オプション）

    Returns:
        (デコードされたテキスト, 使用したデコード方法の説明)
    """
    print(f"データサイズ: {len(data)}バイト")

    # エンコーディングヒントがメタデータにあるかチェック
    encoding_hint = None
    if metadata and 'encoding_hint' in metadata:
        encoding_hint = metadata['encoding_hint']
        print(f"メタデータからエンコーディングヒント検出: {encoding_hint}")

    # 1. 特殊パターンの確認
    has_pattern, pattern_desc = check_for_common_patterns(data)
    if has_pattern:
        print(f"特殊パターン検出: {pattern_desc}")
        try:
            # 既知パターンに基づき適切なエンコーディングで復号
            if "ASCIIアート" in pattern_desc:
                text = data.decode('utf-8', errors='replace')
                return text, "ascii-art"
            elif "日本語エラーメッセージ" in pattern_desc:
                if "(UTF-8)" in pattern_desc:
                    text = data.decode('utf-8', errors='replace')
                    return text, "utf-8-japanese"
                else:
                    text = data.decode('shift-jis', errors='replace')
                    return text, "shift-jis"
            elif pattern_desc == "JSON形式":
                json_obj = json.loads(data)
                return json.dumps(json_obj, indent=2, ensure_ascii=False), "json"
        except Exception as e:
            print(f"特殊パターン処理中にエラー: {e}")

    # 2. 標準リファレンスファイルとの比較 (強化版)
    has_match, match_category, similarity = compare_with_reference_files(data)
    if has_match:
        print(f"リファレンスファイル一致: {match_category} (類似度: {similarity:.2f})")

        # リファレンスファイルのパス
        reference_file_path = os.path.join('common', 'true-false-text', f"{match_category}.text")

        # リファレンスファイルを読み込む
        if os.path.exists(reference_file_path):
            try:
                with open(reference_file_path, 'rb') as f:
                    ref_data = f.read()

                # 自動リファレンス適用するか確認
                if similarity >= 0.8:  # 80%以上一致の場合は自動適用
                    print(f"リファレンスファイルを自動適用します: {match_category}")

                    # カテゴリに基づいてエンコーディングを選択
                    if match_category == 'true':
                        return ref_data.decode('utf-8', errors='replace'), "reference-match-true"
                    elif match_category == 'false':
                        return ref_data.decode('shift-jis', errors='replace'), "reference-match-false"
                else:
                    # 類似度が低い場合はXOR解析を試す
                    print(f"リファレンス類似度が低いため元データ解析を継続します: {similarity:.2f}")
            except Exception as e:
                print(f"リファレンスファイル処理中にエラー: {e}")

    # 3. エンコーディングヒントがある場合は優先使用
    if encoding_hint:
        try:
            text = data.decode(encoding_hint, errors='replace')
            if is_readable_text(text, 0.7):
                print(f"エンコーディングヒントによるデコード成功: {encoding_hint}")
                return text, f"metadata-hint:{encoding_hint}"
        except Exception as e:
            print(f"エンコーディングヒントによるデコード失敗: {e}")

    # 4. 一般的なエンコーディング検出
    print("一般的なエンコーディング検出を実行...")
    encoding = detect_encoding(data)
    text, method = decode_data(data, encoding, metadata)

    # 適切なテキストが得られればそのまま返す
    if is_readable_text(text, 0.7):
        print(f"正常にテキストデコード: {method}")
        return text, method

    # 5. Base64デコードの試行
    try:
        print("Base64デコードを試行...")
        decoded = base64.b64decode(data)
        b64_encoding = detect_encoding(decoded)
        b64_text, b64_method = decode_data(decoded, b64_encoding)

        if is_readable_text(b64_text, 0.7):
            print(f"Base64デコード成功: {b64_method}")
            return b64_text, f"base64+{b64_method}"
    except Exception as e:
        print(f"Base64デコード失敗: {e}")

    # 6. UTF-16のBOM有無バリエーションを試す
    for utf16_variant in ['utf-16', 'utf-16-be', 'utf-16-le']:
        try:
            utf16_text = data.decode(utf16_variant)
            if is_readable_text(utf16_text, 0.7):
                print(f"UTF-16バリアントデコード成功: {utf16_variant}")
                return utf16_text, utf16_variant
        except Exception as e:
            print(f"UTF-16バリアント({utf16_variant})デコード失敗: {e}")
            continue

    # 7. XOR復号の試行（一般的なキーパターンで）
    print("XOR復号を試行...")
    common_xor_keys = [0x00, 0xFF, 0x55, 0xAA, 0x33, 0x66, 0x99, 0xCC]
    for key in common_xor_keys:
        try:
            xor_data = bytes(b ^ key for b in data)
            xor_encoding = detect_encoding(xor_data)
            if xor_encoding != 'binary':
                xor_text, _ = decode_data(xor_data, xor_encoding)
                if is_readable_text(xor_text, 0.7):
                    print(f"XOR復号成功: キー=0x{key:02X}, エンコーディング={xor_encoding}")
                    return xor_text, f"xor-{key:02X}+{xor_encoding}"
        except Exception as e:
            print(f"XOR復号失敗(キー=0x{key:02X}): {e}")
            continue

    # 8. JSONのデコードを試行
    if data.startswith(b'{') and data.endswith(b'}'):
        try:
            json_obj = json.loads(data)
            print("JSON解析成功")
            return json.dumps(json_obj, indent=2, ensure_ascii=False), 'json'
        except Exception as e:
            print(f"JSON解析失敗: {e}")

    # 9. 一般的なバイナリファイルパターンの確認
    for file_type, pattern in BINARY_PATTERNS.items():
        if re.match(pattern, data[:20]):
            print(f"バイナリファイルタイプ検出: {file_type}")
            return f"[{file_type}ファイル: {len(data)}バイト]", file_type

    # 10. 最終的に最初の結果を返す
    print(f"他の方法で解析できず、初期解析結果を使用: {method}")
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

    # リファレンスファイルとの比較処理
    if args.reference:
        from_reference = True

        print(f"ファイル: {args.file_path}")
        print("リファレンスファイルとの比較を実行中...")

        reference_files = {
            'true': os.path.join('common', 'true-false-text', 'true.text'),
            'false': os.path.join('common', 'true-false-text', 'false.text')
        }

        try:
            with open(args.file_path, 'rb') as f:
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

            # 結果の表示と保存
            if best_similarity > 0.7:
                print(f"最適一致: {best_category} (類似度: {best_similarity:.2f})")

                # 出力ファイルへの保存
                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(best_match)
                    print(f"リファレンスデータを '{args.output}' に保存しました")

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
                with open(args.file_path, 'rb') as f:
                    data = f.read()

                # 指定エンコーディングでデコード
                text = data.decode(args.force_text, errors='replace')

                print(f"ファイル: {args.file_path}")
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
                decoded_text, method = decode_file(args.file_path)

                print(f"ファイル: {args.file_path}")
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
            decoded_text, method = decode_file(args.file_path)

            print(f"ファイル: {args.file_path}")
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
