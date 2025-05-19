#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
import hashlib
import argparse
import re
from typing import Dict, List, Union, Tuple, Any, Optional

# シンプルなPaillier暗号実装
class SimplePaillierCrypto:
    def __init__(self, key=None):
        self.public_key = {}
        self.private_key = {}

        # 鍵ファイルがあれば読み込む
        if os.path.exists('keys/paillier_public.json'):
            with open('keys/paillier_public.json', 'r') as f:
                self.public_key = json.load(f)

        if os.path.exists('keys/paillier_private.json'):
            with open('keys/paillier_private.json', 'r') as f:
                self.private_key = json.load(f)

    def decrypt(self, encrypted_value: int) -> int:
        """Paillier暗号による復号"""
        # Private key parameters
        if not self.private_key:
            raise ValueError("秘密鍵がロードされていません")

        n = int(self.private_key['n'])
        lambda_val = int(self.private_key['lambda'])
        mu = int(self.private_key['mu'])
        n_squared = n * n

        # Step 1: L(c^lambda mod n^2)
        c_lambda_mod = pow(encrypted_value, lambda_val, n_squared)
        l_val = (c_lambda_mod - 1) // n

        # Step 2: L(c^lambda mod n^2) * mu mod n
        decrypted = (l_val * mu) % n

        return decrypted

    def apply_linear_mask(self, value: int, mask_params: Dict[str, Any], inverse: bool = False) -> int:
        """線形マスクを適用または除去"""
        if mask_params.get('type') != 'linear':
            raise ValueError(f"未対応のマスクタイプ: {mask_params.get('type')}")

        coefficient = int(mask_params.get('coefficient', 1))
        constant = int(mask_params.get('constant', 0))

        if inverse:
            # マスクの除去（逆変換）: (value - constant) / coefficient
            inv_coef = pow(coefficient, -1, int(self.private_key['n']))
            return ((value - constant) * inv_coef) % int(self.private_key['n'])
        else:
            # マスクの適用: value * coefficient + constant
            return (value * coefficient + constant) % int(self.private_key['n'])

def parse_chunk(chunk_data: str) -> int:
    """チャンクデータ（大きな整数文字列）をintに変換"""
    return int(chunk_data)

def try_different_decodings(data: bytes, verbose=False) -> Union[str, bytes]:
    """様々なデコード方法を試してみる"""
    if verbose:
        print(f"様々なデコードを試行中... データ長: {len(data)}バイト")
        print(f"データ先頭: {data[:20]}")

    # 直接UTF-8デコードを試みる
    try:
        result = data.decode('utf-8')
        if verbose:
            print("UTF-8デコードに成功")
        return result
    except UnicodeDecodeError:
        if verbose:
            print("UTF-8デコードに失敗")

    # Base64デコードを試みる
    try:
        decoded = base64.b64decode(data)
        try:
            result = decoded.decode('utf-8')
            if verbose:
                print("Base64 + UTF-8デコードに成功")
            return result
        except UnicodeDecodeError:
            if verbose:
                print("Base64デコードに成功したがUTF-8デコードは失敗")
    except Exception:
        if verbose:
            print("Base64デコードに失敗")

    # Base64エンコードされたUTF-8の部分のみを探す
    base64_pattern = rb'[A-Za-z0-9+/=]+'
    matches = re.findall(base64_pattern, data)
    for match in matches:
        if len(match) > 20:  # 十分な長さのBase64文字列のみ試す
            try:
                decoded = base64.b64decode(match)
                try:
                    result = decoded.decode('utf-8')
                    if verbose:
                        print(f"見つかったBase64パターン '{match[:20]}...' のデコードに成功")
                    return result
                except UnicodeDecodeError:
                    pass
            except Exception:
                pass

    # TEXTマーカーがあるか探す
    text_marker = b'TEXT:UTF8:'
    if text_marker in data:
        if verbose:
            print("TEXTマーカーを発見")
        start_idx = data.find(text_marker) + len(text_marker)
        try:
            base64_data = data[start_idx:]
            decoded = base64.b64decode(base64_data)
            result = decoded.decode('utf-8')
            if verbose:
                print("TEXT:UTF8: マーカー以降のBase64 + UTF-8デコードに成功")
            return result
        except Exception as e:
            if verbose:
                print(f"TEXTマーカー以降のデコードに失敗: {e}")

    # ダメ押しでLatin-1エンコーディングを試す
    try:
        result = data.decode('latin-1')
        if verbose:
            print("Latin-1デコードに成功")
        return result
    except Exception:
        if verbose:
            print("Latin-1デコードに失敗")

    # バイナリファイルと判断
    if verbose:
        print("すべてのデコードに失敗。バイナリデータとして扱います")
    return data

def process_decrypted_data(decrypted_bytes, metadata, verbose=False):
    """復号化されたデータを処理"""
    if verbose:
        print(f"復号されたデータ先頭: {decrypted_bytes[:20]} (長さ: {len(decrypted_bytes)}バイト)")

    # UTF-8エンコードされたデータを識別
    prefix = b'TEXT:UTF8:'
    if decrypted_bytes.startswith(prefix):
        base64_data = decrypted_bytes[len(prefix):]
        try:
            # Base64デコード
            decoded_data = base64.b64decode(base64_data)
            if verbose:
                print(f"Base64デコード後: {len(decoded_data)}バイト")

            # UTF-8デコード
            text_data = decoded_data.decode('utf-8')
            return text_data
        except Exception as e:
            if verbose:
                print(f"テキストデコードエラー: {e}")

    # JSON形式データを識別
    prefix = b'JSON:UTF8:'
    if decrypted_bytes.startswith(prefix):
        base64_data = decrypted_bytes[len(prefix):]
        try:
            # Base64デコード
            decoded_data = base64.b64decode(base64_data)
            if verbose:
                print(f"Base64デコード後: {len(decoded_data)}バイト")

            # UTF-8デコード
            text_data = decoded_data.decode('utf-8')
            return text_data
        except Exception as e:
            if verbose:
                print(f"JSONデコードエラー: {e}")

    # CSV形式データを識別
    prefix = b'CSV:UTF8:'
    if decrypted_bytes.startswith(prefix):
        base64_data = decrypted_bytes[len(prefix):]
        try:
            # Base64デコード
            decoded_data = base64.b64decode(base64_data)
            if verbose:
                print(f"Base64デコード後: {len(decoded_data)}バイト")

            # UTF-8デコード
            text_data = decoded_data.decode('utf-8')
            return text_data
        except Exception as e:
            if verbose:
                print(f"CSVデコードエラー: {e}")

    # その他の場合：さまざまなデコード方法を試す
    return try_different_decodings(decrypted_bytes, verbose)

def int_to_bytes(n: int) -> bytes:
    """大きな整数をバイト列に変換"""
    # 整数のバイナリ表現の長さを計算
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')

def decrypt_file(encrypted_file: str, key: str, output_file: str, key_type: str = 'auto', verbose: bool = False):
    """暗号化ファイルを復号する"""
    print(f"ファイル復号を開始: {encrypted_file}")
    print(f"キータイプ: {key_type}")

    try:
        # 暗号化ファイルを読み込む
        with open(encrypted_file, 'r', encoding='utf-8') as f:
            encrypted_data = json.load(f)

        # 最初に基本情報を表示
        if verbose:
            print(f"フォーマット: {encrypted_data.get('format')}")
            print(f"バージョン: {encrypted_data.get('version')}")
            print(f"アルゴリズム: {encrypted_data.get('algorithm')}")
            print(f"真ファイル名: {encrypted_data.get('true_filename')}")
            print(f"偽ファイル名: {encrypted_data.get('false_filename')}")

        # キータイプが自動の場合、ハッシュに基づいて決定
        if key_type == 'auto':
            key_bytes = bytes.fromhex(key) if len(key) == 64 else key.encode('utf-8')
            key_hash = hashlib.sha256(key_bytes).digest()[0]
            key_type = 'true' if key_hash % 2 == 0 else 'false'
            if verbose:
                print(f"自動キータイプ決定: {key_type}")

        # チャンク情報を取得
        if key_type == 'true':
            chunks = encrypted_data.get('true_chunks', [])
            mask_params = encrypted_data.get('mask', {}).get('true_mask', {})
            metadata = encrypted_data.get('metadata', {}).get('true', {})
        else:
            chunks = encrypted_data.get('false_chunks', [])
            mask_params = encrypted_data.get('mask', {}).get('false_mask', {})
            metadata = encrypted_data.get('metadata', {}).get('false', {})

        if not chunks:
            print("警告: 復号するチャンクが見つかりません")
            return None

        if verbose:
            print(f"マスク情報: {mask_params}")
            print(f"チャンク数: {len(chunks)}")

        # Paillier暗号オブジェクトの初期化
        crypto = SimplePaillierCrypto()

        # 各チャンクを復号
        decrypted_chunks = []
        for i, chunk in enumerate(chunks):
            if verbose:
                print(f"チャンク {i+1}/{len(chunks)} 復号中...")

            # チャンクをintに変換
            chunk_int = parse_chunk(chunk)

            # Paillier暗号で復号
            decrypted_value = crypto.decrypt(chunk_int)

            # マスクを除去
            unmasked_value = crypto.apply_linear_mask(decrypted_value, mask_params, inverse=True)

            # バイト列に変換
            decrypted_bytes = int_to_bytes(unmasked_value)

            decrypted_chunks.append(decrypted_bytes)

        # チャンクを結合
        combined_data = b''.join(decrypted_chunks)

        # 復号化されたデータを処理
        result = process_decrypted_data(combined_data, metadata, verbose)

        # 結果を出力ファイルに書き込む
        if isinstance(result, str):
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result)
            if verbose:
                print(f"テキストとして出力: {output_file}")
        else:
            with open(output_file, 'wb') as f:
                f.write(result)
            if verbose:
                print(f"バイナリとして出力: {output_file}")

        print(f"復号が完了しました: {output_file}")
        print(f"データタイプ: {'テキスト' if isinstance(result, str) else 'バイナリ'}")
        print(f"データサイズ: {len(result)} バイト")

        return result

    except Exception as e:
        print(f"エラー: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    parser = argparse.ArgumentParser(description='Paillier暗号化ファイルの復号ツール')
    parser.add_argument('encrypted_file', help='復号する暗号化ファイルのパス')
    parser.add_argument('--key', required=True, help='16進数形式の復号鍵')
    parser.add_argument('--key-type', choices=['true', 'false', 'auto'], default='auto',
                        help='復号するデータタイプ (true/false/auto)')
    parser.add_argument('--output', '-o', required=True, help='出力先ファイルパス')
    parser.add_argument('--verbose', '-v', action='store_true', help='詳細な出力を表示')

    args = parser.parse_args()

    # ファイルの復号を実行
    decrypt_file(
        args.encrypted_file,
        args.key,
        args.output,
        args.key_type,
        args.verbose
    )

if __name__ == "__main__":
    main()