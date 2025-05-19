#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式 - 修正版復号プログラム

エンコーディング問題を修正し、UTF-8テキストの復号に特化した修正版です。
"""

import os
import sys
import json
import base64
import binascii
import hashlib
import random
import time
import argparse
import uuid
import traceback
from typing import Dict, List, Any, Tuple, Optional, Union

# 鍵解析関数
def analyze_key_type(key_data: Dict[str, Any]) -> str:
    """鍵の種類を解析"""
    # パラメータを取得
    parameters = key_data.get("parameters", {})
    if not parameters:
        parameters = key_data

    a = parameters.get("a")
    p = parameters.get("p")
    q = parameters.get("q")

    # 数学的特性による判定
    if p and q:
        if p > q:
            return "b"
        else:
            return "a"

    # フォールバック: uuidから判定
    uuid_str = key_data.get("uuid", "")
    if uuid_str:
        uuid_hash = hashlib.sha256(uuid_str.encode()).digest()[0]
        return "a" if uuid_hash % 2 == 0 else "b"

    # 最終フォールバック
    return "a"

# 準同型マスク除去関数
def remove_homomorphic_mask(data: bytes, key_data: Dict[str, Any]) -> bytes:
    """準同型マスクを除去"""
    # パラメータを取得
    parameters = key_data.get("parameters", key_data)
    a = parameters.get("a", 1)
    b = parameters.get("b", 0)
    n = parameters.get("n", 256)

    # マスク除去用のシード値を設定
    seed_value = (a * 12345 + b) % n
    random.seed(seed_value)

    # マスクの生成
    mask = bytearray(len(data))
    for i in range(len(data)):
        position_seed = (a * i + b) % n
        mask_value = (position_seed * random.randint(1, 255)) % 256
        mask[i] = mask_value

    # マスクの除去
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] - mask[i % len(mask)] + 256) % 256

    return bytes(result)

# Base64デコードの強化版
def safe_base64_decode(data: bytes) -> bytes:
    """Base64デコードの強化版（パディングや無効文字に対応）"""
    try:
        # パディング補正（必要なら）
        if len(data) % 4 != 0:
            # 足りないパディングを追加
            padding = b'=' * (4 - len(data) % 4)
            data = data + padding

        # 標準的なBase64デコード
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        print(f"Base64デコードでエラー: {e}")
        # 非標準のパディングを処理
        try:
            # '-_'を'+/'に置換（URL-safeからスタンダードへ）
            mod_data = data.replace(b'-', b'+').replace(b'_', b'/')
            return base64.b64decode(mod_data)
        except Exception as e2:
            print(f"代替Base64デコードでもエラー: {e2}")

        # どちらの方法でも失敗した場合、可能な限りデコード
        for i in range(4):
            try:
                # パディングを少しずつ減らして試行
                if len(data) > i:
                    test_data = data[:-i] if i > 0 else data
                    if len(test_data) % 4 != 0:
                        test_data = test_data + b'=' * (4 - len(test_data) % 4)
                    return base64.urlsafe_b64decode(test_data)
            except:
                continue

        # 全ての手段が失敗した場合、元のデータを返す
        return data

def decrypt_with_key(encrypted_data: bytes, key_data: Dict[str, Any]) -> bytes:
    """特定の鍵を使って暗号化データを復号"""
    # 鍵タイプに基づく処理を実行
    key_type = analyze_key_type(key_data)
    print(f"鍵タイプの解析結果: {key_type}")

    # 準同型マスクの除去
    unmasked_data = remove_homomorphic_mask(encrypted_data, key_data)

    # Base64デコードの強化版を使用
    try:
        # Base64パターンのチェック（Base64かどうかを確認）
        looks_like_base64 = all(c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_' for c in unmasked_data)

        if looks_like_base64:
            decoded_data = safe_base64_decode(unmasked_data)
        else:
            # Base64に見えない場合はデコードをスキップ
            decoded_data = unmasked_data

        # UTF-8文字列へのデコード試行
        try:
            text = decoded_data.decode('utf-8')
            print(f"UTF-8デコードに成功しました（長さ: {len(text)} 文字）")
            return decoded_data
        except UnicodeDecodeError:
            print("UTF-8デコードに失敗しました。バイナリデータとして処理します。")
            return decoded_data
    except Exception as e:
        print(f"デコード処理でエラー: {e}")
        return unmasked_data

def parse_key_file(key_file: str) -> Dict[str, Any]:
    """鍵ファイルを解析"""
    try:
        with open(key_file, 'r') as f:
            key_data = json.load(f)
        return key_data
    except Exception as e:
        print(f"鍵ファイルの解析に失敗しました: {e}")
        return {}

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='準同型暗号マスキング方式による復号（修正版）')
    parser.add_argument('input_file', help='復号する暗号化ファイルのパス')
    parser.add_argument('--key', '-k', required=True, help='復号鍵ファイルのパス（JSONファイル）')
    parser.add_argument('--output', '-o', help='出力ファイル名（省略時は自動生成）')
    parser.add_argument('--verbose', '-v', action='store_true', help='詳細な出力')
    parser.add_argument('--diagnose', '-d', action='store_true', help='診断モード（復号過程の詳細を出力）')
    args = parser.parse_args()

    # ファイル存在チェック
    if not os.path.exists(args.input_file):
        print(f"エラー: 暗号化ファイル '{args.input_file}' が見つかりません", file=sys.stderr)
        return 1

    if not os.path.exists(args.key):
        print(f"エラー: 鍵ファイル '{args.key}' が見つかりません", file=sys.stderr)
        return 1

    try:
        # 鍵の解析
        key_data = parse_key_file(args.key)
        if not key_data:
            print("エラー: 鍵データの解析に失敗しました", file=sys.stderr)
            return 1

        # 出力ファイル名
        if args.output:
            # 指定された出力ファイル名にUUIDを付加
            base_name, ext = os.path.splitext(args.output)
            output_path = f"{base_name}_{uuid.uuid4().hex[:8]}{ext}"
        else:
            # 入力ファイル名から自動生成
            base_name = os.path.splitext(os.path.basename(args.input_file))[0]
            output_path = f"{base_name}_fixed_{uuid.uuid4().hex[:8]}.txt"

        # 暗号化ファイルの読み込み
        with open(args.input_file, 'rb') as f:
            encrypted_data = f.read()

        print(f"暗号化ファイルを読み込みました: {args.input_file} ({len(encrypted_data)} バイト)")

        # 診断モードの場合、データの最初の部分を表示
        if args.diagnose:
            print(f"暗号化データのサンプル (先頭16バイト): {encrypted_data[:16].hex()}")
            print(f"鍵情報: {json.dumps(key_data, indent=2)}")

        # 復号処理
        print("準同型暗号マスキング方式で復号を開始します...")
        start_time = time.time()

        # 復号処理
        decrypted_data = decrypt_with_key(encrypted_data, key_data)

        # 診断モードの場合、復号結果の一部を表示
        if args.diagnose:
            print(f"復号結果のサンプル (先頭16バイト): {decrypted_data[:16].hex()}")
            try:
                # テキストとして解釈できるか試みる
                text_preview = decrypted_data[:100].decode('utf-8', errors='replace')
                print(f"テキストプレビュー: {text_preview}")
            except:
                print("テキストとして解釈できません（バイナリデータ）")

        # ファイルへの書き込み
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        elapsed_time = time.time() - start_time
        print(f"復号が完了しました（所要時間: {elapsed_time:.2f}秒）")
        print(f"出力ファイル: {output_path}")
        print(f"復号後のサイズ: {len(decrypted_data)} バイト")

        return 0

    except Exception as e:
        print(f"エラー: 復号処理中に問題が発生しました: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())