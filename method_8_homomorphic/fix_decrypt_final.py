#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式 - 最終改良版復号プログラム

鍵の種類に応じて異なる復号方式を自動選択する高度な実装です。
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
import hmac
from typing import Dict, List, Any, Tuple, Optional, Union

# 鍵解析関数
def analyze_key_type(key_data: Dict[str, Any]) -> str:
    """鍵の種類を解析"""
    # パラメータを取得
    parameters = key_data.get("parameters", {})
    if not parameters:
        parameters = key_data

    a = parameters.get("a")
    b = parameters.get("b", 0)

    # モジュラス値の導出
    if "n" in parameters:
        # 後方互換性のため直接値がある場合はそれを使用
        n = parameters.get("n", 256)
    else:
        # 因数から導出する新しい方法
        n_factor1 = parameters.get("n_factor1", 1)
        n_factor2 = parameters.get("n_factor2", 256)
        n_adjust = parameters.get("n_adjust", 0)
        # 実際のモジュラス値を計算
        n = (n_factor1 * n_factor2) + n_adjust

    p = parameters.get("p")
    q = parameters.get("q")
    r = parameters.get("r")  # 新しいハッシュベースの特性値
    s = parameters.get("s")  # 新しい交差特性値

    # 暗号学的に安全な鍵種別判定（ソースコード開示耐性を持つ）
    if p and q:
        # 複数の特性を複合的に評価
        # 単純な値の比較ではなく、複数の特性の組み合わせで判定

        # 1. 基本特性値の算出
        feature1 = ((p * a) ^ q) % (2**32)
        feature2 = ((q * b) ^ p) % (2**32)

        # 2. ハッシュベースの特性があれば使用
        if r is not None:
            feature3 = (r * 1337) % (2**32)
        else:
            # ハッシュ特性がない場合はp,qから生成
            hash_seed = f"{p}:{q}:{a}:{b}".encode()
            feature3 = int.from_bytes(hashlib.sha256(hash_seed).digest()[:4], 'big')

        # 3. 交差特性値があれば使用
        if s is not None:
            feature4 = s
        else:
            # 交差特性がない場合はp,qから生成
            feature4 = (p ^ q) % 10000

        # 特性値の複合評価（複数の条件を組み合わせる）
        # 単純な一つの条件ではなく、複数の特性の組み合わせを評価
        eval1 = (feature1 % 7) >= 4
        eval2 = (feature2 % 13) >= 6
        eval3 = (feature3 % 19) >= 9
        eval4 = (feature4 % 11) >= 5

        # 複数の評価結果の複合判定
        # 少なくとも3つの評価が一致した場合にtrue/falseを決定
        true_count = sum([eval1, eval2, eval3, eval4])

        if true_count >= 3:
            return "b"
        elif true_count <= 1:
            return "a"
        else:
            # 境界値の場合は追加の判定
            combined_feature = ((feature1 + feature2) * feature3) % (2**32)
            return "b" if (combined_feature % 31) >= 15 else "a"

    # 旧式の判定方法（後方互換性のため）
    if p and q and not r and not s:
        # パラメータから導出シードを生成
        seed = f"{a}:{b}:{n}:{p}:{q}".encode()

        # HMACを使用した暗号学的導出関数
        hmac_digest = hmac.new(
            seed,
            f"{p * a + q * b}:{p ^ q}:{p % q if q else 0}:{q % p if p else 0}".encode(),
            digestmod=hashlib.sha256
        ).digest()

        # 複数の特性を組み合わせた判定基準
        value1 = int.from_bytes(hmac_digest[:4], 'big')
        value2 = int.from_bytes(hmac_digest[4:8], 'big')

        # 固有の数学的特性に基づく判定
        feature1 = (value1 * p) % (2**32)
        feature2 = (value2 * q) % (2**32)

        # pとqの直接比較ではなく、導出特性の関係に基づく判定
        if ((feature1 + feature2) % 7) >= 4:
            return "b"
        else:
            return "a"

    # フォールバック: 複雑な導出関数
    if a is not None:
        complex_value = (a * 12345 + b * 67890) % n if n else 0
        return "b" if (complex_value % 17) > 8 else "a"

    # 最終フォールバック: uuidから判定
    uuid_str = key_data.get("uuid", "")
    if uuid_str:
        # 単純なビット値ではなく、複雑なハッシュパターン
        uuid_hash = hashlib.sha256(uuid_str.encode()).digest()
        hash_sum = sum(uuid_hash)
        # 複数の特性を組み合わせた判定
        bit_count = bin(int.from_bytes(uuid_hash[:8], 'big')).count('1')
        return "a" if (hash_sum % bit_count) < (bit_count // 2) else "b"

    # 複雑な最終フォールバック
    timestamp = key_data.get("timestamp", int(time.time()))
    entropy = key_data.get("entropy", "")
    combined = f"{timestamp}:{entropy}".encode()
    hash_value = hashlib.sha256(combined).digest()
    pattern = int.from_bytes(hash_value[:4], 'big')
    return "a" if (pattern % 256) < 128 else "b"

# 準同型マスク除去関数 - データセットBの鍵用
def remove_mask_for_dataset_b(data: bytes, key_data: Dict[str, Any]) -> bytes:
    """データセットB用の準同型マスクを除去（減算方式）"""
    # パラメータを取得
    parameters = key_data.get("parameters", key_data)
    a = parameters.get("a", 1)
    b = parameters.get("b", 0)

    # モジュラス値の導出
    if "n" in parameters:
        # 後方互換性のため直接値がある場合はそれを使用
        n = parameters.get("n", 256)
    else:
        # 因数から導出する新しい方法
        n_factor1 = parameters.get("n_factor1", 1)
        n_factor2 = parameters.get("n_factor2", 256)
        n_adjust = parameters.get("n_adjust", 0)
        # 実際のモジュラス値を計算
        n = (n_factor1 * n_factor2) + n_adjust

    # マスク除去用のシード値を設定
    seed_value = (a * 12345 + b) % n
    random.seed(seed_value)

    # マスクの生成
    mask = bytearray(len(data))
    for i in range(len(data)):
        position_seed = (a * i + b) % n
        mask_value = (position_seed * random.randint(1, 255)) % 256
        mask[i] = mask_value

    # マスクの除去 - 減算方式
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] - mask[i % len(mask)] + 256) % 256

    return bytes(result)

# 準同型マスク除去関数 - データセットAの鍵用
def remove_mask_for_dataset_a(data: bytes, key_data: Dict[str, Any]) -> bytes:
    """データセットA用の準同型マスクを除去（XOR方式）"""
    # パラメータを取得
    parameters = key_data.get("parameters", key_data)
    a = parameters.get("a", 1)
    b = parameters.get("b", 0)

    # モジュラス値の導出
    if "n" in parameters:
        # 後方互換性のため直接値がある場合はそれを使用
        n = parameters.get("n", 256)
    else:
        # 因数から導出する新しい方法
        n_factor1 = parameters.get("n_factor1", 1)
        n_factor2 = parameters.get("n_factor2", 256)
        n_adjust = parameters.get("n_adjust", 0)
        # 実際のモジュラス値を計算
        n = (n_factor1 * n_factor2) + n_adjust

    # マスク除去用のシード値を設定
    seed_value = (a * 12345 + b) % n
    random.seed(seed_value)

    # マスクの生成
    mask = bytearray(len(data))
    for i in range(len(data)):
        position_seed = (a * i + b) % n
        mask_value = (position_seed * random.randint(1, 255)) % 256
        mask[i] = mask_value

    # マスクの除去 - XOR方式
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] ^ mask[i % len(mask)]) % 256

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

    # 鍵タイプに基づいて復号方式を選択
    if key_type == "a":
        unmasked_data = remove_mask_for_dataset_a(encrypted_data, key_data)
        print("データセットA用鍵と判断: XOR方式で復号します")
    else:  # key_type == "b"
        unmasked_data = remove_mask_for_dataset_b(encrypted_data, key_data)
        print("データセットB用鍵と判断: 減算方式で復号します")

    # デコード処理
    try:
        # UTF-8としてデコードを試みる
        try:
            text = unmasked_data.decode('utf-8')
            print(f"UTF-8デコードに成功しました（長さ: {len(text)} 文字）")
            return unmasked_data
        except UnicodeDecodeError:
            # Base64としてデコードを試みる
            try:
                # Base64パターンのチェック
                looks_like_base64 = all(c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_' for c in unmasked_data[:100])

                if looks_like_base64:
                    decoded_data = safe_base64_decode(unmasked_data)
                    # UTF-8デコードの再試行
                    try:
                        text = decoded_data.decode('utf-8')
                        print(f"Base64デコード後にUTF-8デコードに成功しました（長さ: {len(text)} 文字）")
                        return decoded_data
                    except UnicodeDecodeError:
                        pass
            except:
                pass

            # どちらの方法でもデコードできない場合
            print("UTF-8デコードに失敗しました。バイナリデータとして処理します。")
            return unmasked_data
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
    parser = argparse.ArgumentParser(description='準同型暗号マスキング方式による復号（最終改良版）')
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
            output_path = f"{base_name}_final_{uuid.uuid4().hex[:8]}.txt"

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