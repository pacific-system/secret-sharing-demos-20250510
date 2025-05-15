#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
#                  ███████ ███    ██  ██████ ██████  ██    ██ ██████  ████████ #
#                  ██      ████   ██ ██      ██   ██  ██  ██  ██   ██    ██    #
#                  █████   ██ ██  ██ ██      ██████    ████   ██████     ██    #
#                  ██      ██  ██ ██ ██      ██   ██    ██    ██         ██    #
#                  ███████ ██   ████  ██████ ██   ██    ██    ██         ██    #
#                                                                              #
#               【暗号化を実行するメインスクリプト - MAIN ENCRYPTION SCRIPT】    #
#                                                                              #
#     このファイルは準同型暗号マスキング方式の「暗号化」機能のメインエントリーポイントです       #
#     最終成果物として、ユーザーはこのファイルを直接実行してファイルを暗号化します         #
#                                                                              #
################################################################################

"""
準同型暗号マスキング方式の暗号化実行ファイル

このモジュールは、準同型暗号マスキング方式を使用してファイルを暗号化するための
コマンドラインツールを提供します。マスク関数を使って真と偽の状態を区別不可能な形式で
暗号化します。どちらのキーが「正規」か「非正規」かはシステムの区別ではなく、
使用者の意図によって決まります。これにより、ハニーポット戦略（意図的に「正規」鍵を
漏洩させて偽情報を信じ込ませる）やリバーストラップ（本当に重要な情報を「非正規」側に
隠す）のような高度なセキュリティ戦略が可能になります。
"""

import os
import sys
import time
import json
import base64
import hashlib
import argparse
import binascii
import random
import secrets
from typing import Dict, Any, Tuple, List, Optional

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.config import (
    TRUE_TEXT_PATH,
    FALSE_TEXT_PATH,
    KEY_SIZE_BYTES,
    SALT_SIZE,
    OUTPUT_FORMAT,
    OUTPUT_EXTENSION,
    CRYPTO_ALGORITHM,
    PAILLIER_KEY_BITS,
    ELGAMAL_KEY_BITS,
    MASK_SEED_SIZE,
    MAX_CHUNK_SIZE
)
from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, save_keys, load_keys,
    serialize_encrypted_data, deserialize_encrypted_data
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)
from method_8_homomorphic.crypto_adapters import (
    process_data_for_encryption, process_data_after_decryption,
    DataAdapter
)
from method_8_homomorphic.indistinguishable import (
    randomize_ciphertext, batch_randomize_ciphertexts,
    add_statistical_noise, remove_statistical_noise,
    interleave_ciphertexts, deinterleave_ciphertexts,
    add_redundancy, remove_redundancy,
    apply_comprehensive_indistinguishability, remove_comprehensive_indistinguishability
)


def parse_arguments() -> argparse.Namespace:
    """
    コマンドライン引数の解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(
        description='準同型暗号マスキング方式による暗号化ツール'
    )

    parser.add_argument(
        '--true-file', '-t',
        type=str,
        default=TRUE_TEXT_PATH,
        help='真のファイルパス (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--false-file', '-f',
        type=str,
        default=FALSE_TEXT_PATH,
        help='偽のファイルパス (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        default=f'output{OUTPUT_EXTENSION}',
        help=f'出力ファイル名 (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--algorithm', '-a',
        type=str,
        choices=['paillier', 'elgamal', 'hybrid'],
        default=CRYPTO_ALGORITHM,
        help='使用する準同型暗号アルゴリズム (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--key', '-k',
        type=str,
        help='使用する鍵（16進数文字列、省略時はランダム生成）'
    )

    parser.add_argument(
        '--password', '-p',
        type=str,
        help='パスワードから鍵を導出（--keyよりも優先）'
    )

    parser.add_argument(
        '--advanced-mask', '-am',
        action='store_true',
        help='高度なマスク関数を使用（多項式変換など）'
    )

    parser.add_argument(
        '--key-bits', '-b',
        type=int,
        default=PAILLIER_KEY_BITS,
        help=f'鍵のビット長 (デフォルト: %(default)s)'
    )

    parser.add_argument(
        '--save-keys', '-s',
        action='store_true',
        help='生成した鍵をファイルに保存'
    )

    parser.add_argument(
        '--keys-dir', '-d',
        type=str,
        default='keys',
        help='鍵を保存するディレクトリ (--save-keysが指定された場合に使用)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='詳細な出力'
    )

    parser.add_argument(
        '--force-data-type',
        choices=['text', 'binary', 'json', 'base64', 'auto'],
        default='auto',
        help='入力データの形式を強制指定（デフォルト: 自動検出）'
    )

    # 識別不能性機能関連のオプション
    parser.add_argument(
        '--indistinguishable', '-i',
        action='store_true',
        help='識別不能性機能を適用する'
    )

    parser.add_argument(
        '--noise-intensity',
        type=float,
        default=0.05,
        help='統計的ノイズの強度（0.0～1.0）'
    )

    parser.add_argument(
        '--redundancy-factor',
        type=int,
        default=1,
        help='冗長性の係数（1以上の整数、1の場合は冗長性なし）'
    )

    parser.add_argument(
        '--shuffle-seed',
        type=str,
        help='シャッフルのためのシード（16進数文字列、省略時はランダム生成）'
    )

    return parser.parse_args()


def generate_key(provided_key: Optional[str] = None) -> bytes:
    """
    暗号化鍵を生成または変換

    Args:
        provided_key: 提供された鍵（16進数文字列）

    Returns:
        生成された鍵
    """
    if provided_key:
        try:
            # 16進数文字列から鍵を復元
            key = binascii.unhexlify(provided_key)
            # 鍵長を調整
            if len(key) < KEY_SIZE_BYTES:
                key = key.ljust(KEY_SIZE_BYTES, b'\0')
            elif len(key) > KEY_SIZE_BYTES:
                key = key[:KEY_SIZE_BYTES]
            return key
        except binascii.Error:
            print(f"Error: 無効な鍵形式です。16進数文字列を指定してください。")
            sys.exit(1)
    else:
        # ランダムな鍵を生成
        return os.urandom(KEY_SIZE_BYTES)


def ensure_directory(directory: str) -> None:
    """
    ディレクトリの存在を確認し、なければ作成

    Args:
        directory: 確認するディレクトリパス
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
        if os.path.exists(directory):
            print(f"ディレクトリを作成しました: {directory}")
        else:
            print(f"Error: ディレクトリの作成に失敗しました: {directory}")
            sys.exit(1)


def encrypt_files(args: argparse.Namespace) -> Tuple[bytes, Dict[str, Any]]:
    """
    ファイルを暗号化

    Args:
        args: コマンドライン引数

    Returns:
        (master_key, metadata): マスター鍵とメタデータ。エラー時はNoneを返す。
    """
    start_time = time.time()

    # 処理開始メッセージ
    print(f"準同型暗号マスキング方式による暗号化を開始します...")
    print(f"重要：どちらのキーが「正規」か「非正規」かはユーザーの意図によって決まります")
    print(f"      復号時に使用する鍵によって、どちらのファイルが復元されるかが決まります")

    # 入力ファイルの存在確認を前もって行う
    if not os.path.exists(args.true_file):
        print(f"Error: 真ファイルが見つかりません: {args.true_file}")
        return None, None

    if not os.path.exists(args.false_file):
        print(f"Error: 偽ファイルが見つかりません: {args.false_file}")
        return None, None

    try:
        # 鍵の生成または取得
        if args.password:
            # パスワードから鍵を導出
            salt = os.urandom(SALT_SIZE)
            print(f"パスワードから鍵を導出中...")

            # bits属性の存在を確認
            key_bits = getattr(args, 'key_bits', PAILLIER_KEY_BITS)

            paillier_pub, paillier_priv, salt = derive_key_from_password(
                args.password, salt, "paillier", bits=key_bits)

            # PaillierCryptoインスタンスを作成
            paillier_obj = PaillierCrypto(bits=key_bits)
            paillier_obj.public_key = paillier_pub
            paillier_obj.private_key = paillier_priv

            # マスク関数生成用のシード
            key = hashlib.pbkdf2_hmac(
                'sha256',
                args.password.encode(),
                salt,
                10000,
                MASK_SEED_SIZE
            )
        else:
            # 鍵の生成または取得
            key = generate_key(args.key)
            salt = os.urandom(SALT_SIZE)

            # Paillier暗号システムの初期化
            print(f"準同型暗号鍵を生成中...")
            key_bits = getattr(args, 'key_bits', PAILLIER_KEY_BITS)
            paillier_obj = PaillierCrypto(bits=key_bits)
            paillier_pub, paillier_priv = paillier_obj.generate_keys()

        if args.verbose:
            print(f"暗号化鍵: {binascii.hexlify(key).decode()}")
            print(f"ソルト: {binascii.hexlify(salt).decode()}")

        # 鍵を保存
        if hasattr(args, 'save_keys') and args.save_keys:
            keys_dir = getattr(args, 'keys_dir', 'keys')
            ensure_directory(keys_dir)
            print(f"鍵ファイルを保存中...")

            public_key_file = os.path.join(keys_dir, "paillier_public.json")
            private_key_file = os.path.join(keys_dir, "paillier_private.json")

            save_keys(paillier_pub, paillier_priv, public_key_file, private_key_file)

            key_file = os.path.join(keys_dir, "encryption_key.bin")
            salt_file = os.path.join(keys_dir, "salt.bin")

            with open(key_file, 'wb') as f:
                f.write(key)

            with open(salt_file, 'wb') as f:
                f.write(salt)

            if args.verbose:
                print(f"鍵を保存しました:")
                print(f"  - 公開鍵: {public_key_file}")
                print(f"  - 秘密鍵: {private_key_file}")
                print(f"  - 暗号化鍵: {key_file}")
                print(f"  - ソルト: {salt_file}")

        # ファイルの内容を読み込み
        print(f"入力ファイルを読み込み中...")
        try:
            with open(args.true_file, 'rb') as f:
                true_raw_content = f.read()
            with open(args.false_file, 'rb') as f:
                false_raw_content = f.read()
        except FileNotFoundError as e:
            print(f"Error: {e}")
            return None, None

        # データタイプの検出と処理 - 両方のファイルに対して一貫性を持たせる
        true_data_type = 'auto'
        false_data_type = 'auto'

        if args.force_data_type != 'auto':
            # 強制指定された場合
            true_data_type = args.force_data_type
            false_data_type = args.force_data_type
            print(f"データタイプを強制指定: {true_data_type}")
        else:
            # 自動検出
            true_data_type = DataAdapter.detect_data_type(true_raw_content)
            false_data_type = DataAdapter.detect_data_type(false_raw_content)
            print(f"真データタイプを自動検出: {true_data_type}")
            print(f"偽データタイプを自動検出: {false_data_type}")

        # データの前処理（両方のファイルに対して同じ処理パイプラインを適用）
        true_content, true_final_type = process_data_for_encryption(true_raw_content, true_data_type)
        false_content, false_final_type = process_data_for_encryption(false_raw_content, false_data_type)

        if args.verbose:
            # 真データの詳細情報
            print(f"[DEBUG] 真ファイル暗号化前: データタイプ={true_data_type}, サイズ={len(true_raw_content)}バイト")
            print(f"[DEBUG] 真ファイルテキスト内容: {true_raw_content[:20]}...")
            if true_data_type == 'text':
                try:
                    encoding = 'utf-8'
                    text = true_raw_content.decode(encoding)
                    print(f"[DEBUG] 真ファイル検出されたエンコーディング: {encoding}")
                    print(f"[DEBUG] 真ファイルデコードされたテキスト（先頭30文字）: {text[:30]}")
                except UnicodeDecodeError:
                    print(f"[DEBUG] 真ファイルデコードできませんでした")
            print(f"[DEBUG] 真ファイル変換後: サイズ={len(true_content)}バイト")
            print(f"[DEBUG] 真ファイル変換後先頭バイト: {true_content[:20]}")

            # 偽データの詳細情報
            print(f"[DEBUG] 偽ファイル暗号化前: データタイプ={false_data_type}, サイズ={len(false_raw_content)}バイト")
            print(f"[DEBUG] 偽ファイルテキスト内容: {false_raw_content[:20]}...")
            if false_data_type == 'text':
                try:
                    encoding = 'utf-8'
                    text = false_raw_content.decode(encoding)
                    print(f"[DEBUG] 偽ファイル検出されたエンコーディング: {encoding}")
                    print(f"[DEBUG] 偽ファイルデコードされたテキスト（先頭30文字）: {text[:30]}")
                except UnicodeDecodeError:
                    print(f"[DEBUG] 偽ファイルデコードできませんでした")
            print(f"[DEBUG] 偽ファイル変換後: サイズ={len(false_content)}バイト")
            print(f"[DEBUG] 偽ファイル変換後先頭バイト: {false_content[:20]}")

        # データをチャンクに分割（両方のファイルに対して同じチャンクサイズを使用）
        chunk_size = MAX_CHUNK_SIZE  # バイトごとの暗号化に適したサイズ
        true_chunks = [true_content[i:i+chunk_size] for i in range(0, len(true_content), chunk_size)]
        false_chunks = [false_content[i:i+chunk_size] for i in range(0, len(false_content), chunk_size)]

        # 各チャンクを暗号化（両方のファイルに対して同じ暗号化処理を適用）
        true_encrypted = []
        false_encrypted = []

        for i, chunk in enumerate(true_chunks):
            # 進行状況表示
            if args.verbose and i % 5 == 0:
                print(f"真データ暗号化中: {i+1}/{len(true_chunks)} チャンク")
            # バイト列を整数に変換
            chunk_int = int.from_bytes(chunk, byteorder='big')
            # 暗号化
            encrypted = paillier_obj.encrypt(chunk_int, paillier_pub)
            true_encrypted.append(encrypted)

        for i, chunk in enumerate(false_chunks):
            # 進行状況表示
            if args.verbose and i % 5 == 0:
                print(f"偽データ暗号化中: {i+1}/{len(false_chunks)} チャンク")
            # バイト列を整数に変換
            chunk_int = int.from_bytes(chunk, byteorder='big')
            # 暗号化
            encrypted = paillier_obj.encrypt(chunk_int, paillier_pub)
            false_encrypted.append(encrypted)

        # 識別不能性機能の適用（オプションが指定されている場合）
        if hasattr(args, 'indistinguishable') and args.indistinguishable:
            print("識別不能性機能を適用中...")

            # シャッフルのためのシード値を準備
            shuffle_seed = None
            if hasattr(args, 'shuffle_seed') and args.shuffle_seed:
                try:
                    shuffle_seed = binascii.unhexlify(args.shuffle_seed)
                except binascii.Error:
                    print("警告: 無効なシャッフルシード形式です。ランダムなシードを生成します。")
                    shuffle_seed = secrets.token_bytes(16)
            else:
                shuffle_seed = secrets.token_bytes(16)

            # 識別不能性パラメータを取得
            noise_intensity = getattr(args, 'noise_intensity', 0.05)
            redundancy_factor = getattr(args, 'redundancy_factor', 1)

            print(f"統計的ノイズ強度: {noise_intensity}")
            print(f"冗長性係数: {redundancy_factor}")

            # 暗号文のランダム化
            true_encrypted = batch_randomize_ciphertexts(paillier_obj, true_encrypted)
            false_encrypted = batch_randomize_ciphertexts(paillier_obj, false_encrypted)

            # 総合的な識別不能性を適用
            indist_true, indist_false = None, None
            indist_true_metadata, indist_false_metadata = None, None

            if redundancy_factor > 1 or noise_intensity > 0:
                # 総合的な識別不能性処理
                indist_true, indist_true_metadata = apply_comprehensive_indistinguishability(
                    true_encrypted, false_encrypted, paillier_obj,
                    noise_intensity=noise_intensity,
                    redundancy_factor=redundancy_factor
                )

                # 偽データにも同じパラメータで適用
                indist_false, indist_false_metadata = apply_comprehensive_indistinguishability(
                    false_encrypted, true_encrypted, paillier_obj,
                    noise_intensity=noise_intensity,
                    redundancy_factor=redundancy_factor
                )

                # 識別不能性メタデータを保存
                true_encrypted = indist_true
                false_encrypted = indist_false

                # 識別不能性のメタデータを設定
                indist_metadata = {
                    "true_indist_metadata": indist_true_metadata,
                    "false_indist_metadata": indist_false_metadata,
                    "noise_intensity": noise_intensity,
                    "redundancy_factor": redundancy_factor,
                    "shuffle_seed": shuffle_seed.hex() if shuffle_seed else None
                }
            else:
                # 基本的なランダム化のみ
                indist_metadata = {
                    "randomized": True,
                    "noise_intensity": 0,
                    "redundancy_factor": 1,
                    "shuffle_seed": shuffle_seed.hex() if shuffle_seed else None
                }

        # マスク適用と真偽変換
        print("マスク関数を適用し、真偽両方の状態を区別不可能な形式に変換中...")
        print("この処理により、暗号文だけではどちらが「正規」ファイルか判別できなくなります")

        # マスク関数生成器の初期化
        if args.advanced_mask:
            mask_generator = AdvancedMaskFunctionGenerator(paillier_obj, key)
            print("高度なマスク関数を使用します（多項式変換など）")
        else:
            mask_generator = MaskFunctionGenerator(paillier_obj, key)
            print("基本マスク関数を使用します")

        # マスク適用と真偽変換
        masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
            paillier_obj, true_encrypted, false_encrypted, mask_generator
        )

        # データの元のフォーマット情報を保持（復号時に利用）
        metadata = {
            "format": "homomorphic_masked",
            "version": "1.0",
            "algorithm": args.algorithm,
            "key_bits": args.key_bits,
            "timestamp": int(time.time()),
            "true_size": len(true_content),
            "false_size": len(false_content),
            "chunk_size": chunk_size,
            "salt": base64.b64encode(salt).decode('ascii'),
            "true_data_type": true_final_type,
            "false_data_type": false_final_type,
            "true_filename": os.path.basename(args.true_file),
            "false_filename": os.path.basename(args.false_file),
            "public_key": paillier_obj.public_key  # 公開鍵情報を追加
        }

        # 識別不能性メタデータを追加
        if hasattr(args, 'indistinguishable') and args.indistinguishable:
            metadata["indistinguishable"] = True
            metadata["indistinguishable_metadata"] = indist_metadata
        else:
            metadata["indistinguishable"] = False

        # エンコーディング情報の統一的な取得と保存（両方のファイルに対して同じアプローチ）
        try:
            # テキストファイルかどうかをチェック（エンコーディング検出）
            for file_type, raw_content, file_path in [
                ('true', true_raw_content, args.true_file),
                ('false', false_raw_content, args.false_file)
            ]:
                is_text = False

                # ファイル拡張子でテキストファイルかどうかを判断
                file_ext = os.path.splitext(file_path)[1].lower()
                text_extensions = ['.txt', '.text', '.md', '.json', '.xml', '.html', '.htm', '.csv', '.log']

                if file_ext in text_extensions:
                    # テキストファイルの可能性が高い
                    for enc in ['utf-8', 'latin-1', 'shift-jis', 'euc-jp']:
                        try:
                            raw_content.decode(enc)
                            is_text = True
                            metadata[f"{file_type}_encoding"] = enc
                            break
                        except UnicodeDecodeError:
                            continue

                metadata[f"is_{file_type}_text"] = is_text

        except Exception as e:
            print(f"ファイル形式の判定中にエラーが発生しました: {e}")

        # 区別不可能な形式に変換
        print("暗号文を区別不可能な形式に変換中...")
        indistinguishable_data = create_indistinguishable_form(
            masked_true, masked_false, true_mask, false_mask, metadata
        )

        # 出力ファイルに書き込み
        print(f"暗号化ファイルを出力中: {args.output}")
        try:
            with open(args.output, 'w') as f:
                json.dump(indistinguishable_data, f, indent=2)
        except IOError as e:
            print(f"Error: ファイルの書き込みに失敗しました: {e}")
            return None, None

        end_time = time.time()
        elapsed_time = end_time - start_time

        # 結果出力
        print(f"\n暗号化が完了しました！")
        print(f"出力ファイル: {args.output}")
        print(f"鍵（安全に保管してください）: {binascii.hexlify(key).decode()}")
        print(f"処理時間: {elapsed_time:.2f}秒")
        print(f"\n重要な注意:")
        print(f"1. この鍵を使用すると、復号時に「真」ファイルまたは「偽」ファイルのいずれかが得られます")
        print(f"2. どちらが「正規」ファイルかは、あなたの意図によって決まります")
        print(f"3. ハニーポット戦略を実装したい場合は、「偽」ファイルを復号する鍵を意図的に漏洩させることができます")
        print(f"4. リバーストラップを設定したい場合は、本当に重要な情報を「偽」側に隠すこともできます")

        if args.verbose:
            print(f"\n詳細情報:")
            print(f"真ファイルサイズ: {len(true_raw_content)} バイト")
            print(f"偽ファイルサイズ: {len(false_raw_content)} バイト")
            print(f"真データタイプ: {true_final_type}")
            print(f"偽データタイプ: {false_final_type}")
            print(f"処理後真データサイズ: {len(true_content)} バイト")
            print(f"処理後偽データサイズ: {len(false_content)} バイト")
            print(f"暗号化後ファイルサイズ: {os.path.getsize(args.output)} バイト")
            print(f"真チャンク数: {len(true_chunks)}")
            print(f"偽チャンク数: {len(false_chunks)}")

        return key, metadata

    except Exception as e:
        print(f"暗号化中に問題が発生しました: {e}")
        return None, None


def main():
    """メイン関数"""
    args = parse_arguments()
    try:
        key, metadata = encrypt_files(args)

        # save_keysオプションが有効な場合は既にencrypt_files内で保存済み

        sys.exit(0)
    except Exception as e:
        print(f"Error: 暗号化中に問題が発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
