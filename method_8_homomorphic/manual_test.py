#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の手動テスト

このスクリプトは、準同型暗号マスキング方式の実装を検証するための
手動テストを提供します。循環インポート問題などのバグ修正が
正しく適用されているかを確認します。
"""

import os
import sys
import time
import random
import math
import base64
import hashlib
import binascii

# インポートパスを追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# インポートを試みてエラーが発生しないか確認
print("インポートテスト中...")
from homomorphic import PaillierCrypto
from indistinguishable_ext import (
    safe_log10,
    remove_comprehensive_indistinguishability,
    analyze_key_type_enhanced,
    add_statistical_noise,
    add_redundancy
)
from decrypt import parse_key
from encrypt import generate_key, interleave_ciphertexts

print("インポート成功!")

# テストデータのディレクトリ作成
TEST_OUTPUT_DIR = "test_output"
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

def test_safe_log10():
    """safe_log10関数のテスト"""
    print("\n=== safe_log10 テスト ===")
    # 通常の入力
    test_cases = [
        (0, 0),
        (1, 0),
        (10, 1),
        (100, 2),
        (1000, 3),
        (10000, 4),
    ]

    print("通常の入力テスト...")
    for value, expected in test_cases:
        result = safe_log10(value)
        print(f"log10({value}) = {result}, 期待値: {expected}")
        assert abs(result - expected) < 0.001

    # 大きな整数の入力
    big_ints = [
        10**20,
        10**50,
        2**100,
        2**200,
        2**1000
    ]

    print("\n大きな整数のテスト...")
    for value in big_ints:
        try:
            result = safe_log10(value)
            print(f"log10({value}) = {result}")
            # 大まかな検証（ビット長からの推定）
            bit_length = value.bit_length()
            approx = bit_length * math.log10(2)
            assert abs(result - approx) < 0.1
        except Exception as e:
            print(f"エラー発生: {e}")
            assert False, f"safe_log10がエラーを発生させました: {e}"

    print("safe_log10テスト成功!")

def test_crypto_operations():
    """暗号化/復号の基本的な操作のテスト"""
    print("\n=== 基本的な暗号操作テスト ===")

    # Paillierインスタンスの作成
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テストデータ
    test_value = 12345

    # 暗号化
    encrypted = paillier.encrypt(test_value, public_key)
    print(f"元の値: {test_value}")
    print(f"暗号化された値: {encrypted}")

    # 復号
    decrypted = paillier.decrypt(encrypted, private_key)
    print(f"復号された値: {decrypted}")

    # 検証
    assert decrypted == test_value, "暗号化/復号の結果が一致しません!"

    # 準同型性のテスト
    a = 123
    b = 456

    encrypted_a = paillier.encrypt(a, public_key)
    encrypted_b = paillier.encrypt(b, public_key)

    # 暗号文の加算
    encrypted_sum = (encrypted_a * encrypted_b) % (public_key['n'] ** 2)

    # 復号
    decrypted_sum = paillier.decrypt(encrypted_sum, private_key)

    print(f"a = {a}, b = {b}")
    print(f"a + b = {a + b}")
    print(f"復号された和: {decrypted_sum}")

    # 検証
    assert decrypted_sum == a + b, "準同型性が機能していません!"

    print("基本的な暗号操作テスト成功!")

def test_noise_addition_removal():
    """ノイズの追加と除去のテスト"""
    print("\n=== ノイズ追加/除去テスト ===")

    # Paillierインスタンスの作成
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テストデータ
    test_values = [1234, 5678, 9012, 3456, 7890]

    # 暗号化
    encrypted_values = [paillier.encrypt(val, public_key) for val in test_values]
    print(f"元の暗号文: {encrypted_values[:2]}...")

    # ノイズ追加
    noisy_values, noise = add_statistical_noise(encrypted_values, intensity=0.1, paillier=paillier)
    print(f"ノイズ追加後: {noisy_values[:2]}...")
    print(f"ノイズ値: {noise[:2]}...")

    # ノイズ除去
    from indistinguishable_ext import remove_statistical_noise
    denoised_values = remove_statistical_noise(noisy_values, noise, paillier)
    print(f"ノイズ除去後: {denoised_values[:2]}...")

    # 復号して検証
    original_decrypted = [paillier.decrypt(val, private_key) for val in encrypted_values]
    denoised_decrypted = [paillier.decrypt(val, private_key) for val in denoised_values]

    print(f"元の値: {original_decrypted}")
    print(f"ノイズ除去後の値: {denoised_decrypted}")

    assert original_decrypted == denoised_decrypted, "ノイズ除去が正しく機能していません!"

    print("ノイズ追加/除去テスト成功!")

def test_redundancy_addition_removal():
    """冗長性の追加と除去のテスト"""
    print("\n=== 冗長性追加/除去テスト ===")

    # Paillierインスタンスの作成
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テストデータ
    test_values = [1234, 5678, 9012]

    # 暗号化
    encrypted_values = [paillier.encrypt(val, public_key) for val in test_values]
    print(f"元の暗号文: {encrypted_values}")

    # 冗長性追加
    redundancy_factor = 2
    redundant_values, metadata = add_redundancy(encrypted_values, redundancy_factor, paillier)
    print(f"冗長性追加後 ({len(redundant_values)} 要素): {redundant_values[:3]}...")
    print(f"メタデータ: {metadata}")

    # 冗長性除去
    from indistinguishable_ext import remove_redundancy
    dedup_values = remove_redundancy(redundant_values, metadata)
    print(f"冗長性除去後: {dedup_values}")

    # 復号して検証
    original_decrypted = [paillier.decrypt(val, private_key) for val in encrypted_values]
    dedup_decrypted = [paillier.decrypt(val, private_key) for val in dedup_values]

    print(f"元の値: {original_decrypted}")
    print(f"冗長性除去後の値: {dedup_decrypted}")

    assert len(dedup_values) == len(encrypted_values), "冗長性除去後の長さが一致しません!"
    assert original_decrypted == dedup_decrypted, "冗長性除去が正しく機能していません!"

    print("冗長性追加/除去テスト成功!")

def test_interleave_deinterleave():
    """交互配置とその解除のテスト"""
    print("\n=== 交互配置テスト ===")

    # テストデータ
    true_values = [1, 3, 5, 7, 9]
    false_values = [2, 4, 6, 8, 10]

    print(f"真の値: {true_values}")
    print(f"偽の値: {false_values}")

    # 交互配置
    shuffle_seed = hashlib.sha256(b"test_seed").digest()[:16]
    interleaved_values, metadata = interleave_ciphertexts(true_values, false_values, shuffle_seed)

    print(f"交互配置後: {interleaved_values}")
    print(f"メタデータ: {metadata}")

    # 解除
    from indistinguishable_ext import deinterleave_ciphertexts
    retrieved_true = deinterleave_ciphertexts(interleaved_values, metadata, "true")
    retrieved_false = deinterleave_ciphertexts(interleaved_values, metadata, "false")

    print(f"抽出された真の値: {retrieved_true}")
    print(f"抽出された偽の値: {retrieved_false}")

    # 順序は変わるがすべての要素が含まれているか確認
    assert sorted(retrieved_true) == sorted(true_values), "真の値の復元に失敗!"
    assert sorted(retrieved_false) == sorted(false_values), "偽の値の復元に失敗!"

    print("交互配置テスト成功!")

def test_comprehensive_indistinguishability():
    """総合的な識別不能性のテスト"""
    print("\n=== 総合的な識別不能性テスト ===")

    # Paillierインスタンスの作成
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テストデータ
    true_values = [111, 222, 333]
    false_values = [444, 555, 666]

    # 暗号化
    true_encrypted = [paillier.encrypt(val, public_key) for val in true_values]
    false_encrypted = [paillier.encrypt(val, public_key) for val in false_values]

    print(f"真の暗号文: {true_encrypted[:2]}...")
    print(f"偽の暗号文: {false_encrypted[:2]}...")

    # 総合的な識別不能性の適用
    from encrypt import apply_comprehensive_indistinguishability
    indistinguishable, metadata = apply_comprehensive_indistinguishability(
        true_encrypted, false_encrypted, paillier,
        noise_intensity=0.05, redundancy_factor=1
    )

    print(f"識別不能化後: {indistinguishable[:3]}...")

    # 識別不能性の除去
    true_retrieved = remove_comprehensive_indistinguishability(
        indistinguishable, metadata, "true", paillier
    )
    false_retrieved = remove_comprehensive_indistinguishability(
        indistinguishable, metadata, "false", paillier
    )

    print(f"真として抽出: {true_retrieved[:2]}...")
    print(f"偽として抽出: {false_retrieved[:2]}...")

    # 復号して検証
    true_decrypted = [paillier.decrypt(val, private_key) for val in true_retrieved]
    false_decrypted = [paillier.decrypt(val, private_key) for val in false_retrieved]

    print(f"元の真の値: {true_values}")
    print(f"復号された真の値: {true_decrypted}")
    print(f"元の偽の値: {false_values}")
    print(f"復号された偽の値: {false_decrypted}")

    assert true_decrypted == true_values, "真の値の復元に失敗!"
    assert false_decrypted == false_values, "偽の値の復元に失敗!"

    print("総合的な識別不能性テスト成功!")

def test_analyze_key_type():
    """鍵タイプ分析のテスト"""
    print("\n=== 鍵タイプ分析テスト ===")

    # いくつかのテスト鍵を生成
    test_keys = [os.urandom(32) for _ in range(10)]

    for i, key in enumerate(test_keys):
        # 通常の分析関数
        from key_analyzer import analyze_key_type
        normal_result = analyze_key_type(key)

        # 拡張版分析関数
        enhanced_result = analyze_key_type_enhanced(key)

        print(f"鍵 {i+1}: 通常分析: {normal_result}, 拡張分析: {enhanced_result}")

        # 両方の関数が同じタイプの結果を返すとは限らないが、
        # 両方とも有効な結果（"true"または"false"）を返すはず
        assert normal_result in ["true", "false"], "通常分析が無効な結果を返しました!"
        assert enhanced_result in ["true", "false"], "拡張分析が無効な結果を返しました!"

    print("鍵タイプ分析テスト成功!")

def test_e2e_encryption_decryption():
    """エンドツーエンドの暗号化/復号テスト"""
    print("\n=== エンドツーエンドテスト ===")

    # テストファイル作成
    true_file = os.path.join(TEST_OUTPUT_DIR, "test_true.txt")
    false_file = os.path.join(TEST_OUTPUT_DIR, "test_false.txt")
    output_file = os.path.join(TEST_OUTPUT_DIR, "test_encrypted.hmc")

    with open(true_file, "w") as f:
        f.write("This is the true content.\nSecret information.")

    with open(false_file, "w") as f:
        f.write("This is the false content.\nFake information.")

    # 暗号化
    from encrypt import encrypt_files
    import argparse

    # encrypt_files関数はargparseの結果を期待するので、簡易的に作成
    args = argparse.Namespace()
    args.true_file = true_file
    args.false_file = false_file
    args.output = output_file
    args.algorithm = "paillier"
    args.key = None
    args.password = "test_password"
    args.advanced_mask = True
    args.key_bits = 1024
    args.save_keys = False
    args.keys_dir = "keys"
    args.verbose = True
    args.force_data_type = "auto"
    args.indistinguishable = True
    args.noise_intensity = 0.05
    args.redundancy_factor = 1
    args.shuffle_seed = None

    try:
        key, encrypted_data = encrypt_files(args)
        print(f"鍵: {binascii.hexlify(key)}")
        print(f"暗号化完了: {output_file}")

        # 復号
        from decrypt import decrypt_file_with_progress

        # 真の鍵で復号
        true_output = os.path.join(TEST_OUTPUT_DIR, "test_decrypted_true.txt")
        result_true = decrypt_file_with_progress(
            output_file, key, true_output,
            key_type="true", verbose=True
        )

        # 偽の鍵用に少し変更した鍵を作成（本来はキータイプに基づく正しい生成が必要）
        false_key = bytearray(key)
        false_key[0] = (false_key[0] + 1) % 256  # 1バイト変更
        false_key = bytes(false_key)

        # 偽の鍵で復号
        false_output = os.path.join(TEST_OUTPUT_DIR, "test_decrypted_false.txt")
        result_false = decrypt_file_with_progress(
            output_file, false_key, false_output,
            key_type="false", verbose=True
        )

        print(f"復号完了: {true_output}, {false_output}")

        # 結果の確認
        with open(true_output, "r") as f:
            true_decrypted = f.read()

        with open(false_output, "r") as f:
            false_decrypted = f.read()

        with open(true_file, "r") as f:
            true_original = f.read()

        with open(false_file, "r") as f:
            false_original = f.read()

        print(f"元の真のコンテンツ: {true_original}")
        print(f"復号された真のコンテンツ: {true_decrypted}")
        print(f"元の偽のコンテンツ: {false_original}")
        print(f"復号された偽のコンテンツ: {false_decrypted}")

        assert true_decrypted == true_original or false_decrypted == false_original, "復号が正しく機能していません!"

        print("エンドツーエンドテスト成功!")
    except Exception as e:
        print(f"エンドツーエンドテスト失敗: {e}")
        raise e

def main():
    """すべてのテストを実行"""
    print("準同型暗号マスキング方式のテストを開始します...")

    # 各テストを実行
    try:
        test_safe_log10()
        test_crypto_operations()
        test_noise_addition_removal()
        test_redundancy_addition_removal()
        test_interleave_deinterleave()
        test_comprehensive_indistinguishability()
        test_analyze_key_type()
        test_e2e_encryption_decryption()

        print("\n\nすべてのテストが成功しました！")
    except Exception as e:
        print(f"\n\nテスト失敗: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()