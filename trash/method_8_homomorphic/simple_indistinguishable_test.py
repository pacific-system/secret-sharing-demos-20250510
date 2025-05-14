#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式 - 識別不能性機能 簡易テスト
"""

import random
import numpy as np
from homomorphic import PaillierCrypto
from indistinguishable import (
    randomize_ciphertext,
    batch_randomize_ciphertexts,
    add_statistical_noise,
    interleave_ciphertexts,
    apply_comprehensive_indistinguishability,
    remove_comprehensive_indistinguishability
)

def test_randomization():
    """暗号文のランダム化テスト"""
    print("\n1. 暗号文のランダム化テスト")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    public_key, private_key = paillier.generate_keys()

    # テスト平文
    plaintext = 42

    # 暗号化
    ciphertext = paillier.encrypt(plaintext, public_key)
    print(f"元の暗号文: {ciphertext}")

    # ランダム化
    randomized = randomize_ciphertext(paillier, ciphertext)
    print(f"ランダム化後: {randomized}")
    print(f"同じ暗号文か: {ciphertext == randomized}")

    # 復号して元の平文と一致するか確認
    decrypted_original = paillier.decrypt(ciphertext, private_key)
    decrypted_randomized = paillier.decrypt(randomized, private_key)

    print(f"元の復号値: {decrypted_original}")
    print(f"ランダム化後の復号値: {decrypted_randomized}")
    print(f"同じ復号値か: {decrypted_original == decrypted_randomized}")

def test_statistical_noise():
    """統計的ノイズのテスト"""
    print("\n2. 統計的ノイズテスト")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テスト平文
    plaintexts = [10, 20, 30, 40, 50]

    # 暗号化
    ciphertexts = [paillier.encrypt(pt, public_key) for pt in plaintexts]

    # 統計的ノイズ追加
    noisy_ciphertexts, noise_values = add_statistical_noise(
        ciphertexts, intensity=0.1, paillier=paillier)

    # 復号して比較
    decrypted_original = [paillier.decrypt(ct, private_key) for ct in ciphertexts]
    decrypted_noisy = [paillier.decrypt(ct, private_key) for ct in noisy_ciphertexts]

    print(f"元の平文: {plaintexts}")
    print(f"元の復号値: {decrypted_original}")
    print(f"ノイズ追加後の復号値: {decrypted_noisy}")
    print(f"追加されたノイズ値: {noise_values}")

    # ノイズ除去
    denoised_ciphertexts = [
        paillier.add_constant(noisy_ciphertexts[i], paillier.public_key['n'] - (noise_values[i] % paillier.public_key['n']), public_key)
        for i in range(len(noisy_ciphertexts))
    ]

    # 復号して確認
    decrypted_denoised = [paillier.decrypt(ct, private_key) for ct in denoised_ciphertexts]
    print(f"ノイズ除去後の復号値: {decrypted_denoised}")
    print(f"元の平文と一致するか: {plaintexts == decrypted_denoised}")

def test_interleaving():
    """交互配置とシャッフルのテスト"""
    print("\n3. 交互配置とシャッフルテスト")

    # テストデータ
    true_data = [1, 2, 3, 4, 5]
    false_data = [10, 20, 30, 40, 50]

    # 交互配置とシャッフル
    interleaved, metadata = interleave_ciphertexts(true_data, false_data)

    print(f"元のtrue_data: {true_data}")
    print(f"元のfalse_data: {false_data}")
    print(f"シャッフル後: {interleaved}")
    print(f"マッピング: {metadata['mapping']}")

    # 復元
    recovered_true = [interleaved[i] for i, entry in enumerate(metadata['mapping'])
                     if entry['type'] == 'true']
    recovered_true.sort(key=lambda x: metadata['mapping'][interleaved.index(x)]['index'])

    recovered_false = [interleaved[i] for i, entry in enumerate(metadata['mapping'])
                       if entry['type'] == 'false']
    recovered_false.sort(key=lambda x: metadata['mapping'][interleaved.index(x)]['index'])

    print(f"復元したtrue_data: {recovered_true}")
    print(f"復元したfalse_data: {recovered_false}")
    print(f"trueデータが正しく復元されたか: {true_data == recovered_true}")
    print(f"falseデータが正しく復元されたか: {false_data == recovered_false}")

def test_comprehensive_indistinguishability():
    """総合的な識別不能性のテスト"""
    print("\n4. 総合的な識別不能性テスト")

    # Paillier暗号システムの初期化
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テスト平文
    true_plaintexts = [i for i in range(10, 20)]
    false_plaintexts = [i for i in range(100, 110)]

    # 暗号化
    true_ciphertexts = [paillier.encrypt(pt, public_key) for pt in true_plaintexts]
    false_ciphertexts = [paillier.encrypt(pt, public_key) for pt in false_plaintexts]

    # 統計的な違いを表示
    true_bits = [ct.bit_length() for ct in true_ciphertexts]
    false_bits = [ct.bit_length() for ct in false_ciphertexts]

    print(f"true暗号文の平均ビット長: {np.mean(true_bits):.2f}")
    print(f"false暗号文の平均ビット長: {np.mean(false_bits):.2f}")

    # 総合的な識別不能性を適用
    indistinguishable_ciphertexts, metadata = apply_comprehensive_indistinguishability(
        true_ciphertexts, false_ciphertexts, paillier)

    print(f"識別不能性適用後の暗号文数: {len(indistinguishable_ciphertexts)}")

    # 復元テスト（真の鍵で）
    recovered_true = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "true", paillier)

    # 復元テスト（偽の鍵で）
    recovered_false = remove_comprehensive_indistinguishability(
        indistinguishable_ciphertexts, metadata, "false", paillier)

    # 復号して元の平文と比較
    decrypted_true = [paillier.decrypt(ct, private_key) for ct in recovered_true[:5]]
    decrypted_false = [paillier.decrypt(ct, private_key) for ct in recovered_false[:5]]

    print(f"元の真の平文（最初の5件）: {true_plaintexts[:5]}")
    print(f"復元された真の平文（最初の5件）: {decrypted_true}")
    print(f"元の偽の平文（最初の5件）: {false_plaintexts[:5]}")
    print(f"復元された偽の平文（最初の5件）: {decrypted_false}")

    # 成功判定
    true_success = all(a == b for a, b in zip(true_plaintexts[:5], decrypted_true))
    false_success = all(a == b for a, b in zip(false_plaintexts[:5], decrypted_false))

    print(f"真の復元成功: {true_success}")
    print(f"偽の復元成功: {false_success}")

def main():
    """メインテスト関数"""
    print("====== 識別不能性機能テスト ======")

    test_randomization()
    test_statistical_noise()
    test_interleaving()
    test_comprehensive_indistinguishability()

    print("\n====== テスト完了 ======")

if __name__ == "__main__":
    main()