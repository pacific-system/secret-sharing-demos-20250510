#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の全テストを実行するスクリプト

このスクリプトは、準同型暗号マスキング方式のすべてのテストを実行します。
"""

import os
import sys
import unittest
import time
import matplotlib.pyplot as plt
import numpy as np

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))


def run_tests():
    """全てのテストを実行"""
    print("準同型暗号マスキング方式テストスイートを実行中...")
    start_time = time.time()

    # テストを検出してロード
    test_loader = unittest.TestLoader()

    # ディレクトリを取得
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # テストスイート作成
    test_suite = unittest.TestSuite()

    # 個別のテストモジュールを追加
    from method_8_homomorphic.tests import test_homomorphic
    from method_8_homomorphic.tests import test_encrypt_decrypt
    from method_8_homomorphic.tests import test_indistinguishability

    # 各テストモジュールからのテストを追加
    test_suite.addTest(unittest.makeSuite(test_homomorphic.TestPaillierCrypto))
    test_suite.addTest(unittest.makeSuite(test_homomorphic.TestElGamalCrypto))
    test_suite.addTest(unittest.makeSuite(test_encrypt_decrypt.TestEncryptDecrypt))
    test_suite.addTest(unittest.makeSuite(test_indistinguishability.TestIndistinguishability))

    # テスト実行
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)

    # 結果の表示
    elapsed_time = time.time() - start_time
    print(f"\nテスト完了（所要時間: {elapsed_time:.2f}秒）")
    print(f"テスト数: {result.testsRun}")
    print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失敗: {len(result.failures)}")
    print(f"エラー: {len(result.errors)}")

    # グラフの生成
    generate_test_graphs()

    # 終了コード設定
    return 0 if result.wasSuccessful() else 1


def generate_test_graphs():
    """テスト結果のグラフを生成"""
    print("テスト結果のグラフを生成中...")

    # テスト出力ディレクトリを確認
    output_dir = "test_output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 識別不能性テストのための分布グラフ生成
    generate_indistinguishability_graph(output_dir)

    # 性能テストグラフの生成
    generate_performance_graph(output_dir)


def generate_indistinguishability_graph(output_dir):
    """識別不能性テストのグラフ生成"""
    # 1000個のランダム鍵を生成して真/偽の判定を収集
    from method_8_homomorphic.indistinguishable import IndistinguishableWrapper
    from method_8_homomorphic.config import KEY_SIZE_BYTES, SALT_SIZE

    indist = IndistinguishableWrapper()
    salt = os.urandom(SALT_SIZE)

    # ビット位置ごとの判定結果を収集
    bit_results = [[] for _ in range(8)]

    # 各ビット位置でテスト
    for bit_pos in range(8):
        true_count = 0
        results = []

        for _ in range(100):
            # ランダムな鍵を生成
            key = os.urandom(KEY_SIZE_BYTES)

            # 特定ビットが1の場合と0の場合で調査
            bit_key = bytearray(key)
            # 指定ビットが1であることを確認
            bit_key[0] = bit_key[0] | (1 << bit_pos)
            bit_key = bytes(bit_key)

            indist.generate_seed(bit_key, salt)
            result = indist.is_true_path(bit_key, salt)
            results.append(1 if result else 0)
            if result:
                true_count += 1

        bit_results[bit_pos] = results

    # グラフ作成
    plt.figure(figsize=(10, 6))

    # ヒストグラム用データ
    counts = [sum(results) for results in bit_results]

    # 棒グラフ作成
    plt.bar(range(8), counts, color='royalblue')
    plt.axhline(y=50, color='r', linestyle='--', label='Expected (50)')

    plt.title('Distribution of True Path by Bit Position')
    plt.xlabel('Bit Position')
    plt.ylabel('Number of True Results (out of 100)')
    plt.legend()
    plt.xticks(range(8))
    plt.ylim(0, 100)
    plt.grid(True, alpha=0.3)

    # グラフ保存
    plt.savefig(os.path.join(output_dir, 'indistinguishability_distribution.png'))
    plt.close()


def generate_performance_graph(output_dir):
    """暗号化・復号のパフォーマンステスト結果グラフ生成"""
    from method_8_homomorphic.homomorphic import PaillierCrypto, ElGamalCrypto

    # テストデータサイズ
    sizes = [10, 100, 1000, 10000]

    # 時間計測結果
    paillier_encrypt_times = []
    paillier_decrypt_times = []
    elgamal_encrypt_times = []
    elgamal_decrypt_times = []

    # Paillier暗号のテスト
    paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
    paillier_public, paillier_private = paillier.generate_keys()

    # ElGamal暗号のテスト
    elgamal = ElGamalCrypto(bits=512)  # テスト用に小さいビット数
    elgamal_public, elgamal_private = elgamal.generate_keys()

    # 各サイズでテスト
    for size in sizes:
        # テストデータ生成
        test_data = random.randint(1, 10**size)

        # Paillier暗号化時間
        start_time = time.time()
        paillier_enc = paillier.encrypt(test_data, paillier_public)
        paillier_encrypt_times.append(time.time() - start_time)

        # Paillier復号時間
        start_time = time.time()
        paillier.decrypt(paillier_enc, paillier_private)
        paillier_decrypt_times.append(time.time() - start_time)

        # ElGamal暗号化時間
        start_time = time.time()
        elgamal_enc = elgamal.encrypt(test_data % elgamal_public["p"], elgamal_public)
        elgamal_encrypt_times.append(time.time() - start_time)

        # ElGamal復号時間
        start_time = time.time()
        elgamal.decrypt(elgamal_enc, elgamal_private)
        elgamal_decrypt_times.append(time.time() - start_time)

    # グラフ作成
    plt.figure(figsize=(12, 8))

    x = np.arange(len(sizes))
    width = 0.2

    plt.bar(x - width*1.5, paillier_encrypt_times, width, label='Paillier Encrypt')
    plt.bar(x - width/2, paillier_decrypt_times, width, label='Paillier Decrypt')
    plt.bar(x + width/2, elgamal_encrypt_times, width, label='ElGamal Encrypt')
    plt.bar(x + width*1.5, elgamal_decrypt_times, width, label='ElGamal Decrypt')

    plt.xlabel('Data Size (10^n)')
    plt.ylabel('Time (seconds)')
    plt.title('Encryption/Decryption Performance')
    plt.xticks(x, [f'10^{int(np.log10(size))}' for size in sizes])
    plt.legend()
    plt.grid(True, alpha=0.3)

    # グラフ保存
    plt.savefig(os.path.join(output_dir, 'cryptography_performance.png'))
    plt.close()


if __name__ == "__main__":
    import random
    sys.exit(run_tests())