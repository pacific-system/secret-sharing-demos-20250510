#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号デモスクリプト

このスクリプトは、準同型暗号の基本機能をわかりやすくデモします。
Paillier暗号（加法準同型）とElGamal暗号（乗法準同型）の両方を使用し、
暗号文のまま演算が可能であることを視覚的に示します。
"""

import os
import sys
import time
import random
import matplotlib.pyplot as plt
import numpy as np

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, serialize_encrypted_data, deserialize_encrypted_data
)


def print_header(text):
    """ヘッダーテキストを出力"""
    print("\n" + "=" * 80)
    print(f" {text} ".center(80, "="))
    print("=" * 80)


def print_subheader(text):
    """サブヘッダーテキストを出力"""
    print("\n" + "-" * 60)
    print(f" {text} ".center(60, "-"))
    print("-" * 60)


def demo_paillier_basic():
    """Paillier暗号の基本機能デモ"""
    print_header("Paillier暗号の基本機能デモ（加法準同型）")

    # Paillierインスタンス作成（デモ用に小さいビット数）
    print("鍵の生成中...")
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    print(f"公開鍵 (n): {public_key['n']}")
    print(f"秘密鍵 (λ): {private_key['lambda']}")

    # 基本的な暗号化と復号
    print_subheader("基本的な暗号化と復号")
    message = 42
    print(f"元のメッセージ: {message}")

    encrypted = paillier.encrypt(message, public_key)
    print(f"暗号化されたメッセージ: {encrypted}")

    decrypted = paillier.decrypt(encrypted, private_key)
    print(f"復号されたメッセージ: {decrypted}")
    print(f"復号成功: {message == decrypted}")

    # 別のメッセージを暗号化
    print_subheader("別のメッセージの暗号化")
    message2 = 31
    print(f"2つ目のメッセージ: {message2}")

    encrypted2 = paillier.encrypt(message2, public_key)
    print(f"暗号化されたメッセージ2: {encrypted2}")

    # 加法準同型性のデモ
    print_subheader("加法準同型性のデモ")
    print(f"平文での計算: {message} + {message2} = {message + message2}")

    encrypted_sum = paillier.add(encrypted, encrypted2, public_key)
    print(f"暗号文のまま加算: {encrypted} × {encrypted2} = {encrypted_sum}")

    decrypted_sum = paillier.decrypt(encrypted_sum, private_key)
    print(f"加算結果の復号: {decrypted_sum}")
    print(f"正しい結果: {message + message2 == decrypted_sum}")

    # 定数倍のデモ
    print_subheader("暗号文の定数倍（スカラー乗算）")
    scalar = 5
    print(f"スカラー値: {scalar}")
    print(f"平文での計算: {message} × {scalar} = {message * scalar}")

    encrypted_mul = paillier.multiply_constant(encrypted, scalar, public_key)
    print(f"暗号文のままスカラー乗算: (結果: {encrypted_mul})")

    decrypted_mul = paillier.decrypt(encrypted_mul, private_key)
    print(f"乗算結果の復号: {decrypted_mul}")
    print(f"正しい結果: {message * scalar == decrypted_mul}")

    # 定数加算のデモ
    print_subheader("暗号文への定数加算")
    constant = 17
    print(f"定数: {constant}")
    print(f"平文での計算: {message} + {constant} = {message + constant}")

    encrypted_add = paillier.add_constant(encrypted, constant, public_key)
    print(f"暗号文のまま定数加算: (結果: {encrypted_add})")

    decrypted_add = paillier.decrypt(encrypted_add, private_key)
    print(f"加算結果の復号: {decrypted_add}")
    print(f"正しい結果: {message + constant == decrypted_add}")


def demo_elgamal_basic():
    """ElGamal暗号の基本機能デモ"""
    print_header("ElGamal暗号の基本機能デモ（乗法準同型）")

    # ElGamalインスタンス作成（デモ用に小さいビット数）
    print("鍵の生成中...")
    elgamal = ElGamalCrypto(bits=512)
    public_key, private_key = elgamal.generate_keys()

    print(f"公開鍵 (p): {public_key['p']}")
    print(f"秘密鍵 (x): {private_key['x']}")

    # 基本的な暗号化と復号
    print_subheader("基本的な暗号化と復号")
    message = 11
    print(f"元のメッセージ: {message}")

    encrypted = elgamal.encrypt(message, public_key)
    print(f"暗号化されたメッセージ: {encrypted}")

    decrypted = elgamal.decrypt(encrypted, private_key)
    print(f"復号されたメッセージ: {decrypted}")
    print(f"復号成功: {message == decrypted}")

    # 別のメッセージを暗号化
    print_subheader("別のメッセージの暗号化")
    message2 = 7
    print(f"2つ目のメッセージ: {message2}")

    encrypted2 = elgamal.encrypt(message2, public_key)
    print(f"暗号化されたメッセージ2: {encrypted2}")

    # 乗法準同型性のデモ
    print_subheader("乗法準同型性のデモ")
    print(f"平文での計算: {message} × {message2} = {message * message2}")

    encrypted_mul = elgamal.multiply(encrypted, encrypted2, public_key)
    print(f"暗号文のまま乗算: {encrypted} * {encrypted2} = {encrypted_mul}")

    decrypted_mul = elgamal.decrypt(encrypted_mul, private_key)
    print(f"乗算結果の復号: {decrypted_mul}")
    print(f"正しい結果: {message * message2 == decrypted_mul}")

    # 指数乗のデモ
    print_subheader("暗号文の指数乗（スカラー冪乗）")
    exponent = 3
    print(f"指数: {exponent}")
    print(f"平文での計算: {message} ^ {exponent} = {message ** exponent}")

    encrypted_pow = elgamal.pow_constant(encrypted, exponent, public_key)
    print(f"暗号文のまま指数乗: (結果: {encrypted_pow})")

    decrypted_pow = elgamal.decrypt(encrypted_pow, private_key)
    print(f"指数乗結果の復号: {decrypted_pow}")
    print(f"正しい結果: {message ** exponent == decrypted_pow}")


def demo_binary_data():
    """バイナリデータの暗号化デモ"""
    print_header("バイナリデータの暗号化デモ")

    # Paillierインスタンス作成
    paillier = PaillierCrypto(bits=1024)
    public_key, private_key = paillier.generate_keys()

    # テキストデータ
    text = "これは準同型暗号でのバイナリデータ暗号化のデモです。Hello, Homomorphic Encryption! 🔐"
    print(f"元のテキスト: {text}")

    # テキストをバイトデータに変換
    byte_data = text.encode('utf-8')
    print(f"バイトデータの長さ: {len(byte_data)} バイト")

    print("\nバイナリデータを暗号化中...")
    start_time = time.time()
    encrypted_chunks = paillier.encrypt_bytes(byte_data, public_key)
    encryption_time = time.time() - start_time

    print(f"暗号化チャンク数: {len(encrypted_chunks)}")
    print(f"暗号化時間: {encryption_time:.4f} 秒")

    # シリアライズのデモ
    print_subheader("暗号化データのシリアライズ")
    serialized = serialize_encrypted_data(encrypted_chunks, len(byte_data), "paillier")
    print(f"シリアライズされたデータのキー: {list(serialized.keys())}")

    # デシリアライズのデモ
    print("\nシリアライズデータからの復元...")
    deserialized_chunks, original_size, crypto_type = deserialize_encrypted_data(serialized)
    print(f"復元されたチャンク数: {len(deserialized_chunks)}")
    print(f"元のサイズ: {original_size}, 暗号方式: {crypto_type}")

    # 復号のデモ
    print("\nバイナリデータを復号中...")
    start_time = time.time()
    decrypted_data = paillier.decrypt_bytes(deserialized_chunks, original_size, private_key)
    decryption_time = time.time() - start_time

    decrypted_text = decrypted_data.decode('utf-8')
    print(f"復号されたテキスト: {decrypted_text}")
    print(f"復号時間: {decryption_time:.4f} 秒")
    print(f"復号成功: {text == decrypted_text}")


def demo_password_key_derivation():
    """パスワードからの鍵導出デモ"""
    print_header("パスワードからの鍵導出デモ")

    password = "secure_password_123"
    print(f"パスワード: {password}")

    # ソルトの生成
    salt = os.urandom(16)
    print(f"ソルト: {salt.hex()}")

    print("\nPaillier暗号の鍵を導出中...")
    start_time = time.time()
    pub1, priv1, _ = derive_key_from_password(password, salt, "paillier")
    derivation_time = time.time() - start_time

    print(f"鍵導出時間: {derivation_time:.4f} 秒")
    print(f"公開鍵 (n): {pub1['n']}")
    print(f"秘密鍵 (λ): {priv1['lambda']}")

    print("\n同じパスワードとソルトで再導出...")
    pub2, priv2, _ = derive_key_from_password(password, salt, "paillier")

    print(f"鍵の一致: {'成功' if pub1['n'] == pub2['n'] else '失敗'}")

    print("\n異なるパスワードでの導出...")
    different_password = "different_password_456"
    pub3, priv3, _ = derive_key_from_password(different_password, salt, "paillier")

    print(f"異なる鍵の生成: {'成功' if pub1['n'] != pub3['n'] else '失敗'}")

    # メッセージの暗号化と復号
    print_subheader("導出された鍵でのメッセージ暗号化と復号")

    paillier = PaillierCrypto()
    paillier.public_key = pub1
    paillier.private_key = priv1

    message = 42
    print(f"メッセージ: {message}")

    encrypted = paillier.encrypt(message, pub1)
    print(f"暗号化されたメッセージ: {encrypted}")

    decrypted = paillier.decrypt(encrypted, priv1)
    print(f"復号されたメッセージ: {decrypted}")
    print(f"復号成功: {message == decrypted}")


def generate_performance_graphs():
    """パフォーマンスグラフの生成"""
    print_header("パフォーマンスグラフ生成")

    # 鍵サイズと処理時間の関係を測定
    key_sizes = [512, 1024, 2048]
    paillier_times = []
    elgamal_times = []

    print("各鍵サイズでの処理時間を測定中...")

    for size in key_sizes:
        print(f"\n鍵サイズ {size} ビット:")

        # Paillier
        start_time = time.time()
        paillier = PaillierCrypto(bits=size)
        public_key, private_key = paillier.generate_keys()
        key_gen_time = time.time() - start_time
        print(f"  Paillier鍵生成時間: {key_gen_time:.4f} 秒")

        # 暗号化・復号の時間測定
        message = 12345

        start_time = time.time()
        encrypted = paillier.encrypt(message, public_key)
        encrypt_time = time.time() - start_time
        print(f"  Paillier暗号化時間: {encrypt_time:.4f} 秒")

        start_time = time.time()
        _ = paillier.decrypt(encrypted, private_key)
        decrypt_time = time.time() - start_time
        print(f"  Paillier復号時間: {decrypt_time:.4f} 秒")

        paillier_times.append((key_gen_time, encrypt_time, decrypt_time))

        # ElGamal
        if size <= 1024:  # ElGamalは大きなサイズだと非常に遅くなるので制限
            start_time = time.time()
            elgamal = ElGamalCrypto(bits=size)
            el_public_key, el_private_key = elgamal.generate_keys()
            el_key_gen_time = time.time() - start_time
            print(f"  ElGamal鍵生成時間: {el_key_gen_time:.4f} 秒")

            start_time = time.time()
            el_encrypted = elgamal.encrypt(message, el_public_key)
            el_encrypt_time = time.time() - start_time
            print(f"  ElGamal暗号化時間: {el_encrypt_time:.4f} 秒")

            start_time = time.time()
            _ = elgamal.decrypt(el_encrypted, el_private_key)
            el_decrypt_time = time.time() - start_time
            print(f"  ElGamal復号時間: {el_decrypt_time:.4f} 秒")

            elgamal_times.append((el_key_gen_time, el_encrypt_time, el_decrypt_time))
        else:
            elgamal_times.append((0, 0, 0))  # ダミーデータ

    # グラフの作成
    print("\nパフォーマンスグラフを生成中...")

    plt.figure(figsize=(15, 10))

    # Paillierのグラフ
    plt.subplot(2, 1, 1)
    bar_width = 0.2
    index = np.arange(len(key_sizes))

    # 鍵生成時間
    plt.bar(index, [p[0] for p in paillier_times], bar_width, label='鍵生成')

    # 暗号化時間
    plt.bar(index + bar_width, [p[1] for p in paillier_times], bar_width, label='暗号化')

    # 復号時間
    plt.bar(index + 2 * bar_width, [p[2] for p in paillier_times], bar_width, label='復号')

    plt.title('Paillier暗号の処理時間（鍵サイズ別）')
    plt.xlabel('鍵サイズ（ビット）')
    plt.ylabel('処理時間（秒）')
    plt.xticks(index + bar_width, key_sizes)
    plt.legend()
    plt.grid(True, alpha=0.3)

    # ElGamalのグラフ
    plt.subplot(2, 1, 2)

    # 有効なElGamalデータのみ使用
    valid_sizes = key_sizes[:2]  # 512, 1024のみ
    valid_data = elgamal_times[:2]

    index = np.arange(len(valid_sizes))

    # 鍵生成時間
    plt.bar(index, [e[0] for e in valid_data], bar_width, label='鍵生成')

    # 暗号化時間
    plt.bar(index + bar_width, [e[1] for e in valid_data], bar_width, label='暗号化')

    # 復号時間
    plt.bar(index + 2 * bar_width, [e[2] for e in valid_data], bar_width, label='復号')

    plt.title('ElGamal暗号の処理時間（鍵サイズ別）')
    plt.xlabel('鍵サイズ（ビット）')
    plt.ylabel('処理時間（秒）')
    plt.xticks(index + bar_width, valid_sizes)
    plt.legend()
    plt.grid(True, alpha=0.3)

    plt.tight_layout()

    # グラフの保存
    output_path = "test_output/cryptography_performance.png"
    plt.savefig(output_path)
    print(f"グラフを保存しました: {output_path}")


def main():
    """メイン関数"""
    # 出力ディレクトリの確認
    os.makedirs("test_output", exist_ok=True)

    print("準同型暗号の基本機能デモプログラム")
    print("=" * 50)

    # デモの実行
    demo_paillier_basic()
    demo_elgamal_basic()
    demo_binary_data()
    demo_password_key_derivation()
    generate_performance_graphs()

    print("\n" + "=" * 50)
    print("デモが完了しました。")
    print(f"グラフは test_output/ ディレクトリに保存されています。")


if __name__ == "__main__":
    main()