#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号システム - Homomorphic Encryption System

このモジュールは、準同型性を持つ暗号化システムを実装します。主にPaillier暗号アルゴリズムに
基づいており、暗号化されたデータに対して限定的な演算を可能にします。

Paillier暗号システムは加法準同型性を持ち、暗号化された値同士の加算や、
暗号化された値と平文値の乗算をサポートします。
"""

import os
import random
import hashlib
import math
import secrets
import json
import base64
import time
from typing import Tuple, Dict, Any, Union, List, Optional
import sympy
from sympy import mod_inverse

from config import (
    PAILLIER_KEY_BITS,
    PAILLIER_PRECISION,
    ELGAMAL_KEY_BITS,
    KDF_ITERATIONS,
    SALT_SIZE
)


class PaillierCrypto:
    """
    Paillier暗号システムの実装

    加法準同型性を持つPaillier暗号アルゴリズムを実装します。
    暗号化されたデータに対する加算演算と、暗号化されたデータと平文の乗算をサポートします。
    """

    def __init__(self, bits: int = PAILLIER_KEY_BITS, key_bytes: Optional[bytes] = None):
        """
        初期化

        Args:
            bits: 鍵長（ビット数）
            key_bytes: 鍵のバイトデータ（省略可）
        """
        self.bits = bits
        self.precision = PAILLIER_PRECISION
        self.n = 0
        self.g = 0
        self.lambda_val = 0
        self.mu = 0
        self.public_key = None
        self.private_key = None

        # key_bytesが指定されている場合は鍵を導出
        if key_bytes is not None:
            # 鍵からシード値を生成
            seed = hashlib.sha256(key_bytes).digest()
            seed_int = int.from_bytes(seed, 'big')

            # シードを基に鍵を生成
            random.seed(seed_int)
            try:
                self.public_key, self.private_key = self.generate_keys()
            except Exception as e:
                print(f"鍵生成中にエラーが発生しました: {e}")
                # エラー時はデフォルト鍵を生成
                random.seed(0)  # 決定論的に生成
                self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """
        Paillier暗号の鍵ペアを生成

        Returns:
            (公開鍵, 秘密鍵)のタプル
        """
        # 2つの同じサイズの大きな素数を生成
        p = sympy.randprime(2**(self.bits//2-1), 2**(self.bits//2))
        q = sympy.randprime(2**(self.bits//2-1), 2**(self.bits//2))

        # n = p * q
        n = p * q

        # λ = lcm(p-1, q-1)
        lambda_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)

        # g は通常 n+1 を使用
        g = n + 1

        # μ = (L(g^λ mod n^2))^(-1) mod n
        # ここで L(x) = (x-1)/n
        # g^λ mod n^2 を計算
        g_lambda = pow(g, lambda_val, n * n)

        # L(g_lambda) = (g_lambda - 1) / n
        l_g_lambda = (g_lambda - 1) // n

        # μ = l_g_lambda^(-1) mod n
        mu = mod_inverse(l_g_lambda, n)

        # 公開鍵と秘密鍵を設定
        self.n = n
        self.g = g
        self.lambda_val = lambda_val
        self.mu = mu

        public_key = {'n': n, 'g': g}
        private_key = {'lambda': lambda_val, 'mu': mu, 'p': p, 'q': q, 'n': n}

        self.public_key = public_key
        self.private_key = private_key

        return public_key, private_key

    def encrypt(self, m: int, public_key: Dict[str, int] = None) -> int:
        """
        メッセージを暗号化

        Args:
            m: 暗号化する整数値
            public_key: 公開鍵（指定がなければ内部の鍵を使用）

        Returns:
            暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = public_key['n']
        g = public_key['g']

        # 0 <= m < n の範囲に収める
        m = m % n

        # 乱数 r (0 < r < n) を生成
        r = random.randint(1, n - 1)

        # 暗号文 c = g^m * r^n mod n^2
        n_squared = n * n
        g_m = pow(g, m, n_squared)
        r_n = pow(r, n, n_squared)
        c = (g_m * r_n) % n_squared

        return c

    def decrypt(self, c: int, private_key: Dict[str, int] = None) -> int:
        """
        暗号文を復号

        Args:
            c: 復号する暗号文
            private_key: 秘密鍵（指定がなければ内部の鍵を使用）

        Returns:
            復号された整数値
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        # リスト型の場合は最初の要素を使用（互換性のため）
        if isinstance(c, list):
            if len(c) > 0:
                c = c[0]
            else:
                raise ValueError("暗号文リストが空です")

        n = private_key['n']
        lambda_val = private_key['lambda']
        mu = private_key['mu']

        # L(c^λ mod n^2) * μ mod n を計算
        n_squared = n * n

        # c^λ mod n^2
        c_lambda = pow(c, lambda_val, n_squared)

        # L(c_lambda) = (c_lambda - 1) / n
        l_c_lambda = (c_lambda - 1) // n

        # m = L(c_lambda) * μ mod n
        m = (l_c_lambda * mu) % n

        return m

    def encrypt_float(self, m: float, public_key: Dict[str, int] = None) -> int:
        """
        浮動小数点数を暗号化

        Args:
            m: 暗号化する浮動小数点数
            public_key: 公開鍵

        Returns:
            暗号文
        """
        # 浮動小数点数を整数に変換
        m_int = int(m * self.precision)
        return self.encrypt(m_int, public_key)

    def decrypt_float(self, c: int, private_key: Dict[str, int] = None) -> float:
        """
        暗号文を浮動小数点数に復号

        Args:
            c: 復号する暗号文
            private_key: 秘密鍵

        Returns:
            復号された浮動小数点数
        """
        m_int = self.decrypt(c, private_key)
        return m_int / self.precision

    def add(self, c1: int, c2: int, public_key: Dict[str, int] = None) -> int:
        """
        暗号文同士の加算（平文では m1 + m2 に相当）

        Args:
            c1: 1つ目の暗号文
            c2: 2つ目の暗号文
            public_key: 公開鍵

        Returns:
            加算結果の暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n_squared = public_key['n'] * public_key['n']
        return (c1 * c2) % n_squared

    def add_constant(self, c: int, k: int, public_key: Dict[str, int] = None) -> int:
        """
        暗号文に定数を加算（平文では m + k に相当）

        Args:
            c: 暗号文
            k: 加算する定数
            public_key: 公開鍵

        Returns:
            加算結果の暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = public_key['n']
        g = public_key['g']
        n_squared = n * n

        # 定数がnを超えないようにする
        k = k % n

        # g^k mod n^2
        g_k = pow(g, k, n_squared)

        # c * g^k mod n^2
        return (c * g_k) % n_squared

    def multiply(self, a: int, k: int, public_key: Optional[Dict[str, int]] = None) -> int:
        """
        暗号文と平文定数の乗算

        Args:
            a: 暗号文
            k: 乗算する平文定数
            public_key: 公開鍵（指定しない場合はself.public_keyを使用）

        Returns:
            a * k に対応する暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n_squared = public_key['n'] * public_key['n']

        # E(a)^k mod n^2
        return pow(a, k, n_squared)

    def multiply_constant(self, a: int, k: int, public_key: Optional[Dict[str, int]] = None) -> int:
        """
        暗号文と平文定数の乗算（multiplyのエイリアス）

        Args:
            a: 暗号文
            k: 乗算する平文定数
            public_key: 公開鍵（指定しない場合はself.public_keyを使用）

        Returns:
            a * k に対応する暗号文
        """
        return self.multiply(a, k, public_key)

    def encrypt_bytes(self, data: bytes, public_key: Dict[str, int] = None, chunk_size: int = 128) -> List[int]:
        """
        バイトデータを暗号化

        Args:
            data: 暗号化するバイトデータ
            public_key: 公開鍵
            chunk_size: チャンクサイズ（バイト）

        Returns:
            暗号化されたチャンクのリスト
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        # データをチャンクに分割
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

        # 各チャンクを整数に変換して暗号化
        encrypted_chunks = []
        for chunk in chunks:
            # バイト列を整数に変換
            int_value = int.from_bytes(chunk, 'big')
            # 暗号化
            encrypted = self.encrypt(int_value, public_key)
            encrypted_chunks.append(encrypted)

        return encrypted_chunks

    def decrypt_bytes(self, encrypted_chunks: List[int], original_size: int,
                 private_key: Dict[str, int] = None, chunk_size: int = 128) -> bytes:
        """
        暗号化されたバイトデータを復号

        Args:
            encrypted_chunks: 暗号化されたチャンクのリスト
            original_size: 元のデータサイズ
            private_key: 秘密鍵
            chunk_size: チャンクサイズ（バイト）

        Returns:
            復号されたバイトデータ
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("秘密鍵が設定されていません")

        # デバッグ情報
        print(f"[DEBUG] decrypt_bytes: チャンク数={len(encrypted_chunks)}, 元サイズ={original_size}バイト")

        # 各チャンクを復号
        decrypted_data = bytearray()
        remaining_size = original_size

        for i, chunk in enumerate(encrypted_chunks):
            try:
                # 暗号文を復号
                int_value = self.decrypt(chunk, private_key)

                # 最初のチャンクのデバッグ情報
                if i == 0:
                    print(f"[DEBUG] 復号されたチャンク#{i}の整数値: {int_value}")

                # 最後のチャンクは部分的かもしれない
                bytes_in_chunk = min(chunk_size, remaining_size)

                # 最初のチャンクのデバッグ情報
                if i == 0:
                    print(f"[DEBUG] チャンク#{i}のバイト数: {bytes_in_chunk}")

                try:
                    # 整数をバイト列に変換
                    if int_value == 0:
                        # 特殊ケース: 0はバイト変換で問題が発生するため個別処理
                        bytes_value = b'\x00' * bytes_in_chunk
                    else:
                        # 必要なバイト数を計算（ビット長から）
                        needed_bytes = max(1, (int_value.bit_length() + 7) // 8)

                        # バイト変換の方法を改善
                        try:
                            # 十分な長さのバイト配列を確保
                            buffer_size = max(needed_bytes, bytes_in_chunk)
                            # 整数をバイト列に変換
                            bytes_value = int_value.to_bytes(buffer_size, 'big')

                            # バイト長調整（big-endianでは先頭に0パディングされる）
                            # 必要なサイズだけを末尾から取得
                            if len(bytes_value) > bytes_in_chunk:
                                # 末尾のbytes_in_chunk分を取得
                                bytes_value = bytes_value[-bytes_in_chunk:]
                            elif len(bytes_value) < bytes_in_chunk:
                                # 不足分を0パディング（右寄せ）
                                bytes_value = bytes_value.rjust(bytes_in_chunk, b'\x00')
                        except (OverflowError, ValueError):
                            # より大きいバッファで再試行
                            try:
                                buffer_size = bytes_in_chunk * 2
                                bytes_value = int_value.to_bytes(buffer_size, 'big')
                                # 必要なサイズだけを末尾から取得
                                bytes_value = bytes_value[-bytes_in_chunk:]
                            except (OverflowError, ValueError) as err:
                                print(f"[ERROR] バイト変換エラー（再試行）: {err}")
                                # 最終手段：ビット長から計算
                                bit_length = int_value.bit_length()
                                buffer_size = (bit_length + 7) // 8
                                try:
                                    bytes_value = int_value.to_bytes(buffer_size, 'big')
                                    # 必要なサイズに調整
                                    if len(bytes_value) > bytes_in_chunk:
                                        bytes_value = bytes_value[-bytes_in_chunk:]
                                    elif len(bytes_value) < bytes_in_chunk:
                                        bytes_value = bytes_value.rjust(bytes_in_chunk, b'\x00')
                                except Exception as e:
                                    print(f"[ERROR] 最終バイト変換エラー: {e}")
                                    bytes_value = b'\x00' * bytes_in_chunk

                    # デバッグログ
                    if i == 0 and bytes_value:
                        print(f"[DEBUG] 変換されたバイト先頭: {bytes_value[:min(20, len(bytes_value))]}")

                except (ValueError, OverflowError) as e:
                    print(f"[WARN] バイト変換エラー: {e}")
                    # フォールバック: パディングされたゼロを返す
                    bytes_value = b'\x00' * bytes_in_chunk

            except Exception as e:
                print(f"[ERROR] チャンク {i} の復号エラー: {e}")
                import traceback
                traceback.print_exc()
                # エラー時はゼロパディング
                bytes_value = b'\x00' * bytes_in_chunk

            # バイト配列に追加
            decrypted_data.extend(bytes_value)

            # 残りのサイズを更新
            remaining_size -= bytes_in_chunk
            if remaining_size <= 0:
                # 最後のチャンクを処理したので終了
                break

        # バイト数を必ず元のサイズに合わせる
        # original_sizeが0または不正な値の場合は、結果をそのまま返す
        if original_size > 0:
            # デバッグログ
            if len(decrypted_data) != original_size:
                print(f"[WARN] 復号データサイズ({len(decrypted_data)})が元のサイズ({original_size})と一致しません - 調整します")

            # 元のサイズ分だけを取得（過不足があれば調整）
            result = bytes(decrypted_data[:original_size])

            # 足りない場合はパディング
            if len(result) < original_size:
                result = result + b'\x00' * (original_size - len(result))
        else:
            result = bytes(decrypted_data)
            print(f"[WARN] 元のサイズが不正値({original_size})です - 復号結果をそのまま使用します({len(result)}バイト)")

        print(f"[DEBUG] 復号結果: 長さ={len(result)}バイト（要求サイズ={original_size}バイト）")
        if len(result) > 0:
            print(f"[DEBUG] 復号データ先頭: {result[:min(20, len(result))]}")
            if len(result) > 20:
                print(f"[DEBUG] 復号データ末尾: {result[-min(20, len(result)):]}")

        return result

    def save_keys(self, public_key_file: str, private_key_file: Optional[str] = None) -> None:
        """
        鍵をファイルに保存

        Args:
            public_key_file: 公開鍵の保存先ファイルパス
            private_key_file: 秘密鍵の保存先ファイルパス（省略可）
        """
        if self.public_key is None:
            raise ValueError("公開鍵が設定されていません")

        # 公開鍵の保存
        with open(public_key_file, 'w') as f:
            json.dump(self.public_key, f)

        # 秘密鍵の保存（指定されている場合）
        if private_key_file is not None and self.private_key is not None:
            with open(private_key_file, 'w') as f:
                json.dump(self.private_key, f)

    def load_keys(self, public_key_file: str, private_key_file: Optional[str] = None) -> None:
        """
        ファイルから鍵を読み込み

        Args:
            public_key_file: 公開鍵ファイルのパス
            private_key_file: 秘密鍵ファイルのパス（省略可）
        """
        # 公開鍵の読み込み
        with open(public_key_file, 'r') as f:
            self.public_key = json.load(f)

        # 秘密鍵の読み込み（指定されている場合）
        if private_key_file is not None:
            try:
                with open(private_key_file, 'r') as f:
                    self.private_key = json.load(f)
            except FileNotFoundError:
                self.private_key = None

    def randomize(self, ciphertext: int, public_key: Optional[Dict[str, int]] = None) -> int:
        """
        暗号文を再ランダム化

        同じ平文に対応する異なる暗号文を生成します。これによって暗号文の識別性を低下させます。

        Args:
            ciphertext: 再ランダム化する暗号文
            public_key: 公開鍵（指定しない場合はself.public_keyを使用）

        Returns:
            再ランダム化された暗号文
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("公開鍵が設定されていません")

        n = public_key['n']
        n_squared = n * n

        # ランダムな r ∈ Z*_n を選択
        r = random.randint(1, n - 1)
        while math.gcd(r, n) != 1:
            r = random.randint(1, n - 1)

        # c * r^n mod n^2
        randomized = (ciphertext * pow(r, n, n_squared)) % n_squared

        return randomized


class ElGamalCrypto:
    """
    ElGamal暗号システム（乗法準同型）

    このクラスは実装予定ですが、現在はスタブとして定義されています。
    """
    def __init__(self, bits=PAILLIER_KEY_BITS):
        self.bits = bits
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        """将来の実装のためのスタブ"""
        return {}, {}

    def encrypt(self, plaintext, public_key=None):
        """将来の実装のためのスタブ"""
        return 0

    def decrypt(self, ciphertext, private_key=None):
        """将来の実装のためのスタブ"""
        return 0

def derive_key_from_password(password: str, key_size: int = 32) -> bytes:
    """
    パスワードから暗号鍵を導出する関数

    Args:
        password: 元となるパスワード
        key_size: 鍵のサイズ（バイト）

    Returns:
        導出された鍵
    """
    # パスワードをUTF-8でエンコード
    password_bytes = password.encode('utf-8')

    # PBKDF2を使用して鍵を導出
    # ソルトが固定されていますが、これは単純化のためです
    # 実際のアプリケーションではランダムなソルトを使用し、保存すべきです
    salt = b'homomorphic_masking'
    derived_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, key_size)

    return derived_key

def save_keys(public_key: Dict[str, Any], private_key: Dict[str, Any],
             public_key_file: str, private_key_file: str) -> bool:
    """
    鍵をJSONファイルに保存

    Args:
        public_key: 公開鍵辞書
        private_key: 秘密鍵辞書
        public_key_file: 公開鍵を保存するファイルパス
        private_key_file: 秘密鍵を保存するファイルパス

    Returns:
        保存に成功した場合はTrue
    """
    try:
        # 大きな整数も文字列化して保存
        def int_dict_to_str(d):
            return {k: str(v) if isinstance(v, int) else v for k, v in d.items()}

        with open(public_key_file, 'w') as f:
            json.dump(int_dict_to_str(public_key), f, indent=2)

        with open(private_key_file, 'w') as f:
            json.dump(int_dict_to_str(private_key), f, indent=2)

        return True
    except Exception as e:
        print(f"鍵の保存中にエラーが発生しました: {e}")
        return False

def load_keys(public_key_file: str, private_key_file: Optional[str] = None) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    JSONファイルから鍵を読み込み

    Args:
        public_key_file: 公開鍵ファイルパス
        private_key_file: 秘密鍵ファイルパス（オプション）

    Returns:
        (public_key, private_key): 公開鍵と秘密鍵（秘密鍵ファイルが指定されていない場合はNone）
    """
    try:
        with open(public_key_file, 'r') as f:
            public_key_str = json.load(f)

        # 文字列を整数に変換
        public_key = {k: int(v) if isinstance(v, str) and v.isdigit() else v
                      for k, v in public_key_str.items()}

        private_key = None
        if private_key_file:
            try:
                with open(private_key_file, 'r') as f:
                    private_key_str = json.load(f)

                # 文字列を整数に変換
                private_key = {k: int(v) if isinstance(v, str) and v.isdigit() else v
                               for k, v in private_key_str.items()}
            except Exception as e:
                print(f"秘密鍵の読み込み中にエラーが発生しました: {e}")

        return public_key, private_key
    except Exception as e:
        print(f"鍵の読み込み中にエラーが発生しました: {e}")
        return {}, None

def serialize_encrypted_data(encrypted_data: Dict[str, Any]) -> str:
    """
    暗号化データを文字列にシリアライズ

    Args:
        encrypted_data: シリアライズする暗号化データの辞書

    Returns:
        JSON形式の文字列
    """
    # 大きな整数は文字列に変換
    def process_value(v):
        if isinstance(v, int) and v > 1e15:
            return str(v)
        elif isinstance(v, dict):
            return {k: process_value(val) for k, val in v.items()}
        elif isinstance(v, list):
            return [process_value(item) for item in v]
        else:
            return v

    serializable_data = {k: process_value(v) for k, v in encrypted_data.items()}
    return json.dumps(serializable_data, indent=2)

def deserialize_encrypted_data(serialized_data: str) -> Dict[str, Any]:
    """
    シリアライズされた暗号化データを復元

    Args:
        serialized_data: JSON形式の文字列

    Returns:
        復元された暗号化データの辞書
    """
    try:
        data = json.loads(serialized_data)

        # 数値文字列を整数に変換
        def process_value(v):
            if isinstance(v, str) and v.isdigit():
                return int(v)
            elif isinstance(v, dict):
                return {k: process_value(val) for k, val in v.items()}
            elif isinstance(v, list):
                return [process_value(item) for item in v]
            else:
                return v

        return {k: process_value(v) for k, v in data.items()}
    except json.JSONDecodeError as e:
        print(f"データのデシリアライズ中にエラーが発生しました: {e}")
        return {}

if __name__ == "__main__":
    # テスト用コード
    print("Paillier暗号テスト")

    # Paillierインスタンスの作成
    paillier = PaillierCrypto(bits=1024)  # 小さい値でテスト

    # 鍵の生成
    public_key, private_key = paillier.generate_keys()
    print(f"公開鍵: n={public_key['n']}, g={public_key['g']}")
    print(f"秘密鍵: lambda={private_key['lambda']}, mu={private_key['mu']}")

    # 暗号化テスト
    m1 = 42
    m2 = 73

    c1 = paillier.encrypt(m1, public_key)
    c2 = paillier.encrypt(m2, public_key)

    print(f"平文1: {m1} → 暗号文1: {c1}")
    print(f"平文2: {m2} → 暗号文2: {c2}")

    # 復号テスト
    d1 = paillier.decrypt(c1, private_key)
    d2 = paillier.decrypt(c2, private_key)

    print(f"暗号文1: {c1} → 復号1: {d1}")
    print(f"暗号文2: {c2} → 復号2: {d2}")

    # 準同型性テスト
    print("\n準同型性テスト")

    # 加算: E(m1 + m2) = E(m1) ⊙ E(m2)
    c_add = paillier.add(c1, c2, public_key)
    d_add = paillier.decrypt(c_add, private_key)

    print(f"加算: {m1} + {m2} = {m1 + m2}")
    print(f"準同型加算の復号: {d_add}")
    print(f"検証: {d_add == (m1 + m2) % public_key['n']}")

    # 定数加算: E(m1 + k) = E(m1) ⊙ E(k)
    k = 30
    c_add_const = paillier.add_constant(c1, k, public_key)
    d_add_const = paillier.decrypt(c_add_const, private_key)

    print(f"\n定数加算: {m1} + {k} = {m1 + k}")
    print(f"準同型定数加算の復号: {d_add_const}")
    print(f"検証: {d_add_const == (m1 + k) % public_key['n']}")

    # 定数乗算: E(m1 * k) = E(m1)^k
    c_mult = paillier.multiply_constant(c1, k, public_key)
    d_mult = paillier.decrypt(c_mult, private_key)

    print(f"\n定数乗算: {m1} * {k} = {m1 * k}")
    print(f"準同型定数乗算の復号: {d_mult}")
    print(f"検証: {d_mult == (m1 * k) % public_key['n']}")

    # 再ランダム化テスト
    print("\n再ランダム化テスト")

    c1_rand = paillier.randomize(c1, public_key)
    d1_rand = paillier.decrypt(c1_rand, private_key)

    print(f"元の暗号文: {c1}")
    print(f"再ランダム化後: {c1_rand}")
    print(f"再ランダム化後の復号: {d1_rand}")
    print(f"元の平文と同じ: {d1_rand == m1}")
    print(f"元の暗号文と異なる: {c1_rand != c1}")
