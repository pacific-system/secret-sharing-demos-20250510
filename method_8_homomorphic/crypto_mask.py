#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号のマスク生成と適用機能

このモジュールは、準同型暗号を利用してデータにマスク（変換）を適用する
機能を提供します。マスクは鍵タイプによって異なる結果を生成するために使用されます。
"""

import os
import random
import hashlib
import binascii
from typing import Dict, List, Tuple, Union, Any

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    MASK_SIZE,
    KDF_ITERATIONS
)
from method_8_homomorphic.homomorphic import PaillierCrypto, ElGamalCrypto


class CryptoMask:
    """準同型暗号を使ったマスク生成と適用のクラス"""

    def __init__(self):
        """初期化"""
        self.paillier = PaillierCrypto()
        self.elgamal = ElGamalCrypto()
        self.paillier_public_key = None
        self.paillier_private_key = None
        self.elgamal_public_key = None
        self.elgamal_private_key = None

    def initialize(self) -> Dict[str, Any]:
        """
        準同型暗号のキーペア生成と初期化

        Returns:
            初期化パラメータ辞書
        """
        # Paillier暗号の鍵ペア生成
        self.paillier_public_key, self.paillier_private_key = self.paillier.generate_keys()

        # ElGamal暗号の鍵ペア生成
        self.elgamal_public_key, self.elgamal_private_key = self.elgamal.generate_keys()

        return {
            'paillier_public': self.paillier_public_key,
            'paillier_private': self.paillier_private_key,
            'elgamal_public': self.elgamal_public_key,
            'elgamal_private': self.elgamal_private_key
        }

    def generate_mask_params(self, key: bytes, salt: bytes) -> Dict[str, Any]:
        """
        マスクパラメータの生成

        Args:
            key: 鍵データ
            salt: ソルト

        Returns:
            マスクパラメータ
        """
        # 鍵とソルトから一意的なマスクシードを派生
        kdf_input = key + salt
        mask_seed = hashlib.pbkdf2_hmac('sha256', kdf_input, salt, KDF_ITERATIONS, MASK_SIZE // 8)

        # マスクシードからパラメータを生成
        random.seed(int.from_bytes(mask_seed, byteorder='big'))

        # Paillier暗号用のマスクパラメータ
        paillier_mask_params = {
            'offset': random.randint(1, 10000),
            'scale': random.randint(1, 100),
            'transform': [random.randint(1, 1000) for _ in range(5)]
        }

        # ElGamal暗号用のマスクパラメータ
        elgamal_mask_params = {
            'multiplier': random.randint(1, 1000),
            'power': random.randint(1, 10),
            'transform': [random.randint(1, 1000) for _ in range(5)]
        }

        return {
            'paillier': paillier_mask_params,
            'elgamal': elgamal_mask_params,
            'seed': binascii.hexlify(mask_seed).decode()
        }

    def apply_mask_to_data(self, data: bytes, mask_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        データにマスクを適用

        Args:
            data: マスクを適用するデータ
            mask_params: マスクパラメータ

        Returns:
            マスク適用結果
        """
        # データをチャンクに分割（各チャンクは64バイト以内）
        chunk_size = 64
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        # 各チャンクに対して準同型暗号を適用
        paillier_results = []
        elgamal_results = []

        for i, chunk in enumerate(chunks):
            # チャンクをint値に変換（メタデータとして位置情報を追加）
            chunk_int = int.from_bytes(chunk, byteorder='big')

            # Paillier暗号
            paillier_params = mask_params['paillier']
            # オフセットと乗算係数を適用
            chunk_paillier = chunk_int * paillier_params['scale'] + paillier_params['offset']
            # トランスフォーム関数を適用
            for j, transform in enumerate(paillier_params['transform']):
                if j % 2 == 0:
                    chunk_paillier += transform
                else:
                    chunk_paillier *= transform

            # 暗号化
            encrypted_paillier = self.paillier.encrypt(chunk_paillier, self.paillier_public_key)
            paillier_results.append(encrypted_paillier)

            # ElGamal暗号
            elgamal_params = mask_params['elgamal']
            # 乗算係数と冪乗を適用
            chunk_elgamal = pow(chunk_int * elgamal_params['multiplier'], elgamal_params['power'])
            # トランスフォーム関数を適用
            for j, transform in enumerate(elgamal_params['transform']):
                if j % 2 == 0:
                    chunk_elgamal = (chunk_elgamal * transform) % self.elgamal_public_key['p']
                else:
                    chunk_elgamal = pow(chunk_elgamal, transform % 50 + 1, self.elgamal_public_key['p'])

            # 暗号化
            encrypted_elgamal = self.elgamal.encrypt(chunk_elgamal, self.elgamal_public_key)
            elgamal_results.append(encrypted_elgamal)

        return {
            'paillier': paillier_results,
            'elgamal': elgamal_results,
            'chunks': len(chunks)
        }

    def remove_mask_from_data(self, encrypted_data: Dict[str, Any], mask_params: Dict[str, Any],
                              key_type: str) -> bytes:
        """
        マスクを除去してデータを復元

        Args:
            encrypted_data: マスクが適用されたデータ
            mask_params: マスクパラメータ
            key_type: 鍵タイプ ('true' または 'false')

        Returns:
            復元されたデータ
        """
        # 鍵タイプに基づくマスクパラメータの変換
        # 真鍵と偽鍵で異なる復号方法を提供する
        paillier_params = mask_params['paillier']
        elgamal_params = mask_params['elgamal']

        # key_typeに基づいて復号方法を変更
        if key_type == 'true':
            # 真鍵の場合: Paillier暗号を使って復号
            result_chunks = []
            for i, encrypted in enumerate(encrypted_data['paillier']):
                # 復号
                decrypted = self.paillier.decrypt(encrypted, self.paillier_private_key)

                # マスクを除去
                original = (decrypted - paillier_params['offset']) // paillier_params['scale']

                # 変換を逆適用（トランスフォームを逆順で適用）
                for j, transform in enumerate(reversed(paillier_params['transform'])):
                    if (len(paillier_params['transform']) - 1 - j) % 2 == 0:
                        original -= transform
                    else:
                        original //= transform

                # intをバイト列に戻す
                original_bytes = original.to_bytes((original.bit_length() + 7) // 8, byteorder='big')
                result_chunks.append(original_bytes)

        else:
            # 偽鍵の場合: ElGamal暗号を使って復号
            result_chunks = []
            for i, encrypted in enumerate(encrypted_data['elgamal']):
                # 復号
                decrypted = self.elgamal.decrypt(encrypted, self.elgamal_private_key)

                # 変換を逆適用（トランスフォームを逆順で適用）
                for j, transform in enumerate(reversed(elgamal_params['transform'])):
                    if (len(elgamal_params['transform']) - 1 - j) % 2 == 0:
                        decrypted = (decrypted * mod_inverse(transform, self.elgamal_private_key['p'])) % self.elgamal_private_key['p']
                    else:
                        exp = mod_inverse(transform % 50 + 1, self.elgamal_private_key['p'] - 1)
                        decrypted = pow(decrypted, exp, self.elgamal_private_key['p'])

                # 冪乗と乗算係数を除去
                root = int(pow(decrypted, 1/elgamal_params['power']))
                original = root // elgamal_params['multiplier']

                # intをバイト列に戻す
                original_bytes = original.to_bytes((original.bit_length() + 7) // 8, byteorder='big')
                result_chunks.append(original_bytes)

        # チャンクを結合
        return b''.join(result_chunks)


def mod_inverse(a: int, m: int) -> int:
    """モジュラ逆元を計算"""
    from sympy import mod_inverse
    return mod_inverse(a, m)


# 実装テスト用コード
def test_crypto_mask():
    """CryptoMaskのテスト関数"""
    print("準同型暗号マスクテスト")

    # テストデータ
    test_data = b"This is a test message for homomorphic masking functionality!"
    print(f"元データ: {test_data.decode()}")

    # マスク生成
    mask = CryptoMask()
    mask.initialize()

    # 鍵とソルト
    key = os.urandom(KEY_SIZE_BYTES)
    salt = os.urandom(SALT_SIZE)

    # マスクパラメータ生成
    mask_params = mask.generate_mask_params(key, salt)
    print(f"マスクパラメータ: {mask_params['seed']}")

    # マスク適用
    masked_data = mask.apply_mask_to_data(test_data, mask_params)
    print(f"マスク適用済みデータチャンク数: {masked_data['chunks']}")

    # 真鍵でマスク除去
    unmasked_true = mask.remove_mask_from_data(masked_data, mask_params, 'true')
    print(f"真鍵で復元: {unmasked_true.decode()}")

    # 偽鍵でマスク除去
    unmasked_false = mask.remove_mask_from_data(masked_data, mask_params, 'false')
    print(f"偽鍵で復元: {unmasked_false}")

    # 検証
    print(f"真鍵の復元結果は元データと一致: {unmasked_true == test_data}")
    print(f"偽鍵の復元結果は元データと異なる: {unmasked_false != test_data}")


if __name__ == "__main__":
    test_crypto_mask()
