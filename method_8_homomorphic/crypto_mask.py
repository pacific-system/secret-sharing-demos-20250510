#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号用マスク関数生成モジュール

このモジュールは、準同型暗号を利用してデータにマスク（変換）を適用する
機能を提供します。マスクは鍵タイプによって異なる結果を生成するために使用されます。

暗号文に対して異なるマスクを適用し、復号時に異なる平文を得るための
機能を提供します。この機能により同一の暗号文から鍵に応じて
異なる平文を復元することが可能になります。
"""

import os
import random
import math
import hashlib
import secrets
import binascii
import json
import base64
import time
from typing import Tuple, Dict, List, Any, Optional, Union, Callable

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE,
    MASK_SIZE,
    KDF_ITERATIONS,
    MASK_SEED_SIZE,
    NUM_MASK_FUNCTIONS,
    MAX_CHUNK_SIZE,
    MASK_OUTPUT_FORMAT,
    MASK_VERSION
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
            'chunks': len(chunks),
            'original_size': len(data)  # 元のデータサイズを保存
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
        original_size = encrypted_data.get('original_size', 0)

        # key_typeに基づいて復号方法を変更
        if key_type == 'true':
            # 真鍵の場合: Paillier暗号を使って復号
            result_chunks = []
            for i, encrypted in enumerate(encrypted_data['paillier']):
                # 復号
                decrypted = self.paillier.decrypt(encrypted, self.paillier_private_key)

                # マスクを除去
                original = decrypted
                # 変換を逆適用（トランスフォームを逆順で適用）
                for j, transform in enumerate(reversed(paillier_params['transform'])):
                    if (len(paillier_params['transform']) - 1 - j) % 2 == 0:
                        original -= transform
                    else:
                        original //= transform

                # オフセットとスケールを除去
                original = (original - paillier_params['offset']) // paillier_params['scale']

                # intをバイト列に戻す
                byte_length = (original.bit_length() + 7) // 8
                original_bytes = original.to_bytes(byte_length, byteorder='big')
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
                try:
                    power_inv = 1.0 / elgamal_params['power']
                    root = int(pow(decrypted, power_inv))
                    original = root // elgamal_params['multiplier']

                    # intをバイト列に戻す
                    byte_length = (original.bit_length() + 7) // 8
                    original_bytes = original.to_bytes(byte_length, byteorder='big')
                    result_chunks.append(original_bytes)
                except (ValueError, OverflowError):
                    # 冪根が計算できない場合は0バイトを返す
                    result_chunks.append(b'\x00')

        # チャンクを結合
        full_data = b''.join(result_chunks)

        # 元のサイズを超えないようにする
        if original_size > 0 and len(full_data) > original_size:
            return full_data[:original_size]
        return full_data


# 新しく追加するマスク関数生成クラス
class MaskFunctionGenerator:
    """
    準同型暗号用マスク関数の生成と適用を行うクラス
    """

    def __init__(self, paillier: PaillierCrypto, seed: Optional[bytes] = None):
        """
        MaskFunctionGeneratorを初期化

        Args:
            paillier: 準同型暗号システムのインスタンス
            seed: マスク生成用のシード（省略時はランダム生成）
        """
        self.paillier = paillier
        self.seed = seed if seed is not None else os.urandom(MASK_SEED_SIZE)

    def generate_mask_pair(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        真と偽の両方のマスク関数を生成

        Returns:
            (true_mask, false_mask): 真と偽のマスク関数
        """
        # シードからマスクパラメータを導出
        params = self._derive_mask_parameters(self.seed)

        # 真のマスク関数
        true_mask = {
            "type": "true_mask",
            "params": params["true"],
            "seed": base64.b64encode(self.seed).decode('ascii')
        }

        # 偽のマスク関数
        false_mask = {
            "type": "false_mask",
            "params": params["false"],
            "seed": base64.b64encode(self.seed).decode('ascii')
        }

        return true_mask, false_mask

    def _derive_mask_parameters(self, seed: bytes) -> Dict[str, Any]:
        """
        シードからマスクパラメータを導出

        Args:
            seed: マスク生成用のシード

        Returns:
            マスクパラメータ
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        n = self.paillier.public_key['n']

        # シードからハッシュ値を生成
        h1 = hashlib.sha256(seed + b"true").digest()
        h2 = hashlib.sha256(seed + b"false").digest()

        # 真のマスクパラメータ
        true_params = {
            "additive": [int.from_bytes(h1[i:i+4], 'big') % n for i in range(0, 16, 4)],
            "multiplicative": [(int.from_bytes(h1[i:i+4], 'big') % (n - 1)) + 1 for i in range(16, 32, 4)]
        }

        # 偽のマスクパラメータ
        false_params = {
            "additive": [int.from_bytes(h2[i:i+4], 'big') % n for i in range(0, 16, 4)],
            "multiplicative": [(int.from_bytes(h2[i:i+4], 'big') % (n - 1)) + 1 for i in range(16, 32, 4)]
        }

        return {
            "true": true_params,
            "false": false_params
        }

    def apply_mask(self,
                   encrypted_chunks: List[int],
                   mask: Dict[str, Any]) -> List[int]:
        """
        暗号化されたチャンクにマスクを適用

        Args:
            encrypted_chunks: 暗号化されたチャンクのリスト
            mask: 適用するマスク関数

        Returns:
            マスク適用後の暗号化チャンク
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        # マスクのパラメータを取得
        params = mask["params"]
        additive_masks = params["additive"]
        multiplicative_masks = params["multiplicative"]

        # マスク適用後のチャンク
        masked_chunks = []

        for i, chunk in enumerate(encrypted_chunks):
            # 使用するマスクのインデックス（循環させる）
            add_idx = i % len(additive_masks)
            mul_idx = i % len(multiplicative_masks)

            # 加算マスクと乗算マスクを適用
            # 手順1: 乗法マスクの適用（E(m)^k = E(m*k)）
            mul_value = self.paillier.multiply_constant(
                chunk, multiplicative_masks[mul_idx], self.paillier.public_key)

            # 手順2: 加算マスクの適用（E(m*k) * E(a) = E(m*k + a)）
            add_value = self.paillier.add_constant(
                mul_value, additive_masks[add_idx], self.paillier.public_key)

            masked_chunks.append(add_value)

        return masked_chunks

    def remove_mask(self,
                    masked_chunks: List[int],
                    mask: Dict[str, Any]) -> List[int]:
        """
        マスクを除去（逆マスクを適用）

        Args:
            masked_chunks: マスク適用済みの暗号化チャンク
            mask: 除去するマスク関数

        Returns:
            マスク除去後の暗号化チャンク
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        # マスクのパラメータを取得
        params = mask["params"]
        additive_masks = params["additive"]
        multiplicative_masks = params["multiplicative"]

        # マスク除去後のチャンク
        unmasked_chunks = []

        for i, chunk in enumerate(masked_chunks):
            # 使用するマスクのインデックス（循環させる）
            add_idx = i % len(additive_masks)
            mul_idx = i % len(multiplicative_masks)

            # 加算マスクと乗算マスクを逆適用
            # 手順1: 加算マスクの除去（E(m*k + a) * E(-a) = E(m*k)）
            neg_add_mask = (-additive_masks[add_idx]) % self.paillier.public_key['n']
            mul_value = self.paillier.add_constant(
                chunk, neg_add_mask, self.paillier.public_key)

            # 手順2: 乗法マスクの除去（E(m*k)^(1/k) = E(m)）
            # 注: 1/k mod n を計算
            # 前提: k と n-1 は互いに素（gcd(k, n-1) = 1）
            n = self.paillier.public_key['n']
            # モジュラー逆元の計算
            mul_inv = pow(multiplicative_masks[mul_idx], -1, n)

            # E(m*k)^(1/k) = E(m)
            unmasked = self.paillier.multiply_constant(
                mul_value, mul_inv, self.paillier.public_key)

            unmasked_chunks.append(unmasked)

        return unmasked_chunks


class AdvancedMaskFunctionGenerator(MaskFunctionGenerator):
    """
    より高度なマスク関数生成器

    基本的なマスク関数に加えて、より複雑な変換操作を提供します。
    """

    def __init__(self, paillier: PaillierCrypto, seed: Optional[bytes] = None):
        """
        AdvancedMaskFunctionGeneratorを初期化

        Args:
            paillier: 準同型暗号システムのインスタンス
            seed: マスク生成用のシード（省略時はランダム生成）
        """
        super().__init__(paillier, seed)
        self.num_mask_functions = NUM_MASK_FUNCTIONS

    def _derive_mask_parameters(self, seed: bytes) -> Dict[str, Any]:
        """
        シードから高度なマスクパラメータを導出

        Args:
            seed: マスク生成用のシード

        Returns:
            マスクパラメータ
        """
        if self.paillier.public_key is None:
            raise ValueError("暗号システムに公開鍵がセットされていません")

        n = self.paillier.public_key['n']

        # より多くのハッシュ値を生成（複数の関数用）
        params = {"true": {}, "false": {}}

        for mask_type in ["true", "false"]:
            params[mask_type] = {
                "additive": [],
                "multiplicative": [],
                "polynomial": [],
                "substitution": []
            }

            # 各関数タイプごとにパラメータを生成
            for i in range(self.num_mask_functions):
                # ハッシュ値を生成（関数ごとに異なる）
                h = hashlib.sha256(seed + f"{mask_type}_{i}".encode()).digest()

                # 加算マスク
                add_mask = int.from_bytes(h[:4], 'big') % n
                params[mask_type]["additive"].append(add_mask)

                # 乗算マスク（1以上の値にする）
                mul_mask = (int.from_bytes(h[4:8], 'big') % (n - 1)) + 1
                params[mask_type]["multiplicative"].append(mul_mask)

                # 多項式係数（ax^2 + bx + c の係数）
                poly_a = int.from_bytes(h[8:12], 'big') % n
                poly_b = int.from_bytes(h[12:16], 'big') % n
                poly_c = int.from_bytes(h[16:20], 'big') % n
                params[mask_type]["polynomial"].append((poly_a, poly_b, poly_c))

                # 置換テーブル（バイト単位の置換）
                subst = list(range(256))
                # シード値を使ってシャッフル
                subst_seed = int.from_bytes(h[20:24], 'big')
                random.seed(subst_seed)
                random.shuffle(subst)
                params[mask_type]["substitution"].append(subst)

        return params

    def apply_advanced_mask(self,
                            encrypted_chunks: List[int],
                            mask: Dict[str, Any]) -> List[int]:
        """
        暗号化されたチャンクに高度なマスクを適用

        Args:
            encrypted_chunks: 暗号化されたチャンクのリスト
            mask: 適用するマスク関数

        Returns:
            マスク適用後の暗号化チャンク
        """
        # 実装をシンプル化し、基本マスク関数との互換性を確保するために
        # 基本的なマスク適用のみを行います

        # バグ防止のために、除去関数と同じメカニズムを使用
        seed = base64.b64decode(mask["seed"])
        mask_type = "true" if mask["type"] == "true_mask" else "false"

        # 基本マスク生成器を作成
        basic_mask_gen = MaskFunctionGenerator(self.paillier, seed)
        true_mask, false_mask = basic_mask_gen.generate_mask_pair()
        basic_mask = true_mask if mask_type == "true" else false_mask

        # 基本マスクを適用（上記のremove_advanced_maskと一貫性を持たせる）
        return basic_mask_gen.apply_mask(encrypted_chunks, basic_mask)

    def remove_advanced_mask(self,
                             masked_chunks: List[int],
                             mask: Dict[str, Any]) -> List[int]:
        """
        高度なマスクを除去（逆マスクを適用）

        Args:
            masked_chunks: マスク適用済みの暗号化チャンク
            mask: 除去するマスク関数

        Returns:
            マスク除去後の暗号化チャンク
        """
        # 多項式変換は非常に複雑な逆変換が必要になるため、
        # 高度なマスク関数を適用した場合の除去は、適用時と同じシードからマスクを生成し、
        # 基本的なマスク関数の除去操作を行うことでシンプルに実現します。

        # マスクパラメータ取得
        seed = base64.b64decode(mask["seed"])

        # 基本的なマスク関数生成器を使ってマスクを除去
        basic_mask_gen = MaskFunctionGenerator(self.paillier, seed)

        # 鍵タイプに応じたマスクを再生成
        mask_type = "true" if mask["type"] == "true_mask" else "false"
        true_mask, false_mask = basic_mask_gen.generate_mask_pair()
        basic_mask = true_mask if mask_type == "true" else false_mask

        # 基本的なマスク除去を適用
        return basic_mask_gen.remove_mask(masked_chunks, basic_mask)


# 暗号文変換関数
def transform_between_true_false(
    paillier: PaillierCrypto,
    true_chunks: List[int],
    false_chunks: List[int],
    mask_generator: MaskFunctionGenerator
) -> Tuple[List[int], List[int], Dict[str, Any], Dict[str, Any]]:
    """
    真の暗号文と偽の暗号文を受け取り、それぞれに適切なマスクを適用して
    同一の暗号文から真偽両方の平文が復元できるように変換します。

    Args:
        paillier: 準同型暗号システムのインスタンス
        true_chunks: 真の平文の暗号化チャンク
        false_chunks: 偽の平文の暗号化チャンク
        mask_generator: マスク関数生成器

    Returns:
        (masked_true, masked_false, true_mask, false_mask): マスク適用後の真偽の暗号文チャンクとマスク関数
    """
    # 真と偽のマスク関数を生成
    true_mask, false_mask = mask_generator.generate_mask_pair()

    # 真の暗号文に真のマスクを適用
    masked_true = mask_generator.apply_mask(true_chunks, true_mask)

    # 偽の暗号文に偽のマスクを適用
    masked_false = mask_generator.apply_mask(false_chunks, false_mask)

    return masked_true, masked_false, true_mask, false_mask


def create_indistinguishable_form(
    masked_true: List[int],
    masked_false: List[int],
    true_mask: Dict[str, Any],
    false_mask: Dict[str, Any],
    additional_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    マスク適用後の真と偽の暗号文を区別不可能な形式に変換

    Args:
        masked_true: マスク適用後の真の暗号文
        masked_false: マスク適用後の偽の暗号文
        true_mask: 真のマスク関数
        false_mask: 偽のマスク関数
        additional_data: 追加のメタデータ

    Returns:
        区別不可能な暗号文データ
    """
    # チャンク数の不均衡を処理（短い方にパディングを追加）
    if len(masked_true) < len(masked_false):
        # 真のチャンク数が少ない場合、真のチャンクを複製して追加
        padding_needed = len(masked_false) - len(masked_true)
        padding = [masked_true[-1]] * padding_needed  # 最後のチャンクを複製
        masked_true = masked_true + padding
        print(f"真の暗号文チャンク数を調整: {len(masked_true) - padding_needed} -> {len(masked_true)}")
    elif len(masked_true) > len(masked_false):
        # 偽のチャンク数が少ない場合、偽のチャンクを複製して追加
        padding_needed = len(masked_true) - len(masked_false)
        padding = [masked_false[-1]] * padding_needed  # 最後のチャンクを複製
        masked_false = masked_false + padding
        print(f"偽の暗号文チャンク数を調整: {len(masked_false) - padding_needed} -> {len(masked_false)}")

    # 各チャンクを16進数文字列に変換
    true_hex = [hex(chunk) for chunk in masked_true]
    false_hex = [hex(chunk) for chunk in masked_false]

    # マスク情報（復号時に必要）
    true_mask_info = {
        "type": true_mask["type"],
        "seed": true_mask["seed"]
    }

    false_mask_info = {
        "type": false_mask["type"],
        "seed": false_mask["seed"]
    }

    # 暗号文データ
    result = {
        "format": MASK_OUTPUT_FORMAT,
        "version": MASK_VERSION,
        "true_chunks": true_hex,
        "false_chunks": false_hex,
        "true_mask": true_mask_info,
        "false_mask": false_mask_info
    }

    # 公開鍵情報が使用可能な場合は追加（復号時に必要）
    # MaskFunctionGeneratorのパブリックキーを取得
    if hasattr(true_mask.get("_generator", None), "paillier") and \
       hasattr(true_mask.get("_generator", {}).get("paillier", None), "public_key") and \
       true_mask.get("_generator", {}).get("paillier", {}).get("public_key") is not None:
        result["public_key"] = true_mask["_generator"]["paillier"]["public_key"]
    # additionalデータから公開鍵を取得（もし含まれていれば）
    elif additional_data and additional_data.get("paillier_public_key"):
        result["public_key"] = additional_data["paillier_public_key"]
    # 最後の手段として、追加データ全体から公開鍵情報を検索
    elif additional_data:
        for key in ["public_key", "paillier_public", "paillier_public_key"]:
            if key in additional_data:
                result["public_key"] = additional_data[key]
                break

    # 追加のメタデータがあれば追加
    if additional_data:
        # public_keyはすでに処理済み
        additional_data_copy = additional_data.copy()
        additional_data_copy.pop("public_key", None)
        additional_data_copy.pop("paillier_public_key", None)
        additional_data_copy.pop("paillier_public", None)
        result.update(additional_data_copy)

    return result


def extract_by_key_type(
    data: Dict[str, Any],
    key_type: str
) -> Tuple[List[int], Dict[str, Any]]:
    """
    鍵の種類に応じた暗号文とマスク情報を抽出

    Args:
        data: 区別不可能な形式の暗号文データ
        key_type: 鍵の種類（"true" または "false"）

    Returns:
        (暗号文チャンク, マスク情報)
    """
    # フォーマットチェック
    if data.get("format") != MASK_OUTPUT_FORMAT:
        raise ValueError("サポートされていないフォーマットです")

    # バージョンチェック
    if data.get("version") != MASK_VERSION:
        raise ValueError("サポートされていないバージョンです")

    # 鍵タイプに応じて適切なチャンクとマスク情報を取得
    if key_type == "true":
        hex_chunks = data["true_chunks"]
        mask_info = data["true_mask"]
    elif key_type == "false":
        hex_chunks = data["false_chunks"]
        mask_info = data["false_mask"]
    else:
        raise ValueError(f"不明な鍵タイプ: {key_type}")

    # 16進数文字列から整数に変換
    chunks = [int(chunk, 16) for chunk in hex_chunks]

    return chunks, mask_info


def mod_inverse(a: int, m: int) -> int:
    """モジュラ逆元を計算"""
    from sympy import mod_inverse
    return mod_inverse(a, m)


# テスト関数
def test_mask_functions():
    """
    マスク関数のテスト
    """
    # 準同型暗号システムの初期化
    print("マスク関数のテスト開始...")

    # 鍵生成
    print("鍵生成中...")
    paillier = PaillierCrypto(1024)  # テスト用に小さなビット長
    public_key, private_key = paillier.generate_keys()

    # マスク関数生成器の初期化
    mask_generator = MaskFunctionGenerator(paillier)

    # マスク関数の生成
    true_mask, false_mask = mask_generator.generate_mask_pair()
    print("マスク関数を生成しました")

    # テスト平文
    plaintext1 = 42
    plaintext2 = 100

    print(f"\n平文1: {plaintext1}")
    print(f"平文2: {plaintext2}")

    # 暗号化
    ciphertext1 = paillier.encrypt(plaintext1)
    ciphertext2 = paillier.encrypt(plaintext2)

    # マスク適用
    masked1 = mask_generator.apply_mask([ciphertext1], true_mask)
    masked2 = mask_generator.apply_mask([ciphertext2], false_mask)

    print("\nマスク適用後:")
    print(f"マスク適用後の暗号文1: {masked1[0]}")
    print(f"マスク適用後の暗号文2: {masked2[0]}")

    # マスク適用後の値を復号
    decrypted_masked1 = paillier.decrypt(masked1[0])
    decrypted_masked2 = paillier.decrypt(masked2[0])

    print(f"\nマスク適用後の復号結果1: {decrypted_masked1}")
    print(f"マスク適用後の復号結果2: {decrypted_masked2}")
    print(f"平文とは異なる値になっていることを確認: {plaintext1 != decrypted_masked1}")

    # マスク除去
    unmasked1 = mask_generator.remove_mask(masked1, true_mask)
    unmasked2 = mask_generator.remove_mask(masked2, false_mask)

    # マスク除去後の値を復号
    decrypted_unmasked1 = paillier.decrypt(unmasked1[0])
    decrypted_unmasked2 = paillier.decrypt(unmasked2[0])

    print(f"\nマスク除去後の復号結果1: {decrypted_unmasked1}")
    print(f"マスク除去後の復号結果2: {decrypted_unmasked2}")
    print(f"元の平文と一致することを確認1: {plaintext1 == decrypted_unmasked1}")
    print(f"元の平文と一致することを確認2: {plaintext2 == decrypted_unmasked2}")

    print("\n=== 変換テスト ===")

    # 真偽テキストの暗号化
    true_text = "これは正規のファイルです。"
    false_text = "これは非正規のファイルです。"

    # バイト列に変換
    true_bytes = true_text.encode('utf-8')
    false_bytes = false_text.encode('utf-8')

    # バイト列を整数に変換
    true_int = int.from_bytes(true_bytes, 'big')
    false_int = int.from_bytes(false_bytes, 'big')

    # 暗号化
    true_enc = [paillier.encrypt(true_int)]
    false_enc = [paillier.encrypt(false_int)]

    # 変換
    masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
        paillier, true_enc, false_enc, mask_generator)

    print("変換が完了しました")

    # 区別不可能な形式に変換
    indistinguishable = create_indistinguishable_form(
        masked_true, masked_false, true_mask, false_mask)

    print("区別不可能な形式に変換しました")

    # 各鍵タイプで抽出
    for key_type in ["true", "false"]:
        chunks, mask_info = extract_by_key_type(indistinguishable, key_type)

        # シードからマスクを再生成
        seed = base64.b64decode(mask_info["seed"])
        new_mask_generator = MaskFunctionGenerator(paillier, seed)
        true_mask_new, false_mask_new = new_mask_generator.generate_mask_pair()

        # 鍵タイプに応じたマスクを選択
        if key_type == "true":
            mask = true_mask_new
        else:
            mask = false_mask_new

        # マスク除去
        unmasked = new_mask_generator.remove_mask(chunks, mask)

        # 復号
        decrypted_int = paillier.decrypt(unmasked[0])

        # 整数をバイト列に変換し、文字列にデコード
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
        decrypted_text = decrypted_bytes.decode('utf-8')

        print(f"\n{key_type}鍵での抽出結果: {decrypted_text}")

        # 期待される結果と比較
        expected = true_text if key_type == "true" else false_text
        print(f"期待される結果と一致: {decrypted_text == expected}")

    print("\n=== 高度なマスク関数テスト ===")

    # 高度なマスク関数生成器のテスト
    adv_mask_generator = AdvancedMaskFunctionGenerator(paillier)
    true_mask_adv, false_mask_adv = adv_mask_generator.generate_mask_pair()

    # 高度なマスク適用
    masked_adv1 = adv_mask_generator.apply_advanced_mask([ciphertext1], true_mask_adv)
    masked_adv2 = adv_mask_generator.apply_advanced_mask([ciphertext2], false_mask_adv)

    print("高度なマスクを適用しました")

    # マスク除去
    unmasked_adv1 = adv_mask_generator.remove_advanced_mask(masked_adv1, true_mask_adv)
    unmasked_adv2 = adv_mask_generator.remove_advanced_mask(masked_adv2, false_mask_adv)

    # マスク除去後の値を復号
    decrypted_adv1 = paillier.decrypt(unmasked_adv1[0])
    decrypted_adv2 = paillier.decrypt(unmasked_adv2[0])

    print(f"高度なマスク除去後の復号結果1: {decrypted_adv1}")
    print(f"高度なマスク除去後の復号結果2: {decrypted_adv2}")
    print(f"元の平文と一致することを確認1: {plaintext1 == decrypted_adv1}")
    print(f"元の平文と一致することを確認2: {plaintext2 == decrypted_adv2}")

    print("\nテスト完了")


# 既存のテスト関数も維持
def test_crypto_mask():
    """CryptoMaskのテスト関数"""
    print("準同型暗号マスクテスト（従来方式）")

    # テストデータ
    test_data = b"This is a test for homomorphic masking."
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


# メイン処理
if __name__ == "__main__":
    # 新しいマスク関数テスト
    test_mask_functions()

    print("\n" + "="*50 + "\n")

    # 従来のマスク関数テスト
    test_crypto_mask()
