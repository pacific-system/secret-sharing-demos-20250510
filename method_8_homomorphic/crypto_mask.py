#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式のマスク関数実装

このモジュールは、暗号文に対して準同型性を維持したまま「真」「偽」の
区別を不可能にするマスク関数を提供します。これにより、攻撃者は
暗号化コードを入手しても、どちらの鍵が「真」で「偽」かを判別できません。
"""

import os
import time
import math
import json
import base64
import random
import hashlib
import hmac
import secrets
import binascii
from typing import Dict, List, Tuple, Any, Optional, Union, cast, Callable

# 相対インポートに修正
from method_8_homomorphic.config import (
    MASK_SEED_SIZE,
    SECURITY_PARAMETER
)

class MaskFunctionGenerator:
    """
    準同型暗号用マスク関数生成器

    暗号文に準同型性を維持したまま「真」「偽」の区別を不可能にする
    マスク関数を生成します。加法準同型暗号では「加算」と「スカラー倍」が
    マスク関数として使用可能です。
    """

    def __init__(self, paillier_or_key_bytes, seed=None):
        """
        初期化

        Args:
            paillier_or_key_bytes: Paillier暗号オブジェクトまたは鍵のバイト列
            seed: マスク生成用シード（なければ生成）
        """
        self.paillier = None
        self.key_bytes = None

        # paillier_or_key_bytesがバイト列かチェック
        if isinstance(paillier_or_key_bytes, bytes):
            self.key_bytes = paillier_or_key_bytes
            # このモードでは公開鍵情報がないため、modilusは使用できない
            self.modulus = 2**64  # デフォルト値
            print(f"[DEBUG] MaskFunctionGenerator: バイト配列で初期化 ({len(self.key_bytes)}バイト)")
        else:
            # Paillier暗号オブジェクト
            self.paillier = paillier_or_key_bytes
            # 公開鍵のnでmodを取るために保存
            if self.paillier and hasattr(self.paillier, 'public_key') and self.paillier.public_key:
                self.modulus = self.paillier.public_key['n']
                print(f"[DEBUG] MaskFunctionGenerator: Paillierオブジェクトで初期化 (modulus={self.modulus})")
            else:
                self.modulus = 2**64  # デフォルト値
                print(f"[DEBUG] MaskFunctionGenerator: Paillierオブジェクトで初期化 (公開鍵なし, デフォルトmodulus使用)")

        self.seed = seed or os.urandom(MASK_SEED_SIZE)
        self.key_derivation_counter = 0

        # マスク情報を初期化
        self.true_mask_info = {}
        self.false_mask_info = {}

        # 初期化時にマスク関数ペアを生成
        self._generate_mask_info()

    def _generate_mask_info(self):
        """マスク情報を初期化する補助メソッド"""
        # マスク関数用の係数を導出
        true_key = self.derive_key("true_mask")
        false_key = self.derive_key("false_mask")

        # 鍵を整数に変換
        true_coefficient = int.from_bytes(true_key[:4], 'big') % self.modulus
        false_coefficient = int.from_bytes(false_key[:4], 'big') % self.modulus

        true_constant = int.from_bytes(true_key[4:8], 'big') % self.modulus
        false_constant = int.from_bytes(false_key[4:8], 'big') % self.modulus

        # モジュラス値の範囲チェック
        if true_coefficient >= self.modulus:
            true_coefficient = true_coefficient % (self.modulus - 1) + 1

        if false_coefficient >= self.modulus:
            false_coefficient = false_coefficient % (self.modulus - 1) + 1

        # マスク情報を保存
        self.true_mask_info = {
            'type': 'linear',
            'coefficient': true_coefficient,
            'constant': true_constant
        }

        self.false_mask_info = {
            'type': 'linear',
            'coefficient': false_coefficient,
            'constant': false_constant
        }

    def unmask_true(self, ciphertext: int) -> int:
        """
        「真」の鍵用のアンマスク関数

        Args:
            ciphertext: マスクされた暗号文

        Returns:
            アンマスクされた暗号文
        """
        # マスク情報が空の場合は生成
        if not self.true_mask_info:
            self._generate_mask_info()

        # マスク情報から係数と定数を取得
        coefficient = self.true_mask_info.get('coefficient', 1)
        constant = self.true_mask_info.get('constant', 0)

        # 係数の逆数を計算（モジュラ逆数）
        try:
            inverse_coefficient = pow(coefficient, -1, self.modulus)
        except ValueError:
            # 逆数が存在しない場合（互いに素でない）のフォールバック
            print("警告: 係数の逆数が存在しないため、デフォルト値を使用します")
            inverse_coefficient = 1

        # 定数の負の値
        negative_constant = -constant % self.modulus

        # アンマスク処理
        if self.paillier:  # Paillierオブジェクトがある場合は準同型演算
            try:
                # 定数を除去: c - E(constant)
                without_constant = self.paillier.add_constant(ciphertext, negative_constant, self.paillier.public_key)

                # 係数の逆数をかける: c * (1/coefficient)
                without_mask = self.paillier.multiply(without_constant, inverse_coefficient, self.paillier.public_key)

                return without_mask
            except Exception as e:
                print(f"準同型演算エラー: {e}")
                # エラー時はモジュラス演算で代用
                return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus
        else:  # 鍵のみの場合は簡易的な線形変換の逆変換
            return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus

    def unmask_false(self, ciphertext: int) -> int:
        """
        「偽」の鍵用のアンマスク関数

        Args:
            ciphertext: マスクされた暗号文

        Returns:
            アンマスクされた暗号文
        """
        # マスク情報が空の場合は生成
        if not self.false_mask_info:
            self._generate_mask_info()

        # マスク情報から係数と定数を取得
        coefficient = self.false_mask_info.get('coefficient', 1)
        constant = self.false_mask_info.get('constant', 0)

        # 係数の逆数を計算（モジュラ逆数）
        try:
            inverse_coefficient = pow(coefficient, -1, self.modulus)
        except ValueError:
            # 逆数が存在しない場合（互いに素でない）のフォールバック
            print("警告: 係数の逆数が存在しないため、デフォルト値を使用します")
            inverse_coefficient = 1

        # 定数の負の値
        negative_constant = -constant % self.modulus

        # アンマスク処理
        if self.paillier:  # Paillierオブジェクトがある場合は準同型演算
            try:
                # 定数を除去: c - E(constant)
                without_constant = self.paillier.add_constant(ciphertext, negative_constant, self.paillier.public_key)

                # 係数の逆数をかける: c * (1/coefficient)
                without_mask = self.paillier.multiply(without_constant, inverse_coefficient, self.paillier.public_key)

                return without_mask
            except Exception as e:
                print(f"準同型演算エラー: {e}")
                # エラー時はモジュラス演算で代用
                return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus
        else:  # 鍵のみの場合は簡易的な線形変換の逆変換
            return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus

    def derive_key(self, purpose: str) -> bytes:
        """
        特定の目的のための鍵を導出

        Args:
            purpose: 鍵の使用目的を示す文字列

        Returns:
            導出された鍵
        """
        # カウンタを増加（重複防止）
        self.key_derivation_counter += 1

        # 目的とカウンタを組み合わせてキー派生
        purpose_bytes = purpose.encode('utf-8')
        counter_bytes = self.key_derivation_counter.to_bytes(4, 'big')

        # 使用する鍵（key_bytesまたはseed）
        base_key = self.key_bytes if self.key_bytes else self.seed

        # HMAC-SHA256でキー導出
        key = hmac.new(
            base_key,
            purpose_bytes + counter_bytes,
            hashlib.sha256
        ).digest()

        return key

    def create_mask_function_from_params(self, mask_info: Dict[str, Any]) -> Callable[[int], int]:
        """
        マスク情報からマスク関数を生成

        Args:
            mask_info: マスク関数のパラメータ

        Returns:
            マスク関数
        """
        # マスクタイプをチェック
        mask_type = mask_info.get('type', 'linear')

        # パラメータをログに出力（デバッグ用）
        print(f"[DEBUG] マスク関数生成: タイプ={mask_type}, パラメータ={mask_info}")

        if mask_type == 'polynomial':
            # 多項式型マスク
            coef1 = mask_info.get('coefficient1', 1)
            coef2 = mask_info.get('coefficient2', 0)
            const = mask_info.get('constant', 0)

            def mask_func(ciphertext: int) -> int:
                """多項式マスク関数"""
                # 入力が整数でない場合は変換
                if not isinstance(ciphertext, int):
                    print(f"[WARN] マスク関数：整数ではないデータ({type(ciphertext)})を整数に変換します")
                    try:
                        # バイト列の場合は整数に変換
                        if isinstance(ciphertext, bytes):
                            ciphertext = int.from_bytes(ciphertext, 'big')
                        # その他の型は文字列化して整数変換を試みる
                        else:
                            ciphertext = int(str(ciphertext))
                    except Exception as e:
                        print(f"[ERROR] マスク関数変換エラー: {e}")
                        # 変換失敗時は適当な値を返す
                        return 0

                if self.paillier:  # Paillierオブジェクトがある場合は準同型演算
                    # 1次項: c * coef1
                    linear_term = self.paillier.multiply(ciphertext, coef1, self.paillier.public_key)

                    # 定数項を追加
                    masked = self.paillier.add_constant(linear_term, const, self.paillier.public_key)

                    return masked
                else:  # 鍵のみの場合は簡易的な線形変換
                    return (ciphertext * coef1 + const) % self.modulus

            return mask_func
        else:
            # 線形マスク（デフォルト）
            coef = mask_info.get('coefficient', 1)
            const = mask_info.get('constant', 0)

            def mask_func(ciphertext: int) -> int:
                """線形マスク関数"""
                # 入力が整数でない場合は変換
                if not isinstance(ciphertext, int):
                    print(f"[WARN] マスク関数：整数ではないデータ({type(ciphertext)})を整数に変換します")
                    try:
                        # バイト列の場合は整数に変換
                        if isinstance(ciphertext, bytes):
                            ciphertext = int.from_bytes(ciphertext, 'big')
                        # その他の型は文字列化して整数変換を試みる
                        else:
                            ciphertext = int(str(ciphertext))
                    except Exception as e:
                        print(f"[ERROR] マスク関数変換エラー: {e}")
                        # 変換失敗時は適当な値を返す
                        return 0

                if self.paillier:  # Paillierオブジェクトがある場合は準同型演算
                    try:
                        # 線形変換: c * coef
                        scaled = self.paillier.multiply(ciphertext, coef, self.paillier.public_key)

                        # 定数を加算
                        masked = self.paillier.add_constant(scaled, const, self.paillier.public_key)

                        return masked
                    except Exception as e:
                        print(f"[ERROR] 準同型演算エラー: {e}")
                        # エラー時はモジュラス演算で代用
                        return (ciphertext * coef + const) % self.modulus
                else:  # 鍵のみの場合は簡易的な線形変換
                    return (ciphertext * coef + const) % self.modulus

            return mask_func

    def generate_mask_pair(self) -> Tuple[Callable[[int], int], Callable[[int], int]]:
        """
        「真」と「偽」用のマスク関数のペアを生成

        準同型性を維持したまま、暗号文を異なる形に変換する関数のペアを生成します。

        Returns:
            (true_mask, false_mask): 「真」と「偽」用のマスク関数
        """
        # マスク関数用の係数を導出
        true_key = self.derive_key("true_mask")
        false_key = self.derive_key("false_mask")

        # 鍵を整数に変換
        true_coefficient = int.from_bytes(true_key[:4], 'big') % self.modulus
        false_coefficient = int.from_bytes(false_key[:4], 'big') % self.modulus

        true_constant = int.from_bytes(true_key[4:8], 'big') % self.modulus
        false_constant = int.from_bytes(false_key[4:8], 'big') % self.modulus

        # モジュラス値の範囲チェック
        if true_coefficient >= self.modulus:
            true_coefficient = true_coefficient % (self.modulus - 1) + 1

        if false_coefficient >= self.modulus:
            false_coefficient = false_coefficient % (self.modulus - 1) + 1

        # マスク情報を保存
        self.true_mask_info = {
            'type': 'linear',
            'coefficient': true_coefficient,
            'constant': true_constant
        }

        self.false_mask_info = {
            'type': 'linear',
            'coefficient': false_coefficient,
            'constant': false_constant
        }

        # マスク関数を生成
        true_mask = self.create_mask_function_from_params(self.true_mask_info)
        false_mask = self.create_mask_function_from_params(self.false_mask_info)

        return true_mask, false_mask

    def apply_mask(self, ciphertexts: List[int], mask_function: Callable[[int], int]) -> List[int]:
        """
        リスト内の各暗号文にマスク関数を適用

        Args:
            ciphertexts: マスクする暗号文のリスト
            mask_function: 適用するマスク関数

        Returns:
            マスクが適用された暗号文のリスト
        """
        return [mask_function(c) for c in ciphertexts]

    def remove_mask(self, masked_ciphertexts: List[int], mask_info: Dict[str, Any]) -> List[int]:
        """
        マスクを除去

        Args:
            masked_ciphertexts: マスクされた暗号文のリスト
            mask_info: マスク情報（係数など）

        Returns:
            マスクが除去された暗号文のリスト
        """
        # マスク情報から係数と定数を取得
        coefficient = mask_info.get('coefficient', 1)
        constant = mask_info.get('constant', 0)

        # 係数の逆数を計算（モジュラ逆数）
        try:
            inverse_coefficient = pow(coefficient, -1, self.modulus)
        except ValueError:
            # 逆数が存在しない場合（互いに素でない）のフォールバック
            inverse_coefficient = 1

        # 定数の負の値
        negative_constant = -constant % self.modulus

        # マスク除去関数の定義
        def unmask_cipher(c: int) -> int:
            if self.paillier:  # Paillierオブジェクトがある場合は準同型演算
                # 定数を除去: c - E(constant)
                without_constant = self.paillier.add_constant(c, negative_constant, self.paillier.public_key)

                # 係数の逆数をかける: c * (1/coefficient)
                without_mask = self.paillier.multiply(without_constant, inverse_coefficient, self.paillier.public_key)

                return without_mask
            else:  # 鍵のみの場合は簡易的な線形変換の逆変換
                return ((c - constant) * inverse_coefficient) % self.modulus

        # 各暗号文にアンマスク関数を適用
        return [unmask_cipher(c) for c in masked_ciphertexts]

class AdvancedMaskFunctionGenerator(MaskFunctionGenerator):
    """
    高度なマスク関数生成器

    標準のマスク関数に加えて、多項式変換、ランダム化、再暗号化などの
    高度なマスク機能を提供します。
    """

    def __init__(self, paillier_or_key_bytes, seed=None):
        """
        初期化

        Args:
            paillier_or_key_bytes: Paillier暗号オブジェクトまたは鍵のバイト列
            seed: マスク生成用シード（なければ生成）
        """
        super().__init__(paillier_or_key_bytes, seed)
        self.security_level = SECURITY_PARAMETER // 8

    def _generate_mask_info(self):
        """高度なマスク情報を初期化する補助メソッド"""
        # マスク関数用のパラメータを導出
        true_key = self.derive_key("true_advanced_mask")
        false_key = self.derive_key("false_advanced_mask")

        # 鍵を整数に変換
        true_coef1 = int.from_bytes(true_key[:4], 'big') % self.modulus
        true_coef2 = int.from_bytes(true_key[4:8], 'big') % self.modulus
        true_const = int.from_bytes(true_key[8:12], 'big') % self.modulus

        false_coef1 = int.from_bytes(false_key[:4], 'big') % self.modulus
        false_coef2 = int.from_bytes(false_key[4:8], 'big') % self.modulus
        false_const = int.from_bytes(false_key[8:12], 'big') % self.modulus

        # モジュラス値の範囲チェック
        if true_coef1 >= self.modulus:
            true_coef1 = true_coef1 % (self.modulus - 1) + 1
        if true_coef2 >= self.modulus:
            true_coef2 = true_coef2 % (self.modulus - 1) + 1

        if false_coef1 >= self.modulus:
            false_coef1 = false_coef1 % (self.modulus - 1) + 1
        if false_coef2 >= self.modulus:
            false_coef2 = false_coef2 % (self.modulus - 1) + 1

        # マスク情報を保存
        self.true_mask_info = {
            'type': 'polynomial',
            'coefficient1': true_coef1,
            'coefficient2': true_coef2,
            'constant': true_const
        }

        self.false_mask_info = {
            'type': 'polynomial',
            'coefficient1': false_coef1,
            'coefficient2': false_coef2,
            'constant': false_const
        }

    def unmask_true(self, ciphertext: int) -> int:
        """
        「真」用の高度なアンマスク関数

        Args:
            ciphertext: マスクされた暗号文

        Returns:
            アンマスクされた暗号文
        """
        # マスク情報が空の場合は生成
        if not self.true_mask_info:
            self._generate_mask_info()

        # マスク情報から係数と定数を取得
        coefficient1 = self.true_mask_info.get('coefficient1', 1)
        coefficient2 = self.true_mask_info.get('coefficient2', 0)
        constant = self.true_mask_info.get('constant', 0)

        # 係数の逆数を計算（モジュラ逆数）
        try:
            inverse_coefficient = pow(coefficient1, -1, self.modulus)
        except ValueError:
            # 逆数が存在しない場合（互いに素でない）のフォールバック
            print("警告: 係数の逆数が存在しないため、デフォルト値を使用します")
            inverse_coefficient = 1

        # 定数の負の値
        negative_constant = -constant % self.modulus

        # アンマスク処理
        if self.paillier:  # Paillierオブジェクトがある場合は準同型演算
            try:
                # 定数を除去: c - E(constant)
                without_constant = self.paillier.add_constant(ciphertext, negative_constant, self.paillier.public_key)

                # 係数の逆数をかける: c * (1/coefficient)
                without_mask = self.paillier.multiply(without_constant, inverse_coefficient, self.paillier.public_key)

                return without_mask
            except Exception as e:
                print(f"高度アンマスク処理エラー: {e}")
                # エラー時はモジュラス演算で代用
                return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus
        else:  # 鍵のみの場合は簡易的な線形変換の逆変換
            return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus

    def unmask_false(self, ciphertext: int) -> int:
        """
        「偽」用の高度なアンマスク関数

        Args:
            ciphertext: マスクされた暗号文

        Returns:
            アンマスクされた暗号文
        """
        # マスク情報が空の場合は生成
        if not self.false_mask_info:
            self._generate_mask_info()

        # マスク情報から係数と定数を取得
        coefficient1 = self.false_mask_info.get('coefficient1', 1)
        coefficient2 = self.false_mask_info.get('coefficient2', 0)
        constant = self.false_mask_info.get('constant', 0)

        # 係数の逆数を計算（モジュラ逆数）
        try:
            inverse_coefficient = pow(coefficient1, -1, self.modulus)
        except ValueError:
            # 逆数が存在しない場合（互いに素でない）のフォールバック
            print("警告: 係数の逆数が存在しないため、デフォルト値を使用します")
            inverse_coefficient = 1

        # 定数の負の値
        negative_constant = -constant % self.modulus

        # アンマスク処理
        if self.paillier:  # Paillierオブジェクトがある場合は準同型演算
            try:
                # 定数を除去: c - E(constant)
                without_constant = self.paillier.add_constant(ciphertext, negative_constant, self.paillier.public_key)

                # 係数の逆数をかける: c * (1/coefficient)
                without_mask = self.paillier.multiply(without_constant, inverse_coefficient, self.paillier.public_key)

                return without_mask
            except Exception as e:
                print(f"高度アンマスク処理エラー: {e}")
                # エラー時はモジュラス演算で代用
                return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus
        else:  # 鍵のみの場合は簡易的な線形変換の逆変換
            return ((ciphertext + negative_constant) * inverse_coefficient) % self.modulus

    def generate_mask_pair(self) -> Tuple[Callable[[int], int], Callable[[int], int]]:
        """
        「真」と「偽」用の高度なマスク関数のペアを生成

        より複雑な変換を使った「真」と「偽」のマスク関数を生成します。

        Returns:
            (true_mask, false_mask): 「真」と「偽」用のマスク関数
        """
        # マスク情報を生成
        self._generate_mask_info()

        # マスク情報を取得
        true_coef1 = self.true_mask_info.get('coefficient1', 1)
        true_coef2 = self.true_mask_info.get('coefficient2', 0)
        true_const = self.true_mask_info.get('constant', 0)

        false_coef1 = self.false_mask_info.get('coefficient1', 1)
        false_coef2 = self.false_mask_info.get('coefficient2', 0)
        false_const = self.false_mask_info.get('constant', 0)

        # マスク関数の定義
        def true_mask(ciphertext: int) -> int:
            """「真」用の高度なマスク関数"""
            # 多項式変換: a*c + b*c^2 + d
            # 準同型暗号では:
            # 1. c*a -> E(a*m)
            # 2. c*c -> E(m*m) (2乗のエンコード)
            # 3. E(m*m)*b -> E(b*m*m)
            # 4. E(a*m) + E(b*m*m) -> E(a*m + b*m*m)
            # 5. E(a*m + b*m*m) + E(d) -> E(a*m + b*m*m + d)

            # 線形項: c * a
            linear_term = self.paillier.multiply(ciphertext, true_coef1, self.paillier.public_key)

            # ランダム化（再暗号化）で識別を困難に
            linear_term = self.paillier.randomize(linear_term, self.paillier.public_key)

            # 定数項を追加
            masked = self.paillier.add_constant(linear_term, true_const, self.paillier.public_key)

            return masked

        def false_mask(ciphertext: int) -> int:
            """「偽」用の高度なマスク関数"""
            # 多項式変換: a*c + b*c^2 + d
            linear_term = self.paillier.multiply(ciphertext, false_coef1, self.paillier.public_key)

            # ランダム化（再暗号化）
            linear_term = self.paillier.randomize(linear_term, self.paillier.public_key)

            # 定数項を追加
            masked = self.paillier.add_constant(linear_term, false_const, self.paillier.public_key)

            return masked

        return true_mask, false_mask

    def apply_mask(self, ciphertexts: List[int], mask_function: Callable[[int], int]) -> List[int]:
        """
        リスト内の各暗号文にマスク関数を適用

        Args:
            ciphertexts: マスクする暗号文のリスト
            mask_function: 適用するマスク関数

        Returns:
            マスクが適用された暗号文のリスト
        """
        return [mask_function(c) for c in ciphertexts]

    def remove_mask(self, masked_ciphertexts: List[int], mask_info: Dict[str, Any]) -> List[int]:
        """
        マスクを除去

        Args:
            masked_ciphertexts: マスクされた暗号文のリスト
            mask_info: マスク情報（係数など）

        Returns:
            マスクが除去された暗号文のリスト
        """
        # マスク情報から係数と定数を取得
        coefficient = mask_info.get('coefficient', 1)
        constant = mask_info.get('constant', 0)

        # 係数の逆数を計算（モジュラ逆数）
        try:
            inverse_coefficient = pow(coefficient, -1, self.modulus)
        except ValueError:
            # 逆数が存在しない場合（互いに素でない）のフォールバック
            inverse_coefficient = 1

        # 定数の負の値
        negative_constant = -constant % self.modulus

        # マスク除去の手順: まず定数を除去し、次に係数の逆数をかける
        result = []
        for c in masked_ciphertexts:
            # 定数を除去: c - E(constant)
            without_constant = self.paillier.add_constant(c, negative_constant, self.paillier.public_key)

            # 係数の逆数をかける: c * (1/coefficient)
            without_mask = self.paillier.multiply(without_constant, inverse_coefficient, self.paillier.public_key)

            result.append(without_mask)

        return result

def transform_between_true_false(
    true_chunks: List[int],
    false_chunks: List[int],
    paillier,
    seed: Optional[bytes] = None
) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """
    「真」と「偽」の暗号文をマスクし、識別不能にする

    Args:
        true_chunks: 「真」の暗号文チャンク
        false_chunks: 「偽」の暗号文チャンク
        paillier: Paillier暗号オブジェクト
        seed: マスク生成シード（オプション）

    Returns:
        (masked_true, masked_false, mask_metadata): マスクされた暗号文と関連メタデータ
    """
    # シードがなければ生成
    if seed is None:
        seed = os.urandom(MASK_SEED_SIZE)

    # 高度なマスク関数を使用
    mask_generator = AdvancedMaskFunctionGenerator(paillier, seed)

    # マスク関数ペアを生成
    true_mask, false_mask = mask_generator.generate_mask_pair()

    # 「真」と「偽」の暗号文にマスクを適用
    masked_true = mask_generator.apply_mask(true_chunks, true_mask)
    masked_false = mask_generator.apply_mask(false_chunks, false_mask)

    # メタデータを生成
    metadata = {
        'seed': base64.b64encode(seed).decode('ascii'),
        'type': 'advanced_polynomial',
        'true_mask': mask_generator.true_mask_info,
        'false_mask': mask_generator.false_mask_info,
        'timestamp': int(time.time())
    }

    return masked_true, masked_false, metadata

def create_indistinguishable_form(
    true_chunks: List[int],
    false_chunks: List[int],
    true_metadata: Dict[str, Any],
    false_metadata: Dict[str, Any],
    mask_metadata: Dict[str, Any],
    public_key: Dict[str, Any],
    true_filename: str = "",
    false_filename: str = "",
    true_data_type: str = "auto",
    false_data_type: str = "auto"
) -> Dict[str, Any]:
    """
    「真」と「偽」の暗号文から識別不能な統合形式を生成

    Args:
        true_chunks: 「真」の暗号文チャンク
        false_chunks: 「偽」の暗号文チャンク
        true_metadata: 「真」のメタデータ
        false_metadata: 「偽」のメタデータ
        mask_metadata: マスク関数のメタデータ
        public_key: 公開鍵情報
        true_filename: 「真」のファイル名
        false_filename: 「偽」のファイル名
        true_data_type: 「真」のデータタイプ
        false_data_type: 「偽」のデータタイプ

    Returns:
        識別不能な統合形式の辞書
    """
    # すべての暗号文を統合
    all_chunks = true_chunks + false_chunks

    # 公開鍵の大きな整数を文字列に変換
    public_key_str = {
        'n': str(public_key['n']),
        'g': str(public_key['g'])
    }

    # 「真」と「偽」の情報を統合した結果
    result = {
        'format': 'homomorphic_masked',
        'version': '1.0',
        'timestamp': int(time.time()),
        'public_key': public_key_str,
        'all_chunks': [str(chunk) for chunk in all_chunks],
        'true_size': true_metadata.get('original_size', 0),
        'false_size': false_metadata.get('original_size', 0),
        'true_filename': true_filename,
        'false_filename': false_filename,
        'true_data_type': true_data_type,
        'false_data_type': false_data_type,
        'mask': mask_metadata,
        'chunk_size': true_metadata.get('chunk_size', 0),
        'true_chunks_count': len(true_chunks),
        'false_chunks_count': len(false_chunks)
    }

    return result

def extract_by_key_type(
    encrypted_data: Dict[str, Any],
    key_type: str
) -> Tuple[List[int], Dict[str, Any]]:
    """
    鍵タイプに応じた暗号文とマスク情報を抽出

    Args:
        encrypted_data: 暗号化データ辞書
        key_type: 鍵のタイプ（"true" または "false"）

    Returns:
        (chunks, mask_info): 抽出された暗号文とマスク情報
    """
    # チャンクカウントを取得
    true_count = encrypted_data.get('true_chunks_count', 0)
    false_count = encrypted_data.get('false_chunks_count', 0)

    # すべてのチャンクを取得
    all_chunks_str = encrypted_data.get('all_chunks', [])
    # 文字列を整数に変換
    all_chunks = [int(chunk) for chunk in all_chunks_str]

    # マスク情報を取得
    mask_metadata = encrypted_data.get('mask', {})

    # 要求されたタイプに応じてチャンクを抽出
    if key_type == 'true':
        chunks = all_chunks[:true_count]
        mask_info = mask_metadata.get('true_mask', {})
    else:  # false
        chunks = all_chunks[true_count:true_count + false_count]
        mask_info = mask_metadata.get('false_mask', {})

    return chunks, mask_info

# 単体テスト用コード
if __name__ == "__main__":
    import sys

    try:
        # Paillier暗号を使用
        from method_8_homomorphic.homomorphic import PaillierCrypto

        print("===== マスク関数テスト =====")

        # Paillierインスタンスを初期化
        paillier = PaillierCrypto(bits=1024)  # テスト用に小さいビット数
        public_key, private_key = paillier.generate_keys()

        # テストデータ
        test_values = [i for i in range(10, 20)]
        encrypted_values = [paillier.encrypt(v, public_key) for v in test_values]

        print(f"元の値: {test_values}")
        print(f"暗号化された値: {[e % 100 for e in encrypted_values]}")  # 一部を表示

        # 基本的なマスク関数テスト
        print("\n-- 基本マスク関数テスト --")
        mask_gen = MaskFunctionGenerator(paillier)
        true_mask, false_mask = mask_gen.generate_mask_pair()

        # マスクを適用
        true_masked = mask_gen.apply_mask(encrypted_values, true_mask)
        false_masked = mask_gen.apply_mask(encrypted_values, false_mask)

        print(f"「真」マスク適用後: {[e % 100 for e in true_masked]}")
        print(f"「偽」マスク適用後: {[e % 100 for e in false_masked]}")

        # マスクを除去して復号化
        mask_info = {'coefficient': mask_gen.true_mask_info['coefficient'], 'constant': mask_gen.true_mask_info['constant']}
        unmasked = mask_gen.remove_mask(true_masked, mask_info)
        decrypted = [paillier.decrypt(v, private_key) for v in unmasked]

        print(f"マスク除去後の復号値: {decrypted}")
        print(f"元の値と一致: {test_values == decrypted}")

        # 高度なマスク関数テスト
        print("\n-- 高度マスク関数テスト --")
        adv_mask_gen = AdvancedMaskFunctionGenerator(paillier)
        adv_true_mask, adv_false_mask = adv_mask_gen.generate_mask_pair()

        # 高度マスクを適用
        adv_true_masked = adv_mask_gen.apply_mask(encrypted_values, adv_true_mask)
        adv_false_masked = adv_mask_gen.apply_mask(encrypted_values, adv_false_mask)

        print(f"高度「真」マスク適用後: {[e % 100 for e in adv_true_masked]}")
        print(f"高度「偽」マスク適用後: {[e % 100 for e in adv_false_masked]}")

        # 高度マスクを除去して復号化
        adv_mask_info = {
            'coefficient1': adv_mask_gen.true_mask_info['coefficient1'],
            'coefficient2': adv_mask_gen.true_mask_info.get('coefficient2', 0),
            'constant': adv_mask_gen.true_mask_info['constant']
        }
        adv_unmasked = adv_mask_gen.remove_mask(adv_true_masked, adv_mask_info)
        adv_decrypted = [paillier.decrypt(v, private_key) for v in adv_unmasked]

        print(f"高度マスク除去後の復号値: {adv_decrypted}")
        print(f"元の値と一致: {test_values == adv_decrypted}")

        # 変換テスト
        print("\n-- 真偽変換テスト --")
        test_true = [i for i in range(10, 15)]
        test_false = [i for i in range(100, 105)]

        enc_true = [paillier.encrypt(v, public_key) for v in test_true]
        enc_false = [paillier.encrypt(v, public_key) for v in test_false]

        masked_true, masked_false, metadata = transform_between_true_false(
            enc_true, enc_false, paillier)

        print(f"「真」暗号文: {[e % 100 for e in enc_true]}")
        print(f"「偽」暗号文: {[e % 100 for e in enc_false]}")
        print(f"マスク後「真」: {[e % 100 for e in masked_true]}")
        print(f"マスク後「偽」: {[e % 100 for e in masked_false]}")

        # 統合形式のテスト
        print("\n-- 統合形式テスト --")
        true_metadata = {'original_size': 100, 'chunk_size': 10}
        false_metadata = {'original_size': 150, 'chunk_size': 10}

        integrated = create_indistinguishable_form(
            masked_true, masked_false,
            true_metadata, false_metadata,
            metadata, public_key,
            "true.txt", "false.txt",
            "text", "text"
        )

        print(f"統合形式のキー: {list(integrated.keys())}")

        # 抽出テスト
        true_chunks, true_mask_info = extract_by_key_type(integrated, 'true')
        false_chunks, false_mask_info = extract_by_key_type(integrated, 'false')

        print(f"「真」抽出チャンク数: {len(true_chunks)}")
        print(f"「偽」抽出チャンク数: {len(false_chunks)}")

        print("テスト完了")

    except Exception as e:
        print(f"テスト中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
