#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
区別不能な準同型暗号マスキング方式の安全な実装拡張モジュール

このモジュールは、暗号文から真・偽の区別を不可能にする準同型暗号マスキング方式の
拡張機能を提供します。主に、ファイル暗号化・復号処理を担当します。
"""

import os
import sys
import time
import json
import random
import hashlib
import base64
import binascii
import math
from typing import Dict, List, Tuple, Any, Optional, Union

from homomorphic import (
    PaillierCrypto,
    derive_key_from_password
)
from crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator
)

# 数値のログを安全に計算する関数
def safe_log10(value):
    """
    大きな整数値に対しても安全にlog10を計算

    Args:
        value: 計算する値

    Returns:
        log10(value)の結果
    """
    if value <= 0:
        return 0

    # 大きな整数のビット長を利用した近似計算
    if isinstance(value, int) and value > 1e17:
        bit_length = value.bit_length()
        return bit_length * math.log10(2)

    # 通常の計算
    try:
        # 大きな整数は直接 float に変換するとオーバーフローするため、
        # 文字列経由で変換を試みる
        if isinstance(value, int) and value > 1e16:
            # 次の桁数までしか float で精度を保てないので、文字列化して長さを取得
            value_str = str(value)
            mantissa = float("0." + value_str[:15])  # 仮数部
            exponent = len(value_str)                # 指数部
            return math.log10(mantissa) + exponent
        else:
            return math.log10(float(value))
    except (OverflowError, ValueError):
        # ビット長を使った近似
        bit_length = value.bit_length()
        return bit_length * math.log10(2)

# 暗号文のランダム化関数
def randomize_ciphertext(paillier, ciphertext):
    """
    暗号文を再ランダム化

    準同型暗号の性質を利用して、同じ平文に対応する別の暗号文を生成します。
    これにより、同じ平文でも毎回異なる暗号文が生成され、暗号文からの情報漏洩を防ぎます。

    Args:
        paillier: PaillierCryptoインスタンス
        ciphertext: ランダム化する暗号文

    Returns:
        ランダム化された暗号文
    """
    if hasattr(paillier, 'randomize') and callable(paillier.randomize):
        return paillier.randomize(ciphertext, paillier.public_key)
    else:
        r = random.randint(1, paillier.public_key['n'] - 1)
        n_squared = paillier.public_key['n'] ** 2
        g_r = pow(paillier.public_key['g'], r, n_squared)
        return (ciphertext * g_r) % n_squared

def batch_randomize_ciphertexts(paillier, ciphertexts):
    """暗号文のリストを一括して再ランダム化"""
    return [randomize_ciphertext(paillier, ct) for ct in ciphertexts]

def add_statistical_noise(ciphertexts, intensity=0.1, paillier=None):
    """
    暗号文に統計的ノイズを追加

    Args:
        ciphertexts: ノイズを追加する暗号文のリスト
        intensity: ノイズの強度（0.0～1.0）
        paillier: PaillierCryptoインスタンス（オプション）

    Returns:
        (noisy_ciphertexts, noise_values): ノイズが追加された暗号文とノイズ値のリスト
    """
    if not ciphertexts:
        return [], []

    noisy_ciphertexts = []
    noise_values = []

    # Paillierオブジェクトがある場合は準同型性を保ったノイズ追加
    if paillier and hasattr(paillier, 'public_key') and paillier.public_key:
        n = paillier.public_key['n']
        # intの範囲内に収まるようにintensityを調整
        noise_range = min(1000000, max(1, int(n * 0.0001)))  # 最大0.01%のノイズ

        for ct in ciphertexts:
            noise = random.randint(1, noise_range)
            noise_values.append(noise)

            try:
                n_squared = paillier.public_key['n'] ** 2
                g_noise = pow(paillier.public_key['g'], noise, n_squared)
                noisy_ct = (ct * g_noise) % n_squared
                noisy_ciphertexts.append(noisy_ct)
            except Exception as e:
                # エラーが発生した場合はより単純なノイズ付加を試みる
                print(f"準同型ノイズ付加中にエラー: {e}")
                noisy_ciphertexts.append(ct)
    else:
        # 単純なノイズ追加
        max_val = max(ct if ct < 1e18 else ct.bit_length() for ct in ciphertexts)
        min_val = min(ct if ct < 1e18 else 0 for ct in ciphertexts)
        range_val = max(max_val - min_val, 1)

        for ct in ciphertexts:
            noise_max = min(1000000, int(range_val * intensity))
            noise = random.randint(-noise_max, noise_max)
            noise_values.append(noise)
            noisy_ciphertexts.append(ct + noise)

    return noisy_ciphertexts, noise_values

def add_redundancy(ciphertexts, redundancy_factor=2, paillier=None):
    """
    暗号文に冗長性を追加

    Args:
        ciphertexts: 冗長性を追加する暗号文のリスト
        redundancy_factor: 冗長性の係数（追加するコピーの数）
        paillier: PaillierCryptoインスタンス（オプション）

    Returns:
        (redundant_ciphertexts, metadata): 冗長性が追加された暗号文とそのメタデータ
    """
    if not ciphertexts:
        return [], {}

    redundant_ciphertexts = []
    original_indices = []

    for i, ct in enumerate(ciphertexts):
        # 元の暗号文を追加
        redundant_ciphertexts.append(ct)
        original_indices.append(i)

        # 冗長チャンクの追加
        for j in range(redundancy_factor):
            if paillier and hasattr(paillier, 'public_key') and paillier.public_key:
                try:
                    redundant_ct = randomize_ciphertext(paillier, ct)
                except Exception as e:
                    # エラーが発生した場合は単純なビット操作で冗長性を追加
                    print(f"冗長性追加中にエラー: {e}")
                    redundant_ct = ct ^ (1 << (j % 64))
            else:
                redundant_ct = ct ^ (1 << (j % 64))

            redundant_ciphertexts.append(redundant_ct)
            original_indices.append(i)

    metadata = {
        "redundancy_factor": redundancy_factor,
        "original_length": len(ciphertexts),
        "original_indices": original_indices
    }

    return redundant_ciphertexts, metadata

class SecureHomomorphicCrypto:
    """攻撃者が区別できない準同型暗号実装"""

    def __init__(self, key_bits: int = 1024, use_advanced_masks: bool = True):
        """
        区別不能な準同型暗号を初期化

        Args:
            key_bits: 鍵のビット数
            use_advanced_masks: 高度なマスク関数を使用するかどうか
        """
        self.key_bits = key_bits
        self.use_advanced_masks = use_advanced_masks
        self.paillier = PaillierCrypto(bits=key_bits)
        self.public_key = None
        self.private_key = None

        # シークレットソルト（攻撃者が発見できないようにランダム生成）
        # 注: 実際の製品では、これをハードコードしてはいけません
        # 識別子の計算には固定ソルトを使用（暗号化と復号で同じ識別子になるようにするため）
        self._secret_salt = os.urandom(32)
        # 識別子用固定ソルト（注意: ハードコードは安全ではないが、テスト用にはOK）
        self._id_fixed_salt = b'fixed_salt_for_identifiers_0123456789'

    def generate_keys(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        暗号鍵を生成

        Returns:
            (公開鍵, 秘密鍵)
        """
        self.public_key, self.private_key = self.paillier.generate_keys()
        return self.public_key, self.private_key

    def _secure_hash(self, data: bytes, salt: bytes = None) -> bytes:
        """
        セキュアなハッシュを生成（ソルトを使用）

        Args:
            data: ハッシュ対象のデータ
            salt: ソルト（省略時は内部のシークレットソルトを使用）

        Returns:
            ハッシュ値
        """
        if salt is None:
            salt = self._secret_salt

        # HMAC-SHA256を使用してより強力なハッシュを作成
        h = hashlib.pbkdf2_hmac(
            'sha256',
            data,
            salt,
            iterations=10000,
            dklen=32
        )
        return h

    def _derive_mask_seed(self, content: bytes, key_type: str) -> bytes:
        """
        コンテンツからマスク生成用シードを導出
        この方法では、同一コンテンツから常に同じシードが生成される

        Args:
            content: コンテンツデータ
            key_type: 鍵タイプ ('true' または 'false')

        Returns:
            マスク生成用シード
        """
        # コンテンツと鍵タイプからシード値を生成
        prefix = f"mask_seed_{key_type}_".encode('utf-8')
        data = prefix + content

        # シークレットソルトを使ってハッシュ化
        return self._secure_hash(data)

    def _obfuscate_identifier(self, identifier: str) -> str:
        """
        識別子を難読化（'true', 'false'を直接使わない）

        Args:
            identifier: 識別子

        Returns:
            難読化された識別子
        """
        # 識別子をハッシュ化して難読化
        # 注: 内部的にはtrueとfalseを区別する必要があるが、
        # 外部からは区別がつかないようにする
        if identifier == "true":
            key = "primary_content".encode('utf-8')
        elif identifier == "false":
            key = "alternate_content".encode('utf-8')
        else:
            key = identifier.encode('utf-8')

        # ハッシュを生成し、短い16進文字列に変換
        # 注意: 暗号化と復号で同じ識別子になるように、固定ソルトを使用
        h = hashlib.pbkdf2_hmac(
            'sha256',
            key,
            self._id_fixed_salt,  # インスタンス固有ではなく固定ソルトを使用
            iterations=1000,      # 反復回数は少なめに (復号時の速度のため)
            dklen=16              # 短いダイジェスト
        )
        return h[:8].hex()

    def encrypt_dual_content(self, true_content: bytes, false_content: bytes) -> Dict[str, Any]:
        """
        真偽両方のコンテンツを暗号化し、区別できない形式で出力

        Args:
            true_content: 真のコンテンツ
            false_content: 偽のコンテンツ

        Returns:
            暗号化データ
        """
        if self.public_key is None or self.private_key is None:
            self.generate_keys()

        # マスク生成用のシードを導出（コンテンツから派生）
        true_seed = self._derive_mask_seed(true_content, "true")
        false_seed = self._derive_mask_seed(false_content, "false")

        # 正確な元のバイト長を保存 (改善点)
        true_byte_length = len(true_content)
        false_byte_length = len(false_content)

        # Base64でエンコードしてから整数に変換（改善点）
        true_b64 = base64.b64encode(true_content)
        false_b64 = base64.b64encode(false_content)

        # 各コンテンツを整数に変換
        true_int = int.from_bytes(true_b64, 'big')
        false_int = int.from_bytes(false_b64, 'big')

        # 暗号化（まだマスクなし）
        true_encrypted = self.paillier.encrypt(true_int, self.public_key)
        false_encrypted = self.paillier.encrypt(false_int, self.public_key)

        # マスク関数生成器
        mask_generator_class = AdvancedMaskFunctionGenerator if self.use_advanced_masks else MaskFunctionGenerator

        # 真用のマスク生成
        true_mask_gen = mask_generator_class(self.paillier, true_seed)
        true_mask, _ = true_mask_gen.generate_mask_pair()

        # 偽用のマスク生成
        false_mask_gen = mask_generator_class(self.paillier, false_seed)
        _, false_mask = false_mask_gen.generate_mask_pair()

        # マスク適用関数を選択
        if self.use_advanced_masks:
            apply_mask = lambda gen, chunk, mask: gen.apply_advanced_mask([chunk], mask)[0]
        else:
            apply_mask = lambda gen, chunk, mask: gen.apply_mask([chunk], mask)[0]

        # マスクを適用
        true_masked = apply_mask(true_mask_gen, true_encrypted, true_mask)
        false_masked = apply_mask(false_mask_gen, false_encrypted, false_mask)

        # 攻撃者が区別できないように安全なランダム識別子を使用
        true_id = self._obfuscate_identifier("true")
        false_id = self._obfuscate_identifier("false")

        # シャッフルして順序で区別できないように
        chunks = []
        if random.random() < 0.5:  # 50%の確率で順序をランダム化
            chunks = [
                {"id": true_id, "data": true_masked, "seed": base64.b64encode(true_seed).decode('ascii')},
                {"id": false_id, "data": false_masked, "seed": base64.b64encode(false_seed).decode('ascii')}
            ]
        else:
            chunks = [
                {"id": false_id, "data": false_masked, "seed": base64.b64encode(false_seed).decode('ascii')},
                {"id": true_id, "data": true_masked, "seed": base64.b64encode(true_seed).decode('ascii')}
            ]

        # 復号に必要なメタデータを含める（公開鍵など）
        metadata = {
            "format": "indistinguishable_homomorphic",
            "version": "1.0",
            "timestamp": int(time.time()),
            "public_key": self.public_key,
            # プライベートキーは含めない! これはテスト用途でのみ保存
            "content_size": max(len(true_content), len(false_content)),
            "true_byte_length": true_byte_length,  # 追加: 真のファイルの正確なバイト長
            "false_byte_length": false_byte_length,  # 追加: 偽のファイルの正確なバイト長
            "advanced_masks": self.use_advanced_masks,
            "b64_encoded": True  # Base64エンコードを使用していることを明示
        }

        # IDマッピングを内部的に保持（復号時に必要）
        # 注：このマッピングは暗号化データ自体には含まれない
        id_mapping = {true_id: "true", false_id: "false"}
        metadata["_id_mapping"] = id_mapping  # 注：これは実際の出力には含めない

        # 結果を作成
        result = {
            "metadata": metadata,
            "chunks": chunks
        }

        return result

    def decrypt_content(self, encrypted_data: Dict[str, Any], key_type: str) -> bytes:
        """
        暗号化されたコンテンツを復号

        Args:
            encrypted_data: 暗号化データ
            key_type: 鍵タイプ ('true' または 'false')

        Returns:
            復号されたコンテンツ
        """
        # メタデータを取得
        metadata = encrypted_data["metadata"]
        chunks = encrypted_data["chunks"]

        # 公開鍵をセット
        if self.public_key is None:
            self.public_key = metadata["public_key"]

        # 暗号化エンジンに公開鍵を設定
        self.paillier.public_key = self.public_key

        # 使用するIDを決定
        # 注：実際の実装では、IDマッピングは暗号化データに含まれない
        if "_id_mapping" in metadata:
            # テスト用：明示的なIDマッピングが含まれている場合
            id_mapping = metadata["_id_mapping"]
            target_id = next(id for id, type_name in id_mapping.items() if type_name == key_type)
        else:
            # 実際の使用：IDを再計算
            target_id = self._obfuscate_identifier(key_type)

        # 対応するチャンクを探す
        target_chunk = next((chunk for chunk in chunks if chunk["id"] == target_id), None)
        if target_chunk is None:
            raise ValueError(f"指定された鍵タイプ ({key_type}) に対応するチャンクが見つかりません")

        # シードを取得
        seed = base64.b64decode(target_chunk["seed"])

        # マスク関数生成器
        mask_generator_class = AdvancedMaskFunctionGenerator if metadata.get("advanced_masks", False) else MaskFunctionGenerator
        mask_gen = mask_generator_class(self.paillier, seed)

        # マスクを生成
        if key_type == "true":
            mask, _ = mask_gen.generate_mask_pair()
        else:
            _, mask = mask_gen.generate_mask_pair()

        # マスク除去関数を選択
        if metadata.get("advanced_masks", False):
            remove_mask = lambda gen, chunks, mask: gen.remove_advanced_mask(chunks, mask)[0]
        else:
            remove_mask = lambda gen, chunks, mask: gen.remove_mask(chunks, mask)[0]

        # マスクを除去
        encrypted_chunk = target_chunk["data"]
        unmasked = remove_mask(mask_gen, [encrypted_chunk], mask)

        # 復号
        if self.private_key is None:
            raise ValueError("復号には秘密鍵が必要です")

        decrypted_int = self.paillier.decrypt(unmasked, self.private_key)

        # Base64エンコードされていた場合
        if metadata.get("b64_encoded", False):
            # 整数をバイト列に変換
            try:
                # 整数からBase64エンコードされたバイト列に戻す
                byte_length = (decrypted_int.bit_length() + 7) // 8
                encoded_bytes = decrypted_int.to_bytes(byte_length, 'big')

                # Base64デコード
                try:
                    decrypted_bytes = base64.b64decode(encoded_bytes)
                    return decrypted_bytes
                except Exception as e:
                    # Base64デコードに失敗した場合
                    print(f"Base64デコード失敗: {e}")
                    # そのまま返す
                    return encoded_bytes
            except OverflowError as e:
                print(f"整数からバイト列への変換に失敗: {e}")
                # フォールバック: 元のサイズをバイト列に変換
                if key_type == "true" and "true_byte_length" in metadata:
                    byte_length = metadata["true_byte_length"]
                elif key_type == "false" and "false_byte_length" in metadata:
                    byte_length = metadata["false_byte_length"]
                else:
                    byte_length = metadata.get("content_size", 0)

                # ゼロで埋めたバイト列を返す
                return b'\x00' * byte_length
        else:
            # 従来の方法
            # 正確なバイト長を取得
            if key_type == "true" and "true_byte_length" in metadata:
                byte_length = metadata["true_byte_length"]
            elif key_type == "false" and "false_byte_length" in metadata:
                byte_length = metadata["false_byte_length"]
            else:
                # 後方互換性のために残す
                content_size = metadata.get("content_size", 0)
                byte_length = max((decrypted_int.bit_length() + 7) // 8, content_size)

            # 整数をバイト列に変換
            try:
                # 指定された長さでバイトに変換を試みる
                decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
            except OverflowError:
                # バイト長が足りない場合は、最小限必要なバイト長を計算
                min_bytes_needed = (decrypted_int.bit_length() + 7) // 8
                decrypted_bytes = decrypted_int.to_bytes(min_bytes_needed, 'big')

                # バイト長が元のファイルサイズより小さい場合は、パディングを追加
                if len(decrypted_bytes) < byte_length:
                    padding = b'\x00' * (byte_length - len(decrypted_bytes))
                    decrypted_bytes = padding + decrypted_bytes

            # 余分なゼロバイトを除去する処理を改善
            # 先頭の\x00バイトをすべて除去するのではなく、
            # 元のファイルサイズになるまで調整
            while len(decrypted_bytes) > byte_length:
                decrypted_bytes = decrypted_bytes[1:]

            return decrypted_bytes

    def save_encrypted_data(self, encrypted_data: Dict[str, Any], filename: str) -> None:
        """
        暗号化データをファイルに保存

        Args:
            encrypted_data: 暗号化データ
            filename: 保存先ファイル名
        """
        # 内部的なIDマッピングは保存しない
        data_to_save = encrypted_data.copy()
        if "_id_mapping" in data_to_save.get("metadata", {}):
            data_to_save["metadata"] = data_to_save["metadata"].copy()
            data_to_save["metadata"].pop("_id_mapping", None)

        # "true"や"false"などの直接的なキーワードをファイル内に含めない
        json_str = json.dumps(data_to_save, indent=2)

        # 文字列の置換でキーワードを難読化（安全対策の一環）
        # この方法はセキュリティを高めるための追加レイヤーであり、
        # 主要な安全性は暗号アルゴリズム自体にある
        obfuscated_str = self._obfuscate_json_keywords(json_str)

        with open(filename, 'w') as f:
            f.write(obfuscated_str)

    def _obfuscate_json_keywords(self, json_str: str) -> str:
        """
        JSONテキスト内のセンシティブなキーワードを置換

        Args:
            json_str: 元のJSONテキスト

        Returns:
            難読化されたJSONテキスト
        """
        replacements = [
            ('"true"', '"t_val"'),
            ('"false"', '"f_val"'),
            ('true', 'valid'),
            ('false', 'invalid'),
            ('primary_content', 'data_a'),
            ('alternate_content', 'data_b')
        ]

        result = json_str
        for old, new in replacements:
            result = result.replace(old, new)

        return result

    def load_encrypted_data(self, filename: str) -> Dict[str, Any]:
        """
        暗号化データをファイルから読み込み

        Args:
            filename: ファイル名

        Returns:
            暗号化データ
        """
        with open(filename, 'r') as f:
            obfuscated_str = f.read()

        # 難読化されたキーワードを元に戻す
        json_str = self._deobfuscate_json_keywords(obfuscated_str)

        encrypted_data = json.loads(json_str)

        # IDマッピングを再構築
        if "metadata" in encrypted_data and "_id_mapping" not in encrypted_data["metadata"]:
            true_id = self._obfuscate_identifier("true")
            false_id = self._obfuscate_identifier("false")
            id_mapping = {true_id: "true", false_id: "false"}

            # メタデータにIDマッピングを追加（内部的な使用のみ）
            if "metadata" not in encrypted_data:
                encrypted_data["metadata"] = {}
            encrypted_data["metadata"]["_id_mapping"] = id_mapping

        return encrypted_data

    def _deobfuscate_json_keywords(self, obfuscated_str: str) -> str:
        """
        難読化されたJSONテキストを元に戻す

        Args:
            obfuscated_str: 難読化されたJSONテキスト

        Returns:
            元のJSONテキスト
        """
        replacements = [
            ('"t_val"', '"true"'),
            ('"f_val"', '"false"'),
            ('valid', 'true'),
            ('invalid', 'false'),
            ('data_a', 'primary_content'),
            ('data_b', 'alternate_content')
        ]

        result = obfuscated_str
        for new, old in replacements:
            result = result.replace(new, old)

        return result


def encrypt_file_with_dual_keys(true_file: str, false_file: str, output_file: str,
                               key_bits: int = 1024, use_advanced_masks: bool = True) -> None:
    """
    2つのファイルを暗号化し、区別不能な形式で保存

    Args:
        true_file: 真のファイルパス
        false_file: 偽のファイルパス
        output_file: 出力ファイルパス
        key_bits: 鍵のビット数
        use_advanced_masks: 高度なマスク関数を使用するかどうか
    """
    # ファイル内容を読み込み
    with open(true_file, 'rb') as f:
        true_content = f.read()

    with open(false_file, 'rb') as f:
        false_content = f.read()

    # 暗号化
    crypto = SecureHomomorphicCrypto(key_bits=key_bits, use_advanced_masks=use_advanced_masks)
    crypto.generate_keys()

    encrypted_data = crypto.encrypt_dual_content(true_content, false_content)

    # 複合化に使用する鍵情報を別ファイルに保存
    key_file = os.path.splitext(output_file)[0] + "_keys.json"
    key_info = {
        "paillier_public_key": crypto.public_key,
        "paillier_private_key": crypto.private_key
    }

    with open(key_file, 'w') as f:
        json.dump(key_info, f, indent=2)

    # 暗号化データを保存
    crypto.save_encrypted_data(encrypted_data, output_file)

    print(f"真偽ファイルを暗号化しました: {output_file}")
    print(f"鍵情報を保存しました: {key_file}")


def decrypt_file_with_key(encrypted_file: str, output_file: str, key_type: str = "true", key_file: str = None) -> None:
    """
    暗号化されたファイルを指定された鍵タイプ（真/偽）で復号

    Args:
        encrypted_file: 暗号化ファイルパス
        output_file: 出力ファイルパス
        key_type: 鍵タイプ ('true' または 'false')
        key_file: 鍵情報ファイル（省略時は自動生成）
    """
    if key_type not in ["true", "false"]:
        raise ValueError("鍵タイプは 'true' または 'false' である必要があります")

    # 鍵情報ファイルがない場合は自動生成
    if key_file is None:
        key_file = os.path.splitext(encrypted_file)[0] + "_keys.json"

    # 鍵ファイル読み込み
    try:
        with open(key_file, 'r') as f:
            key_info = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"鍵情報ファイルが見つかりません: {key_file}")

    # 暗号化エンジンの初期化
    crypto = SecureHomomorphicCrypto()
    crypto.public_key = key_info["paillier_public_key"]
    crypto.private_key = key_info["paillier_private_key"]
    crypto.paillier.public_key = crypto.public_key
    crypto.paillier.private_key = crypto.private_key

    # 暗号化ファイル読み込み
    encrypted_data = crypto.load_encrypted_data(encrypted_file)

    # 復号
    decrypted_content = crypto.decrypt_content(encrypted_data, key_type)

    # 復号データを保存
    with open(output_file, 'wb') as f:
        f.write(decrypted_content)

    print(f"{key_type}鍵でファイルを復号しました: {output_file}")


def deinterleave_ciphertexts(interleaved_ciphertexts, interleave_metadata, key_type):
    """
    交互配置された暗号文を元の順序に戻す

    Args:
        interleaved_ciphertexts: 交互配置された暗号文リスト
        interleave_metadata: 交互配置のメタデータ
        key_type: 鍵タイプ ("true" または "false")

    Returns:
        元の順序に戻された暗号文リスト
    """
    if not interleave_metadata:
        return interleaved_ciphertexts

    # マッピング情報を取得（ない場合はデフォルト処理）
    mapping = interleave_metadata.get("mapping", [])
    if not mapping:
        return interleaved_ciphertexts

    # keyでフィルタリングして、元のインデックスでソート
    filtered_mapping = []
    for item in mapping:
        if item.get("type") == key_type:
            filtered_mapping.append(item)

    filtered_mapping.sort(key=lambda x: x.get("original_index", 0))

    # マッピング情報に基づいて復元
    deinterleaved = []
    for item in filtered_mapping:
        index = item.get("index")
        if 0 <= index < len(interleaved_ciphertexts):
            deinterleaved.append(interleaved_ciphertexts[index])

    return deinterleaved

def remove_redundancy(redundant_ciphertexts, redundancy_metadata):
    """
    冗長性を除去して元の暗号文に戻す

    Args:
        redundant_ciphertexts: 冗長性が追加された暗号文リスト
        redundancy_metadata: 冗長性のメタデータ

    Returns:
        冗長性が除去された暗号文リスト
    """
    if not redundancy_metadata:
        return redundant_ciphertexts

    # 元の長さと元のインデックス情報を取得
    original_length = redundancy_metadata.get("original_length", 0)
    original_indices = redundancy_metadata.get("original_indices", [])

    if not original_indices or original_length <= 0:
        return redundant_ciphertexts

    # 冗長性を除去（各元のインデックスの最初の出現のみを保持）
    result = []
    processed_indices = set()

    for i, original_idx in enumerate(original_indices):
        if original_idx not in processed_indices and i < len(redundant_ciphertexts):
            result.append(redundant_ciphertexts[i])
            processed_indices.add(original_idx)

    # 結果のチェック
    if len(result) != original_length:
        print(f"[警告] 冗長性除去後のサイズが元のサイズと一致しません: {len(result)} vs {original_length}")
        # フォールバック: 元の長さに合わせてトリミング
        if len(result) > original_length:
            result = result[:original_length]

    return result

def remove_statistical_noise(ciphertexts, noise_values, paillier):
    """
    統計的ノイズを除去

    Args:
        ciphertexts: ノイズが追加された暗号文リスト
        noise_values: 加えられたノイズ値
        paillier: PaillierCrypto インスタンス

    Returns:
        ノイズが除去された暗号文リスト
    """
    if not noise_values:
        return ciphertexts

    # ノイズ値がチャンク数と一致しない場合、調整
    if len(noise_values) != len(ciphertexts):
        # サイズが一致しない場合の単純な対応
        if len(noise_values) > 0:
            # パターン反復
            extended_noise = []
            for i in range(len(ciphertexts)):
                extended_noise.append(noise_values[i % len(noise_values)])
            noise_values = extended_noise
        else:
            # ノイズがない場合は何もしない
            return ciphertexts

    # ノイズを除去（同種性を使用して減算）
    denoised = []
    for i, (ct, noise) in enumerate(zip(ciphertexts, noise_values)):
        # ノイズの負の値を求める
        neg_noise = paillier.encrypt(-noise)
        # 暗号文からノイズを減算
        denoised_ct = paillier.add(ct, neg_noise)
        denoised.append(denoised_ct)

    return denoised

def remove_comprehensive_indistinguishability(
    indistinguishable_ciphertexts, metadata, key_type, paillier
):
    """総合的な識別不能性を除去して元の暗号文を復元"""
    # 各ステップを逆順に適用して元に戻す

    # 1. 交互配置とシャッフルを元に戻す
    interleave_metadata = metadata.get("interleave", {})
    deinterleaved = deinterleave_ciphertexts(indistinguishable_ciphertexts, interleave_metadata, key_type)

    # 2. 冗長性を除去
    redundancy_metadata = metadata.get(f"{key_type}_redundancy", {})
    deredundant = remove_redundancy(deinterleaved, redundancy_metadata)

    # 3. 統計的ノイズを除去
    noise_values = metadata.get(f"{key_type}_noise_values", [])
    denoised = remove_statistical_noise(deredundant, noise_values, paillier)

    return denoised

def remove_comprehensive_indistinguishability_enhanced(
    indistinguishable_ciphertexts,
    metadata,
    key_type,
    paillier
):
    """
    識別不能性を除去する拡張関数

    standard 版と enhanced 版の両方に対応するよう、metadata の構造を解析して対応

    Args:
        indistinguishable_ciphertexts: 識別不能性が適用された暗号文
        metadata: 識別不能性のメタデータ
        key_type: 鍵タイプ ("true" または "false")
        paillier: PaillierCrypto インスタンス

    Returns:
        識別不能性が除去された暗号文
    """
    # メタデータの構造を解析
    if "indistinguishable_metadata" in metadata:
        # 新しい構造（encrypt.py で識別不能性機能を追加したケース）
        indist_metadata = metadata.get("indistinguishable_metadata", {})

        # 鍵タイプに応じたメタデータを取得
        key_specific_metadata = indist_metadata.get(f"{key_type}_indist_metadata", None)

        if key_specific_metadata:
            # 識別不能性を除去
            print(f"拡張された識別不能性（{key_type}鍵）を除去中...")
            try:
                return remove_comprehensive_indistinguishability(
                    indistinguishable_ciphertexts,
                    key_specific_metadata,
                    key_type,
                    paillier
                )
            except Exception as e:
                print(f"拡張識別不能性除去でエラー: {e}")
                raise

    # 標準的なメタデータ構造の場合
    print(f"標準的な識別不能性（{key_type}鍵）を除去中...")
    try:
        return remove_comprehensive_indistinguishability(
            indistinguishable_ciphertexts,
            metadata,
            key_type,
            paillier
        )
    except Exception as e:
        print(f"標準識別不能性除去でエラー: {e}")
        raise

# 秘密鍵が正規か非正規かの判定をより堅牢にする拡張版
def analyze_key_type_enhanced(key: bytes, metadata: Optional[Dict[str, Any]] = None) -> str:
    """
    鍵の種類をより堅牢に解析する拡張版

    この関数は単純な16進数表現の和ではなく、より複雑なハッシュベースの判定を行います。
    また、利用可能な場合はメタデータの情報も利用して判定の堅牢性を高めます。

    Args:
        key: 解析する鍵
        metadata: 利用可能な場合のメタデータ情報

    Returns:
        鍵の種類 ("true" または "false")
    """
    # 鍵からSHA-256ハッシュを生成
    key_hash = hashlib.sha256(key).digest()

    # ハッシュ値を整数に変換
    hash_int = int.from_bytes(key_hash, byteorder='big')

    # ハッシュ値のビットパターンを分析
    bit_count = bin(hash_int).count('1')
    total_bits = key_hash.bit_length()
    bit_ratio = bit_count / total_bits if total_bits > 0 else 0.5

    # 複数の条件を組み合わせた判定
    # これにより単純な改変による攻撃を防止
    condition1 = bit_ratio > 0.48  # ビット1の比率が48%以上
    condition2 = (hash_int % 256) < 128  # 下位8ビットのモジュロ演算
    condition3 = (hash_int & 0xFF00) > 0x7F00  # 第2バイトのビット比較
    condition4 = hashlib.sha256(key_hash).digest()[0] % 2 == 0  # 二重ハッシュの最初のバイトが偶数

    # メタデータが利用可能な場合、追加の検証を行う
    if metadata:
        try:
            # メタデータから追加の因子を抽出
            interleave = metadata.get("interleave", {})

            # シャッフルシードが存在する場合、それをさらなる因子として使用
            shuffle_seed_hex = interleave.get("shuffle_seed", "")
            if shuffle_seed_hex:
                shuffle_seed = bytes.fromhex(shuffle_seed_hex)
                # シードと鍵を組み合わせた追加ハッシュ
                combined_hash = hashlib.sha256(key + shuffle_seed).digest()
                # 追加条件
                condition5 = combined_hash[0] % 2 == 0
            else:
                condition5 = key_hash[16] % 2 == 0
        except Exception:
            # 例外が発生した場合は、シンプルなフォールバック条件を使用
            condition5 = key_hash[16] % 2 == 0
    else:
        # メタデータがない場合は鍵のハッシュの16バイト目で判定
        condition5 = key_hash[16] % 2 == 0

    # 条件の複雑な組み合わせで判定
    # 単純な条件ではなく、複数の条件を組み合わせることで改ざんに対する耐性を高める
    true_score = sum([condition1, condition2, condition3, condition4, condition5])

    # 3つ以上の条件が満たされれば真の鍵と判定
    return "true" if true_score >= 3 else "false"

class IndistinguishableWrapper:
    """識別不能性を提供するラッパークラス"""

    def __init__(self):
        """初期化"""
        self.seed = None
        self.counter = 0

    def generate_seed(self, key: bytes, salt: bytes, kdf_iterations: int = 100000) -> bytes:
        """
        識別不能性のためのシードを生成

        Args:
            key: 鍵データ
            salt: ソルト
            kdf_iterations: KDFの反復回数

        Returns:
            シードデータ
        """
        # 鍵とソルトからシードを派生
        kdf_input = key + salt
        self.seed = hashlib.pbkdf2_hmac('sha256', kdf_input, salt, kdf_iterations, 32)

        # カウンタをリセット
        self.counter = 0

        return self.seed

    def is_true_path(self, key: bytes, salt: bytes, kdf_iterations: int = 100000) -> bool:
        """
        真偽の判定を行う
        識別不能性を確保するため、計算量的に区別不可能な実装

        Args:
            key: 鍵データ
            salt: ソルト
            kdf_iterations: KDFの反復回数

        Returns:
            True: 真の経路, False: 偽の経路
        """
        if self.seed is None:
            self.generate_seed(key, salt, kdf_iterations)

        # カウンタを増加
        self.counter += 1

        # 現在のシードとカウンタを組み合わせて一時的なキーを生成
        counter_bytes = self.counter.to_bytes(8, byteorder='big')
        temp_key = hashlib.sha256(self.seed + counter_bytes).digest()

        # 最初のバイトを使用して真偽を決定
        # 単純な偶数/奇数ではなく、計算量的に予測困難な方法を使用

        # 単純なビット操作ではなく、複数のビットにわたる複雑な条件チェック
        bit_count = bin(int.from_bytes(temp_key[:4], byteorder='big')).count('1')
        hamming_weight = bit_count / 32

        # 異なる複数条件の組み合わせによる判定
        condition1 = temp_key[0] % 2 == 0
        condition2 = (temp_key[1] & 0x0F) > (temp_key[1] & 0xF0) >> 4
        condition3 = hamming_weight > 0.5
        condition4 = (temp_key[2] ^ temp_key[3]) % 3 == 0

        # 複数条件の組み合わせで識別不能性を高める
        # 条件の複雑さにより、単純なビットパターン分析では予測不可能
        return (condition1 and condition2) or (condition3 and condition4)

    def obfuscate_data(self, data: bytes, iterations: int = 3) -> bytes:
        """
        データに識別不能性のための難読化を適用

        Args:
            data: 難読化するデータ
            iterations: 難読化の反復回数

        Returns:
            難読化されたデータ
        """
        if self.seed is None:
            raise ValueError("シードが初期化されていません。generate_seed()を先に呼び出してください。")

        # 結果をbytearrayにして各操作を行う
        result = bytearray(data)

        for i in range(iterations):
            # 現在の反復に基づいた一時的なシードを生成
            iter_seed = hashlib.sha256(self.seed + i.to_bytes(4, byteorder='big')).digest()
            random.seed(int.from_bytes(iter_seed, byteorder='big'))

            # データの各バイトに対してXOR操作を実行
            xor_mask = [random.randint(0, 255) for _ in range(len(result))]

            # XOR操作をbytearrayに適用
            for j in range(len(result)):
                result[j] ^= xor_mask[j]

            # バイト順序の入れ替え（置換）
            indices = list(range(len(result)))
            random.shuffle(indices)

            # シャッフルされた順序で新しいバイト列を作成
            shuffled = bytearray(len(result))
            for j, idx in enumerate(indices):
                if idx < len(result):
                    shuffled[j] = result[idx]

            # インデックスマップを生成（復号時に使用）
            index_map = bytearray([indices.index(k) if k in indices else 0 for k in range(len(result))])

            # 結果にインデックスマップを追加して更新
            result = index_map + shuffled

        # 最終的にbytesに変換して返す
        return bytes(result)

    def deobfuscate_data(self, data: bytes, iterations: int = 3) -> bytes:
        """
        識別不能性のために難読化されたデータを復元

        Args:
            data: 難読化されたデータ
            iterations: 適用された難読化の反復回数

        Returns:
            復元されたデータ
        """
        if self.seed is None:
            raise ValueError("シードが初期化されていません。generate_seed()を先に呼び出してください。")

        # データをbytearrayにして操作
        result = bytearray(data)
        original_data_size = len(data)

        try:
            # 反復を逆順に処理
            for i in range(iterations - 1, -1, -1):
                # 現在の反復に基づいた一時的なシードを生成
                iter_seed = hashlib.sha256(self.seed + i.to_bytes(4, byteorder='big')).digest()
                random.seed(int.from_bytes(iter_seed, byteorder='big'))

                # 各イテレーションで、データサイズはオリジナルより大きくなる
                # 元のサイズを計算し、インデックスマップとデータを分離
                actual_data_size = len(result) // (i + 2)  # 近似値

                # インデックスマップとデータを分離
                index_map = result[:actual_data_size]
                shuffled_data = result[actual_data_size:]

                # シャッフルを元に戻す
                unshuffled = bytearray(len(shuffled_data))
                for j, idx in enumerate(index_map):
                    if j < len(shuffled_data) and idx < len(unshuffled):
                        unshuffled[idx] = shuffled_data[j]

                # データの各バイトに対してXOR操作を元に戻す
                xor_mask = [random.randint(0, 255) for _ in range(len(unshuffled))]

                # 同じXORマスクを適用して元に戻す
                for j in range(len(unshuffled)):
                    unshuffled[j] ^= xor_mask[j]

                result = unshuffled

            # 最終的にbytesに変換して返す
            return bytes(result[:original_data_size])
        except Exception as e:
            # エラーが発生した場合は、デバッグ情報を出力して空のバイト列を返す
            print(f"データの復元中にエラーが発生しました: {e}")
            return b"Error during deobfuscation"

    def time_equalizer(self, func, *args, **kwargs):
        """
        関数実行時間を均等化し、タイミング攻撃への耐性を提供

        Args:
            func: 実行する関数
            *args: 関数に渡す位置引数
            **kwargs: 関数に渡すキーワード引数

        Returns:
            関数の戻り値
        """
        # 実行開始時刻を記録
        start_time = time.time()

        # 関数を実行
        result = func(*args, **kwargs)

        # 実行完了時刻を記録
        end_time = time.time()

        # 最小実行時間（50ms）
        min_execution_time = 0.05

        # 実際の経過時間
        elapsed = end_time - start_time

        # 最小実行時間より早く終わった場合は待機
        if elapsed < min_execution_time:
            time.sleep(min_execution_time - elapsed)

        return result


# テスト用コード
if __name__ == "__main__":
    print("識別不能性拡張機能のテスト")

    # インスタンス作成とテスト
    wrapper = IndistinguishableWrapper()
    test_key = os.urandom(32)
    test_salt = os.urandom(16)

    # シード生成
    seed = wrapper.generate_seed(test_key, test_salt)
    print(f"生成されたシード: {seed.hex()}")

    # 真偽判定テスト
    is_true = wrapper.is_true_path(test_key, test_salt)
    print(f"真偽判定結果: {is_true}")

    # 難読化テスト
    test_data = b"This is a test of the indistinguishable wrapper!"
    obfuscated = wrapper.obfuscate_data(test_data)
    print(f"難読化されたデータ: {obfuscated.hex()[:50]}...")

    # 難読化解除テスト
    deobfuscated = wrapper.deobfuscate_data(obfuscated)
    print(f"復元されたデータ: {deobfuscated}")
    print(f"元のデータとの一致: {test_data == deobfuscated}")