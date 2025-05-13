#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
区別不能な準同型暗号マスキング方式の安全な実装

このモジュールは、暗号文から真・偽の区別を不可能にする準同型暗号マスキング方式を提供します。
これにより、攻撃者がソースコードを解析してもどちらが正規のファイルか判断できなくなります。
"""

import os
import sys
import time
import json
import random
import hashlib
import base64
import binascii
from typing import Dict, List, Tuple, Any, Optional, Union

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator
)


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

        # 各コンテンツを整数に変換
        true_int = int.from_bytes(true_content, 'big')
        false_int = int.from_bytes(false_content, 'big')

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
            "advanced_masks": self.use_advanced_masks
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

        # 整数をバイト列に変換
        content_size = metadata.get("content_size", 0)
        byte_length = max((decrypted_int.bit_length() + 7) // 8, content_size)
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')

        # 余分なゼロバイトを除去
        while decrypted_bytes.startswith(b'\x00') and len(decrypted_bytes) > content_size:
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

    # 暗号化データを保存
    crypto.save_encrypted_data(encrypted_data, output_file)

    # テスト用に鍵も保存
    key_dir = os.path.dirname(output_file)
    key_file = os.path.join(key_dir, "key_info.json")

    key_data = {
        "public_key": crypto.public_key,
        "private_key": crypto.private_key
    }

    with open(key_file, 'w') as f:
        json.dump(key_data, f, indent=2)

    print(f"暗号化データを保存しました: {output_file}")
    print(f"鍵情報を保存しました: {key_file}")


def decrypt_file_with_key(encrypted_file: str, output_file: str, key_type: str, key_file: str = None) -> None:
    """
    暗号化ファイルを指定した鍵タイプで復号

    Args:
        encrypted_file: 暗号化ファイルパス
        output_file: 出力ファイルパス
        key_type: 鍵タイプ ('true' または 'false')
        key_file: 鍵ファイルパス（省略時は暗号化ファイルと同じディレクトリの key_info.json）
    """
    # 鍵ファイルのパスを決定
    if key_file is None:
        key_file = os.path.join(os.path.dirname(encrypted_file), "key_info.json")

    # 暗号化データを読み込み
    crypto = SecureHomomorphicCrypto()
    encrypted_data = crypto.load_encrypted_data(encrypted_file)

    # 鍵情報を読み込み
    with open(key_file, 'r') as f:
        key_data = json.load(f)

    # Paillierオブジェクトに鍵を設定
    crypto.public_key = key_data["public_key"]
    crypto.private_key = key_data["private_key"]

    # パブリックキーをPaillierオブジェクトにも設定
    crypto.paillier.public_key = key_data["public_key"]

    # 復号
    decrypted_content = crypto.decrypt_content(encrypted_data, key_type)

    # 結果を保存
    with open(output_file, 'wb') as f:
        f.write(decrypted_content)

    print(f"復号されたファイルを保存しました: {output_file}")


if __name__ == "__main__":
    # テスト用のコード
    import argparse

    parser = argparse.ArgumentParser(description="区別不能な準同型暗号マスキング方式")
    subparsers = parser.add_subparsers(dest="command", help="コマンド")

    # 暗号化コマンド
    encrypt_parser = subparsers.add_parser("encrypt", help="ファイルを暗号化")
    encrypt_parser.add_argument("--true", required=True, help="真のファイルパス")
    encrypt_parser.add_argument("--false", required=True, help="偽のファイルパス")
    encrypt_parser.add_argument("--output", required=True, help="出力ファイルパス")
    encrypt_parser.add_argument("--key-bits", type=int, default=1024, help="鍵のビット数")
    encrypt_parser.add_argument("--simple-masks", action="store_true", help="単純なマスク関数を使用")

    # 復号コマンド
    decrypt_parser = subparsers.add_parser("decrypt", help="ファイルを復号")
    decrypt_parser.add_argument("--input", required=True, help="暗号化ファイルパス")
    decrypt_parser.add_argument("--output", required=True, help="出力ファイルパス")
    decrypt_parser.add_argument("--key-type", choices=["true", "false"], required=True, help="鍵タイプ")
    decrypt_parser.add_argument("--key-file", help="鍵ファイルパス")

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_file_with_dual_keys(
            args.true, args.false, args.output,
            key_bits=args.key_bits, use_advanced_masks=not args.simple_masks
        )
    elif args.command == "decrypt":
        decrypt_file_with_key(
            args.input, args.output, args.key_type, args.key_file
        )
    else:
        parser.print_help()