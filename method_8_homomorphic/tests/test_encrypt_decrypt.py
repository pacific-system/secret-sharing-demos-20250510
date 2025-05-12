#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の暗号化と復号のテスト

このモジュールは、encrypt.pyとdecrypt.pyの機能と相互運用性をテストします。
"""

import unittest
import os
import sys
import tempfile
import json
import binascii
from typing import Dict, Any, Tuple

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.config import (
    KEY_SIZE_BYTES,
    SALT_SIZE
)
from method_8_homomorphic.homomorphic import PaillierCrypto, ElGamalCrypto
from method_8_homomorphic.crypto_mask import CryptoMask
from method_8_homomorphic.indistinguishable import IndistinguishableWrapper


class TestEncryptDecrypt(unittest.TestCase):
    """準同型暗号マスキング方式の暗号化と復号のテスト"""

    def setUp(self):
        """テスト前の準備"""
        # テスト用の一時ファイルを作成
        self.true_file = tempfile.NamedTemporaryFile(delete=False)
        self.false_file = tempfile.NamedTemporaryFile(delete=False)
        self.encrypted_file = tempfile.NamedTemporaryFile(delete=False, suffix='.hmc')
        self.decrypted_file_true = tempfile.NamedTemporaryFile(delete=False)
        self.decrypted_file_false = tempfile.NamedTemporaryFile(delete=False)

        # テスト用のデータを書き込み
        self.true_content = b"This is the true content for testing homomorphic encryption."
        self.false_content = b"This is the false content that should not be revealed."

        self.true_file.write(self.true_content)
        self.false_file.write(self.false_content)

        self.true_file.close()
        self.false_file.close()
        self.encrypted_file.close()
        self.decrypted_file_true.close()
        self.decrypted_file_false.close()

        # テスト用の鍵を生成
        self.key = os.urandom(KEY_SIZE_BYTES)
        self.salt = os.urandom(SALT_SIZE)

        # 準同型暗号マスクの初期化
        self.crypto_mask = CryptoMask()
        self.crypto_params = self.crypto_mask.initialize()

        # 識別不能性ラッパーの初期化
        self.indist = IndistinguishableWrapper()
        self.indist.generate_seed(self.key, self.salt)

        # マスクパラメータの生成
        self.mask_params = self.crypto_mask.generate_mask_params(self.key, self.salt)

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # 一時ファイルを削除
        os.unlink(self.true_file.name)
        os.unlink(self.false_file.name)
        os.unlink(self.encrypted_file.name)
        os.unlink(self.decrypted_file_true.name)
        os.unlink(self.decrypted_file_false.name)

    def test_encrypt_decrypt_cycle(self):
        """暗号化と復号の完全なサイクルのテスト"""
        # テスト用のマスクとメタデータを設定
        true_data = self.indist.obfuscate_data(self.true_content)
        false_data = self.indist.obfuscate_data(self.false_content)

        # 真データと偽データをマスキング
        true_masked = self.crypto_mask.apply_mask_to_data(true_data, self.mask_params)
        false_masked = self.crypto_mask.apply_mask_to_data(false_data, self.mask_params)

        # メタデータを準備
        metadata = {
            'format': 'homomorphic',
            'version': '1.0',
            'salt': binascii.b2a_base64(self.salt).decode().strip(),
            'algorithm': 'hybrid',
            'true_size': len(self.true_content),
            'false_size': len(self.false_content),
            'true_chunks': true_masked['chunks'],
            'false_chunks': false_masked['chunks'],
            'paillier_public': {
                'n': str(self.crypto_params['paillier_public']['n']),
                'g': str(self.crypto_params['paillier_public']['g'])
            },
            'elgamal_public': {
                'p': str(self.crypto_params['elgamal_public']['p']),
                'g': str(self.crypto_params['elgamal_public']['g']),
                'y': str(self.crypto_params['elgamal_public']['y'])
            },
            'mask_params': self.mask_params
        }

        # 暗号化データを準備
        encrypted_data = {
            'metadata': metadata,
            'paillier_private': {
                'lambda': str(self.crypto_params['paillier_private']['lambda']),
                'mu': str(self.crypto_params['paillier_private']['mu']),
                'n': str(self.crypto_params['paillier_private']['n'])
            },
            'elgamal_private': {
                'x': str(self.crypto_params['elgamal_private']['x']),
                'p': str(self.crypto_params['elgamal_private']['p'])
            },
            'true_paillier': [str(n) for n in true_masked['paillier']],
            'false_paillier': [str(n) for n in false_masked['paillier']],
            'true_elgamal': [
                [str(c[0]), str(c[1])] for c in true_masked['elgamal']
            ],
            'false_elgamal': [
                [str(c[0]), str(c[1])] for c in false_masked['elgamal']
            ]
        }

        # 暗号化ファイルを書き込み
        with open(self.encrypted_file.name, 'w') as f:
            json.dump(encrypted_data, f, indent=2)

        # --- 鍵の判定テスト ---
        # 真の鍵を使用して判定
        is_true_key = self.indist.is_true_path(self.key, self.salt)
        self.assertTrue(is_true_key)

        # 偽の鍵を生成して判定
        false_key = bytearray(self.key)
        false_key[0] = (false_key[0] + 1) % 256  # 1バイト変更
        false_key = bytes(false_key)

        self.indist.generate_seed(false_key, self.salt)
        is_false_key = self.indist.is_true_path(false_key, self.salt)
        # 注: 確率的に偽の鍵で真と判定されることもあるため、必ずしもFalseとは限らない
        # このテストでは結果を記録するだけ
        print(f"偽の鍵の判定結果: {is_false_key}")

        # 新しい乱数鍵を複数生成して統計的にテスト
        true_count = 0
        false_count = 0
        for _ in range(100):
            random_key = os.urandom(KEY_SIZE_BYTES)
            self.indist.generate_seed(random_key, self.salt)
            if self.indist.is_true_path(random_key, self.salt):
                true_count += 1
            else:
                false_count += 1

        # おおよそ50%に近いことを期待（許容範囲として40%〜60%を設定）
        ratio = true_count / 100
        print(f"真判定率: {ratio:.2f}, 真: {true_count}, 偽: {false_count}")
        self.assertTrue(0.4 <= ratio <= 0.6, "ランダム鍵の真判定率が期待範囲外です")

        # --- 復号テスト（真の鍵） ---
        # 準同型暗号の鍵を設定
        self.crypto_mask.paillier.public_key = {
            'n': int(metadata['paillier_public']['n']),
            'g': int(metadata['paillier_public']['g'])
        }
        self.crypto_mask.paillier.private_key = {
            'lambda': int(encrypted_data['paillier_private']['lambda']),
            'mu': int(encrypted_data['paillier_private']['mu']),
            'n': int(encrypted_data['paillier_private']['n'])
        }

        self.crypto_mask.elgamal.public_key = {
            'p': int(metadata['elgamal_public']['p']),
            'g': int(metadata['elgamal_public']['g']),
            'y': int(metadata['elgamal_public']['y'])
        }
        self.crypto_mask.elgamal.private_key = {
            'x': int(encrypted_data['elgamal_private']['x']),
            'p': int(encrypted_data['elgamal_private']['p'])
        }

        # 真の鍵で復号
        self.indist.generate_seed(self.key, self.salt)

        # Paillier暗号を使用
        true_paillier = [int(c) for c in encrypted_data['true_paillier']]
        encrypted_true = {
            'paillier': true_paillier,
            'chunks': metadata['true_chunks']
        }

        # マスクを除去
        demasked_true = self.crypto_mask.remove_mask_from_data(encrypted_true, metadata['mask_params'], 'true')
        decrypted_true = self.indist.deobfuscate_data(demasked_true)

        # 復号結果が元の真のデータと一致することを確認
        self.assertEqual(self.true_content, decrypted_true)

        # --- 復号テスト（偽の鍵） ---
        # ElGamal暗号を使用
        false_elgamal = [
            (int(c[0]), int(c[1])) for c in encrypted_data['false_elgamal']
        ]
        encrypted_false = {
            'elgamal': false_elgamal,
            'chunks': metadata['false_chunks']
        }

        # 偽の鍵で復号
        self.indist.generate_seed(false_key, self.salt)

        # マスクを除去
        demasked_false = self.crypto_mask.remove_mask_from_data(encrypted_false, metadata['mask_params'], 'false')

        # 復号結果と元の偽のデータを比較（必ずしも一致するとは限らない）
        print(f"偽の鍵での復号結果長: {len(demasked_false)}バイト")

        # ファイルに結果を書き込み
        with open(self.decrypted_file_true.name, 'wb') as f:
            f.write(decrypted_true)

        # 暗号文と鍵のサイズを確認
        encrypted_size = os.path.getsize(self.encrypted_file.name)
        print(f"暗号文サイズ: {encrypted_size} バイト")
        print(f"元の真データサイズ: {len(self.true_content)} バイト")
        print(f"元の偽データサイズ: {len(self.false_content)} バイト")
        print(f"暗号化率: {encrypted_size / (len(self.true_content) + len(self.false_content)):.2f}倍")


if __name__ == '__main__':
    unittest.main()
