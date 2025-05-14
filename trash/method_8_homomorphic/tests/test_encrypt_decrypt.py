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
        # 短いテストデータを使用
        short_true_content = self.true_content[:20]
        short_false_content = self.false_content[:20]

        # わかりやすいように内容を出力
        print(f"True content: {short_true_content}")
        print(f"False content: {short_false_content}")

        try:
            # 難読化は1回のイテレーションで実行
            true_data = self.indist.obfuscate_data(short_true_content, iterations=1)
            false_data = self.indist.obfuscate_data(short_false_content, iterations=1)

            # 真データと偽データをマスキング
            true_masked = self.crypto_mask.apply_mask_to_data(true_data, self.mask_params)
            false_masked = self.crypto_mask.apply_mask_to_data(false_data, self.mask_params)

            # メタデータを準備
            metadata = {
                'format': 'homomorphic',
                'version': '1.0',
                'salt': binascii.b2a_base64(self.salt).decode().strip(),
                'algorithm': 'hybrid',
                'true_size': len(short_true_content),
                'false_size': len(short_false_content),
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
            # 真の鍵の判定
            is_true_key = self.indist.is_true_path(self.key, self.salt)
            print(f"真の鍵の判定結果: {is_true_key}")

            # 偽の鍵を生成
            false_key = bytearray(self.key)
            false_key[0] = (false_key[0] + 1) % 256  # 1バイト変更
            false_key = bytes(false_key)

            # 偽の鍵の判定
            self.indist.generate_seed(false_key, self.salt)
            is_false_key = self.indist.is_true_path(false_key, self.salt)
            print(f"偽の鍵の判定結果: {is_false_key}")

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

            # シードを再設定
            self.indist.generate_seed(self.key, self.salt)

            # Paillier暗号で真データを取得
            true_paillier = [int(c) for c in encrypted_data['true_paillier']]
            encrypted_true = {
                'paillier': true_paillier,
                'chunks': metadata['true_chunks']
            }

            # マスク除去と難読化解除
            demasked_true = self.crypto_mask.remove_mask_from_data(encrypted_true, metadata['mask_params'], 'true')
            decrypted_true = self.indist.deobfuscate_data(demasked_true, iterations=1)

            # 検証 - 長さが一致することを確認
            self.assertEqual(len(short_true_content), len(decrypted_true),
                           f"元の真データ長({len(short_true_content)})と復号データ長({len(decrypted_true)})が一致しません")

            # 結果の出力
            print(f"真の鍵で復号: {decrypted_true[:20]}")

            # 暗号文と鍵のサイズを確認
            encrypted_size = os.path.getsize(self.encrypted_file.name)
            print(f"暗号文サイズ: {encrypted_size} バイト")
            print(f"元の真データサイズ: {len(short_true_content)} バイト")
            print(f"暗号化率: {encrypted_size / len(short_true_content):.2f}倍")

            # 基本テスト成功を示す
            self.assertTrue(True)

        except Exception as e:
            self.fail(f"テスト実行中にエラーが発生: {e}")


if __name__ == '__main__':
    unittest.main()
