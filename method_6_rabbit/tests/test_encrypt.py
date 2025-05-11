#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ラビットストリーム暗号化のテスト
"""

import unittest
import os
import sys
import binascii

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# モジュールインポート
from ..rabbit_stream import RabbitStreamGenerator, derive_key
from ..config import RABBIT_KEY_SIZE, RABBIT_IV_SIZE


class TestRabbitStream(unittest.TestCase):
    """ラビットストリーム生成アルゴリズムのテスト"""

    def test_initialization(self):
        """初期化パラメータのテスト"""
        # 正しいサイズの鍵とIVで初期化
        key = os.urandom(RABBIT_KEY_SIZE)
        iv = os.urandom(RABBIT_IV_SIZE)

        generator = RabbitStreamGenerator(key, iv)
        self.assertIsNotNone(generator)

        # IVなしで初期化
        generator_no_iv = RabbitStreamGenerator(key)
        self.assertIsNotNone(generator_no_iv)

        # 不正なサイズの鍵でのエラーチェック
        with self.assertRaises(ValueError):
            RabbitStreamGenerator(os.urandom(8))  # 短すぎる鍵

        # 不正なサイズのIVでのエラーチェック
        with self.assertRaises(ValueError):
            RabbitStreamGenerator(key, os.urandom(4))  # 短すぎるIV

    def test_stream_generation(self):
        """ストリーム生成のテスト"""
        key = os.urandom(RABBIT_KEY_SIZE)
        iv = os.urandom(RABBIT_IV_SIZE)

        generator = RabbitStreamGenerator(key, iv)

        # 異なる長さのストリーム生成
        stream_16 = generator.generate(16)
        self.assertEqual(len(stream_16), 16)

        # 新しいジェネレータを作成（同じ鍵とIV）
        generator2 = RabbitStreamGenerator(key, iv)
        stream_16_repeat = generator2.generate(16)

        # 同じ鍵とIVで生成したストリームは同一であるべき
        self.assertEqual(stream_16, stream_16_repeat)

        # 異なる長さのストリーム
        generator3 = RabbitStreamGenerator(key, iv)
        stream_32 = generator3.generate(32)
        self.assertEqual(len(stream_32), 32)

        # 長いストリームの前半部分は短いストリームと一致するべき
        self.assertEqual(stream_16, stream_32[:16])

    def test_key_derivation(self):
        """鍵導出関数のテスト"""
        password = "TestPassword123!"

        # ソルトなしでの鍵導出
        key1, iv1, salt1 = derive_key(password)
        self.assertEqual(len(key1), RABBIT_KEY_SIZE)
        self.assertEqual(len(iv1), RABBIT_IV_SIZE)
        self.assertIsNotNone(salt1)

        # 同じソルトを使用した場合、同じ鍵とIVが生成されるべき
        key2, iv2, salt2 = derive_key(password, salt1)
        self.assertEqual(key1, key2)
        self.assertEqual(iv1, iv2)

        # 異なるパスワードでは異なる鍵が生成されるべき
        key3, iv3, salt3 = derive_key("DifferentPassword")
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(iv1, iv3)


# テスト実行
if __name__ == "__main__":
    unittest.main()
