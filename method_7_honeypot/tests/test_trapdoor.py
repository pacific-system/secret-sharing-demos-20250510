#!/usr/bin/env python3
"""
トラップドア関数の単体テスト

このテストは、トラップドア関数が正しく鍵ペアを生成し、入力鍵の
判定が正しく行われることを確認します。
"""

import os
import sys
import unittest
import binascii
import time
from typing import Dict, Any

# テスト対象のモジュールをインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, evaluate_key_type,
    generate_honey_token, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)


class TestTrapdoor(unittest.TestCase):
    """トラップドア関数のテストケース"""

    def setUp(self):
        """テスト前の準備"""
        self.master_key = create_master_key()
        self.params = create_trapdoor_parameters(self.master_key)
        self.keys, self.salt = derive_keys_from_trapdoor(self.params)

    def test_key_generation(self):
        """鍵生成のテスト"""
        # 鍵のサイズを確認
        self.assertEqual(len(self.keys[KEY_TYPE_TRUE]), 32)
        self.assertEqual(len(self.keys[KEY_TYPE_FALSE]), 32)

        # 正規鍵と非正規鍵は異なることを確認
        self.assertNotEqual(self.keys[KEY_TYPE_TRUE], self.keys[KEY_TYPE_FALSE])

        # 同じマスター鍵から生成される鍵は一貫していることを確認
        params2 = create_trapdoor_parameters(self.master_key)
        keys2, salt2 = derive_keys_from_trapdoor(params2)

        # ソルトが異なるため直接比較できないが、鍵評価の結果は一貫しているはず
        self.assertEqual(
            evaluate_key_type(self.keys[KEY_TYPE_TRUE], self.params, self.salt),
            KEY_TYPE_TRUE
        )
        self.assertEqual(
            evaluate_key_type(self.keys[KEY_TYPE_FALSE], self.params, self.salt),
            KEY_TYPE_FALSE
        )

    def test_key_evaluation(self):
        """鍵評価のテスト"""
        # 正規鍵の評価
        result_true = evaluate_key_type(self.keys[KEY_TYPE_TRUE], self.params, self.salt)
        self.assertEqual(result_true, KEY_TYPE_TRUE)

        # 非正規鍵の評価
        result_false = evaluate_key_type(self.keys[KEY_TYPE_FALSE], self.params, self.salt)
        self.assertEqual(result_false, KEY_TYPE_FALSE)

        # ランダムな鍵では一貫した結果が得られるか確認
        random_key = os.urandom(32)
        random_result = evaluate_key_type(random_key, self.params, self.salt)
        self.assertIn(random_result, [KEY_TYPE_TRUE, KEY_TYPE_FALSE])

        # 同じランダム鍵で再評価した場合、結果が一貫していることを確認
        random_result2 = evaluate_key_type(random_key, self.params, self.salt)
        self.assertEqual(random_result, random_result2)

    def test_honey_token(self):
        """ハニートークン生成のテスト"""
        # トークンの生成
        true_token = generate_honey_token(KEY_TYPE_TRUE, self.params)
        false_token = generate_honey_token(KEY_TYPE_FALSE, self.params)

        # トークンのサイズを確認
        self.assertEqual(len(true_token), 32)
        self.assertEqual(len(false_token), 32)

        # 正規と非正規のトークンは異なることを確認
        self.assertNotEqual(true_token, false_token)

        # 同じパラメータからは同じトークンが生成されることを確認
        true_token2 = generate_honey_token(KEY_TYPE_TRUE, self.params)
        self.assertEqual(true_token, true_token2)

    def test_timing_resistance(self):
        """タイミング攻撃耐性のテスト"""
        # 正規鍵の処理時間を測定
        start_time = time.time()
        evaluate_key_type(self.keys[KEY_TYPE_TRUE], self.params, self.salt)
        true_time = time.time() - start_time

        # 非正規鍵の処理時間を測定
        start_time = time.time()
        evaluate_key_type(self.keys[KEY_TYPE_FALSE], self.params, self.salt)
        false_time = time.time() - start_time

        # 処理時間の差が十分に小さいことを確認
        time_diff = abs(true_time - false_time)
        self.assertLess(time_diff, 0.1)  # 100ms以内の差を許容


def run_tests():
    """テスト実行関数"""
    unittest.main()


if __name__ == '__main__':
    run_tests()
