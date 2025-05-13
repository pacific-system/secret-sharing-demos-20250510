#!/usr/bin/env python3
"""
鍵検証機構の単体テスト

このテストは、鍵検証機構が正しく鍵の種類を判定し、適切な処理経路を
選択することを確認します。
"""

import os
import sys
import unittest
import binascii
import time
import tempfile
import shutil
from typing import Dict, Any

# テスト対象のモジュールをインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, generate_honey_token,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.key_verification import (
    KeyVerifier, HoneyTokenManager, DeceptionManager,
    verify_key_and_select_path
)


class TestKeyVerification(unittest.TestCase):
    """鍵検証機構のテストケース"""

    def setUp(self):
        """テスト前の準備"""
        # 一時ディレクトリを作成
        self.test_dir = tempfile.mkdtemp()

        # 鍵とパラメータの生成
        self.master_key = create_master_key()
        self.params = create_trapdoor_parameters(self.master_key)
        self.keys, self.salt = derive_keys_from_trapdoor(self.params)

        # トークンの生成
        self.true_token = generate_honey_token(KEY_TYPE_TRUE, self.params)
        self.false_token = generate_honey_token(KEY_TYPE_FALSE, self.params)

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # 一時ディレクトリを削除
        shutil.rmtree(self.test_dir)

    def test_key_verifier(self):
        """KeyVerifierクラスのテスト"""
        # 検証器の初期化
        verifier = KeyVerifier(self.params, self.salt)

        # 正規鍵の検証
        true_result = verifier.verify_key(self.keys[KEY_TYPE_TRUE])
        self.assertEqual(true_result, KEY_TYPE_TRUE)

        # 非正規鍵の検証
        false_result = verifier.verify_key(self.keys[KEY_TYPE_FALSE])
        self.assertEqual(false_result, KEY_TYPE_FALSE)

        # 複数回の検証で結果が一貫していることを確認
        for _ in range(5):
            self.assertEqual(
                verifier.verify_key(self.keys[KEY_TYPE_TRUE]),
                KEY_TYPE_TRUE
            )
            self.assertEqual(
                verifier.verify_key(self.keys[KEY_TYPE_FALSE]),
                KEY_TYPE_FALSE
            )

    def test_honey_token_manager(self):
        """HoneyTokenManagerクラスのテスト"""
        # トークン管理器の初期化
        token_manager = HoneyTokenManager(self.params)

        # トークン取得テスト
        true_token = token_manager.get_token(KEY_TYPE_TRUE)
        false_token = token_manager.get_token(KEY_TYPE_FALSE)

        # トークンのサイズ確認
        self.assertEqual(len(true_token), 32)
        self.assertEqual(len(false_token), 32)

        # トークン検証テスト
        valid_true, key_type_true = token_manager.verify_token(true_token, self.keys[KEY_TYPE_TRUE])
        valid_false, key_type_false = token_manager.verify_token(false_token, self.keys[KEY_TYPE_FALSE])

        # 検証結果の確認
        self.assertTrue(valid_true)
        self.assertEqual(key_type_true, KEY_TYPE_TRUE)
        self.assertTrue(valid_false)
        self.assertEqual(key_type_false, KEY_TYPE_FALSE)

    def test_deception_manager(self):
        """DeceptionManagerクラスのテスト"""
        # 偽装管理器の初期化
        deception = DeceptionManager(self.params)

        # 偽装トークン生成テスト
        deception_token = deception.generate_deception_token()
        self.assertEqual(len(deception_token), 32)

        # 偽装コンテキスト生成テスト
        context = deception.create_deception_context(self.keys[KEY_TYPE_FALSE])

        # コンテキストの検証
        self.assertIn('token', context)
        self.assertIn('salt', context)
        self.assertIn('key_material', context)
        self.assertIn('timestamp', context)
        self.assertIn('session_id', context)

    def test_verify_key_and_select_path(self):
        """完全な鍵検証ワークフローのテスト"""
        # 正規鍵での検証と経路選択
        true_key_type, true_context = verify_key_and_select_path(
            self.keys[KEY_TYPE_TRUE], self.params, self.salt
        )

        # 非正規鍵での検証と経路選択
        false_key_type, false_context = verify_key_and_select_path(
            self.keys[KEY_TYPE_FALSE], self.params, self.salt
        )

        # 検証結果の確認
        self.assertEqual(true_key_type, KEY_TYPE_TRUE)
        self.assertEqual(true_context['path'], 'authentic')

        self.assertEqual(false_key_type, KEY_TYPE_FALSE)
        self.assertEqual(false_context['path'], 'deception')

        # コンテキストの検証
        self.assertIn('token', true_context)
        self.assertIn('salt', true_context)
        self.assertIn('timestamp', true_context)

        self.assertIn('token', false_context)
        self.assertIn('salt', false_context)
        self.assertIn('key_material', false_context)
        self.assertIn('timestamp', false_context)
        self.assertIn('session_id', false_context)

    def test_timing_resistance(self):
        """タイミング攻撃耐性のテスト"""
        verifier = KeyVerifier(self.params, self.salt)

        # 正規鍵の処理時間を測定
        start_time = time.time()
        verifier.verify_key(self.keys[KEY_TYPE_TRUE])
        true_time = time.time() - start_time

        # 非正規鍵の処理時間を測定
        start_time = time.time()
        verifier.verify_key(self.keys[KEY_TYPE_FALSE])
        false_time = time.time() - start_time

        # 時間差を確認
        time_diff = abs(true_time - false_time)
        self.assertLess(time_diff, 0.1)  # 100ms以内の差を許容

        # 完全なワークフローのタイミングテスト
        start_time = time.time()
        verify_key_and_select_path(self.keys[KEY_TYPE_TRUE], self.params, self.salt)
        true_workflow_time = time.time() - start_time

        start_time = time.time()
        verify_key_and_select_path(self.keys[KEY_TYPE_FALSE], self.params, self.salt)
        false_workflow_time = time.time() - start_time

        # ワークフロー全体の時間差も小さいことを確認
        workflow_time_diff = abs(true_workflow_time - false_workflow_time)
        self.assertLess(workflow_time_diff, 0.2)  # 200ms以内の差を許容


def run_tests():
    """テスト実行関数"""
    unittest.main()


if __name__ == '__main__':
    run_tests()
