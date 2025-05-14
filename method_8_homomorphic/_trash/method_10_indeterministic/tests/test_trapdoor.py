#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - トラップドア機能のテスト

ハニーポット戦略やリバーストラップ機能の動作を検証します。
"""

import os
import sys
import json
import unittest
import tempfile
import binascii
from typing import Tuple, Dict, Any

# テスト用にモジュールパスを追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.encrypt import encrypt_files, generate_master_key
from method_10_indeterministic.decrypt import decrypt_file, determine_path_type
from method_10_indeterministic.trapdoor import (
    TrapdoorStrategy, create_honeypot_strategy, create_reverse_trap_strategy
)
from method_10_indeterministic.config import (
    TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
    OUTPUT_FORMAT, OUTPUT_EXTENSION
)

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = "test_output"

class TestTrapdoor(unittest.TestCase):
    """トラップドア機能のテスト"""

    @classmethod
    def setUpClass(cls):
        """テスト前の準備"""
        # テスト出力ディレクトリの作成
        os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

        # テスト用ファイルの存在確認
        assert os.path.exists(TRUE_TEXT_PATH), f"真のテキストファイル {TRUE_TEXT_PATH} が見つかりません"
        assert os.path.exists(FALSE_TEXT_PATH), f"偽のテキストファイル {FALSE_TEXT_PATH} が見つかりません"

        # テストファイルの内容を読み込み
        with open(TRUE_TEXT_PATH, 'rb') as f:
            cls.true_content = f.read()

        with open(FALSE_TEXT_PATH, 'rb') as f:
            cls.false_content = f.read()

    def setUp(self):
        """各テスト前の準備"""
        # テスト用のファイル名を生成
        self.output_file = os.path.join(TEST_OUTPUT_DIR, f"test_trapdoor_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")
        self.honeypot_file = os.path.join(TEST_OUTPUT_DIR, f"test_honeypot_{os.urandom(4).hex()}.hpot")
        self.reverse_trap_file = os.path.join(TEST_OUTPUT_DIR, f"test_reverse_{os.urandom(4).hex()}.rtrap")

    def test_basic_trapdoor_functionality(self):
        """基本的なトラップドア機能をテスト"""
        # トラップドア戦略を作成
        strategy = TrapdoorStrategy()
        true_key, false_key = strategy.generate_key_pair()

        # 鍵情報を確認
        self.assertEqual(len(true_key), KEY_SIZE_BYTES, f"真の鍵のサイズが {KEY_SIZE_BYTES} バイトではありません")
        self.assertEqual(len(false_key), KEY_SIZE_BYTES, f"偽の鍵のサイズが {KEY_SIZE_BYTES} バイトではありません")
        self.assertNotEqual(true_key, false_key, "真と偽の鍵が同一です")

        # 鍵検証機能をテスト
        verification = strategy.verify_key(true_key)
        self.assertTrue(verification["is_true_key"], "真の鍵が正しく検証されません")
        self.assertFalse(verification["is_false_key"], "真の鍵が偽として誤検出されています")
        self.assertFalse(verification["is_honeypot_key"], "真の鍵がハニーポットとして誤検出されています")

        verification = strategy.verify_key(false_key)
        self.assertFalse(verification["is_true_key"], "偽の鍵が真として誤検出されています")
        self.assertTrue(verification["is_false_key"], "偽の鍵が正しく検証されません")
        self.assertFalse(verification["is_honeypot_key"], "偽の鍵がハニーポットとして誤検出されています")

        # ランダムな鍵の検証
        random_key = generate_master_key()
        verification = strategy.verify_key(random_key)
        self.assertTrue(verification["is_unknown_key"], "未知の鍵が既知として誤検出されています")

        # 戦略情報の辞書変換とシリアライズをテスト
        strategy_dict = strategy.to_dict()
        self.assertIn("true_key", strategy_dict, "戦略情報に真の鍵が含まれていません")
        self.assertIn("false_key", strategy_dict, "戦略情報に偽の鍵が含まれていません")
        self.assertIn("trap_signature", strategy_dict, "戦略情報にトラップシグネチャが含まれていません")

        # JSONシリアライズが可能なことを確認
        try:
            json_str = json.dumps(strategy_dict)
            # ファイルに保存
            with open(self.output_file, 'w') as f:
                f.write(json_str)
            # 再度読み込み
            with open(self.output_file, 'r') as f:
                loaded_dict = json.load(f)
            # 復元
            restored_strategy = TrapdoorStrategy.from_dict(loaded_dict)
            # 鍵を確認
            verification = restored_strategy.verify_key(true_key)
            self.assertTrue(verification["is_true_key"], "シリアライズ後の戦略で真の鍵が検証できません")
        except Exception as e:
            self.fail(f"戦略のシリアライズに失敗しました: {e}")

    def test_honeypot_strategy(self):
        """ハニーポット戦略をテスト"""
        # ハニーポット戦略を作成
        strategy = create_honeypot_strategy(decoy_factor=0.8)

        # 生成された鍵を取得
        true_key = strategy.true_key
        false_key = strategy.false_key
        honeypot_key = strategy.honeypot_key

        # メタデータを確認
        self.assertEqual(strategy.metadata["strategy"], "honeypot", "戦略タイプがハニーポットになっていません")
        self.assertEqual(strategy.metadata["decoy_factor"], 0.8, "decoy_factorが正しく設定されていません")

        # 各鍵の検証
        verification = strategy.verify_key(true_key)
        self.assertTrue(verification["is_true_key"], "真の鍵が正しく検証されません")

        verification = strategy.verify_key(false_key)
        self.assertTrue(verification["is_false_key"], "偽の鍵が正しく検証されません")

        verification = strategy.verify_key(honeypot_key)
        self.assertTrue(verification["is_honeypot_key"], "ハニーポット鍵が正しく検証されません")

        # ハニーポット戦略情報をシリアライズ
        strategy_dict = strategy.to_dict()
        with open(self.honeypot_file, 'w') as f:
            json.dump(strategy_dict, f, indent=2)

        # ファイルサイズと内容を確認
        self.assertTrue(os.path.exists(self.honeypot_file), "ハニーポット戦略ファイルが作成されていません")
        self.assertTrue(os.path.getsize(self.honeypot_file) > 0, "ハニーポット戦略ファイルが空です")

        # 内容をログ出力
        with open(self.honeypot_file, 'r') as f:
            content = f.read()
            print(f"ハニーポット戦略ファイル内容のサンプル（先頭100文字）:")
            print(content[:100] + "...")

    def test_reverse_trap_strategy(self):
        """リバーストラップ戦略をテスト"""
        # リバーストラップ戦略を作成
        strategy = create_reverse_trap_strategy(importance_factor=0.7)

        # 生成された鍵を取得
        # 注意: リバーストラップでは真偽が意図的に入れ替わる
        true_key = strategy.true_key  # これは入れ替え済みの「真」の鍵
        false_key = strategy.false_key  # これは入れ替え済みの「偽」の鍵

        # メタデータを確認
        self.assertEqual(strategy.metadata["strategy"], "reverse_trap", "戦略タイプがリバーストラップになっていません")
        self.assertEqual(strategy.metadata["importance_factor"], 0.7, "importance_factorが正しく設定されていません")

        # 各鍵の検証（リバーストラップでは入れ替わっているはず）
        verification = strategy.verify_key(true_key)
        self.assertTrue(verification["is_true_key"], "真の鍵（入れ替え済み）が正しく検証されません")

        verification = strategy.verify_key(false_key)
        self.assertTrue(verification["is_false_key"], "偽の鍵（入れ替え済み）が正しく検証されません")

        # 実際の検証の内部では、物理的には入れ替わっていることを確認
        # （これは内部実装の詳細に依存するためテストが不安定な可能性あり）

        # リバーストラップ戦略情報をシリアライズ
        strategy_dict = strategy.to_dict()
        with open(self.reverse_trap_file, 'w') as f:
            json.dump(strategy_dict, f, indent=2)

        # ファイルサイズと内容を確認
        self.assertTrue(os.path.exists(self.reverse_trap_file), "リバーストラップ戦略ファイルが作成されていません")
        self.assertTrue(os.path.getsize(self.reverse_trap_file) > 0, "リバーストラップ戦略ファイルが空です")

        # 内容をログ出力
        with open(self.reverse_trap_file, 'r') as f:
            content = f.read()
            print(f"リバーストラップ戦略ファイル内容のサンプル（先頭100文字）:")
            print(content[:100] + "...")

    def test_trap_capsule_creation(self):
        """トラップカプセル生成をテスト"""
        # 標準戦略を作成
        standard_strategy = TrapdoorStrategy()
        standard_strategy.generate_key_pair()

        # ハニーポット戦略を作成
        honeypot_strategy = create_honeypot_strategy()

        # リバーストラップ戦略を作成
        reverse_strategy = create_reverse_trap_strategy()

        # テスト用の出力ファイル名
        std_output = os.path.join(TEST_OUTPUT_DIR, f"trap_std_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")
        honey_output = os.path.join(TEST_OUTPUT_DIR, f"trap_honey_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")
        reverse_output = os.path.join(TEST_OUTPUT_DIR, f"trap_reverse_{os.urandom(4).hex()}{OUTPUT_EXTENSION}")

        # 1. 標準戦略でのカプセル作成テスト
        try:
            capsule = standard_strategy.create_trap_capsule(self.true_content, self.false_content)
            # カプセルを保存
            capsule.save_to_file(std_output)
            self.assertTrue(os.path.exists(std_output), "標準カプセルファイルが作成されていません")
        except Exception as e:
            self.fail(f"標準戦略でのカプセル作成に失敗しました: {e}")

        # 2. ハニーポット戦略でのカプセル作成テスト
        try:
            capsule = honeypot_strategy.create_trap_capsule(self.true_content, self.false_content)
            # カプセルを保存
            capsule.save_to_file(honey_output)
            self.assertTrue(os.path.exists(honey_output), "ハニーポットカプセルファイルが作成されていません")
        except Exception as e:
            self.fail(f"ハニーポット戦略でのカプセル作成に失敗しました: {e}")

        # 3. リバーストラップ戦略でのカプセル作成テスト
        try:
            capsule = reverse_strategy.create_trap_capsule(self.true_content, self.false_content)
            # カプセルを保存
            capsule.save_to_file(reverse_output)
            self.assertTrue(os.path.exists(reverse_output), "リバーストラップカプセルファイルが作成されていません")
        except Exception as e:
            self.fail(f"リバーストラップ戦略でのカプセル作成に失敗しました: {e}")

        # ファイルサイズを確認
        std_size = os.path.getsize(std_output)
        honey_size = os.path.getsize(honey_output)
        reverse_size = os.path.getsize(reverse_output)

        print(f"各カプセルサイズ:")
        print(f"  標準カプセル: {std_size} バイト")
        print(f"  ハニーポットカプセル: {honey_size} バイト")
        print(f"  リバーストラップカプセル: {reverse_size} バイト")

    def tearDown(self):
        """各テスト後のクリーンアップ"""
        # テスト生成ファイルの削除は行わない
        # タイムスタンプ付きでエビデンスとして保存
        pass

if __name__ == "__main__":
    unittest.main()
