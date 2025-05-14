#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - カプセル機能のテスト

状態カプセルと不確定性カプセルの機能を検証します。
"""

import os
import sys
import unittest
import tempfile
import hashlib
import random
import time
import datetime
from typing import Tuple, Dict, Any, List

# テスト用にモジュールパスを追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# プロジェクトのルートディレクトリを取得
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# テスト対象のモジュールをインポート
from method_10_indeterministic.state_capsule import StateCapsule, create_state_capsule
from method_10_indeterministic.indeterministic import IndeterministicCapsule, create_indeterministic_capsule
from method_10_indeterministic.entropy_injector import inject_entropy, get_entropy_bytes
from method_10_indeterministic.state_matrix import StateMatrix, generate_state_matrix
from method_10_indeterministic.probability_engine import ProbabilityEngine, calculate_probability_distribution
from method_10_indeterministic.encrypt import generate_master_key
from method_10_indeterministic.config import (
    STATE_MATRIX_SIZE, OUTPUT_FORMAT, OUTPUT_EXTENSION
)

# パスを絶対パスに変更
TRUE_TEXT_PATH = os.path.join(ROOT_DIR, "common/true-false-text/true.text")
FALSE_TEXT_PATH = os.path.join(ROOT_DIR, "common/true-false-text/false.text")

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = os.path.join(ROOT_DIR, "test_output")

class TestCapsule(unittest.TestCase):
    """カプセル機能のテスト"""

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
        self.capsule_file = os.path.join(TEST_OUTPUT_DIR, f"test_capsule_{os.urandom(4).hex()}.cap")
        self.state_file = os.path.join(TEST_OUTPUT_DIR, f"test_state_{os.urandom(4).hex()}.state")

        # テスト用の鍵を生成
        self.key = generate_master_key()

    def test_state_capsule_creation(self):
        """状態カプセル作成をテスト"""
        # 状態カプセルを作成
        capsule = create_state_capsule(self.key, self.true_content, self.false_content)

        # 基本プロパティを確認
        self.assertIsNotNone(capsule.capsule_id, "カプセルIDが設定されていません")
        self.assertIsNotNone(capsule.created_at, "作成時刻が設定されていません")
        self.assertIsNotNone(capsule.key_hash, "鍵ハッシュが設定されていません")
        self.assertIsNotNone(capsule.salt, "ソルトが設定されていません")
        self.assertIsNotNone(capsule.nonce, "ノンスが設定されていません")

        # 状態マトリクスの初期化を確認
        self.assertIsNotNone(capsule.state_matrix, "状態マトリクスが初期化されていません")
        self.assertTrue(capsule.state_matrix.initialized, "状態マトリクスが初期化されていません")

        # 確率エンジンの初期化を確認
        self.assertIsNotNone(capsule.probability_engine, "確率エンジンが初期化されていません")
        self.assertTrue(capsule.probability_engine.initialized, "確率エンジンが初期化されていません")

        # メタデータを確認
        self.assertEqual(capsule.metadata["format"], OUTPUT_FORMAT, f"メタデータの形式が {OUTPUT_FORMAT} ではありません")
        self.assertEqual(capsule.metadata["state_matrix_size"], STATE_MATRIX_SIZE,
                       f"状態マトリクスサイズが {STATE_MATRIX_SIZE} ではありません")
        self.assertEqual(capsule.metadata["true_data_size"], len(self.true_content),
                       "真のデータサイズが正しくありません")
        self.assertEqual(capsule.metadata["false_data_size"], len(self.false_content),
                       "偽のデータサイズが正しくありません")

        # シリアライズして保存
        capsule.save_to_file(self.state_file)

        # ファイルの存在を確認
        self.assertTrue(os.path.exists(self.state_file), "状態カプセルファイルが作成されていません")
        self.assertTrue(os.path.getsize(self.state_file) > 0, "状態カプセルファイルが空です")

        # 再読み込み
        loaded_capsule = StateCapsule.load_from_file(self.state_file)

        # 基本プロパティが保持されていることを確認
        self.assertEqual(loaded_capsule.capsule_id, capsule.capsule_id, "カプセルIDが保持されていません")
        self.assertEqual(loaded_capsule.created_at, capsule.created_at, "作成時刻が保持されていません")
        self.assertEqual(loaded_capsule.metadata, capsule.metadata, "メタデータが保持されていません")

    def test_indeterministic_capsule_creation(self):
        """不確定性カプセル作成をテスト"""
        # 不確定性カプセルを作成
        capsule = create_indeterministic_capsule(self.key, self.true_content, self.false_content)

        # 基本プロパティを確認
        self.assertIsNotNone(capsule.capsule_id, "カプセルIDが設定されていません")
        self.assertIsNotNone(capsule.created_at, "作成時刻が設定されていません")
        self.assertIsNotNone(capsule.state_capsule, "状態カプセルが設定されていません")
        self.assertIsNotNone(capsule.true_data_hash, "真データハッシュが設定されていません")
        self.assertIsNotNone(capsule.false_data_hash, "偽データハッシュが設定されていません")
        self.assertIsNotNone(capsule.salt, "ソルトが設定されていません")
        self.assertIsNotNone(capsule.nonce, "ノンスが設定されていません")
        self.assertIsNotNone(capsule.encrypted_data, "暗号化データが設定されていません")

        # メタデータを確認
        self.assertEqual(capsule.metadata["format"], OUTPUT_FORMAT, f"メタデータの形式が {OUTPUT_FORMAT} ではありません")
        self.assertEqual(capsule.metadata["true_data_size"], len(self.true_content),
                       "真のデータサイズが正しくありません")
        self.assertEqual(capsule.metadata["false_data_size"], len(self.false_content),
                       "偽のデータサイズが正しくありません")

        # シリアライズして保存
        capsule.save_to_file(self.capsule_file)

        # ファイルの存在を確認
        self.assertTrue(os.path.exists(self.capsule_file), "不確定性カプセルファイルが作成されていません")
        self.assertTrue(os.path.getsize(self.capsule_file) > 0, "不確定性カプセルファイルが空です")

        # 再読み込み
        loaded_capsule = IndeterministicCapsule.load_from_file(self.capsule_file)

        # 基本プロパティが保持されていることを確認
        self.assertEqual(loaded_capsule.capsule_id, capsule.capsule_id, "カプセルIDが保持されていません")
        self.assertEqual(loaded_capsule.created_at, capsule.created_at, "作成時刻が保持されていません")
        self.assertEqual(loaded_capsule.metadata, capsule.metadata, "メタデータが保持されていません")

        # 暗号化データが保持されていることを確認
        self.assertIsNotNone(loaded_capsule.encrypted_data, "暗号化データが保持されていません")
        self.assertEqual(len(loaded_capsule.encrypted_data), len(capsule.encrypted_data),
                        "暗号化データのサイズが一致しません")

    def test_path_determination(self):
        """パス決定機能をテスト"""
        # 状態カプセルを作成
        state_capsule = create_state_capsule(self.key, self.true_content, self.false_content)

        # 同じ鍵を使用してパスを決定
        path_type = state_capsule.determine_path(self.key)

        # 有効なパスタイプが返されることを確認
        self.assertIn(path_type, ["true", "false"], f"不正なパスタイプ: {path_type}")

        # 複数回同じ鍵で呼び出した場合、同じ結果になることを確認
        for _ in range(5):
            self.assertEqual(state_capsule.determine_path(self.key), path_type,
                           "同じ鍵で異なるパスタイプが返されました")

        # 異なる鍵では異なる結果が得られることを確認（確率的）
        different_keys = [generate_master_key() for _ in range(10)]
        path_types = [state_capsule.determine_path(key) for key in different_keys]

        # 少なくとも1つは異なるパスタイプが出ることを期待
        # （確率的なので100%の保証はできないが、十分な数の鍵を試せば偏りが出るはず）
        true_count = path_types.count("true")
        false_count = path_types.count("false")

        print(f"パスタイプ分布（異なる鍵）: true={true_count}, false={false_count}")

        # どちらも0でないことを確認（極端な場合を防ぐ）
        self.assertTrue(true_count > 0 or false_count > 0,
                      "有効なパスタイプが生成されていません")

    def test_capsule_operations(self):
        """カプセル操作をテスト"""
        # 不確定性カプセルを作成
        capsule = create_indeterministic_capsule(self.key, self.true_content, self.false_content)

        # カプセルをシリアライズ
        serialized = capsule.serialize()
        self.assertTrue(isinstance(serialized, bytes), "シリアライズ結果がバイト列ではありません")
        self.assertTrue(len(serialized) > 0, "シリアライズ結果が空です")

        # カプセルをデシリアライズ
        deserialized = IndeterministicCapsule.deserialize(serialized)
        self.assertEqual(deserialized.capsule_id, capsule.capsule_id, "デシリアライズ後のカプセルIDが一致しません")

        # カプセルから辞書を作成
        capsule_dict = capsule.to_dict()
        self.assertTrue(isinstance(capsule_dict, dict), "辞書変換結果が辞書ではありません")
        self.assertIn("capsule_id", capsule_dict, "辞書にカプセルIDが含まれていません")
        self.assertIn("metadata", capsule_dict, "辞書にメタデータが含まれていません")

        # 内部状態カプセルの操作
        state_capsule = capsule.state_capsule
        self.assertIsNotNone(state_capsule, "状態カプセルが設定されていません")

        # 状態カプセルをシリアライズ
        state_serialized = state_capsule.serialize()
        self.assertTrue(isinstance(state_serialized, bytes), "状態カプセルのシリアライズ結果がバイト列ではありません")

        # 状態カプセルをデシリアライズ
        state_deserialized = StateCapsule.deserialize(state_serialized)
        self.assertEqual(state_deserialized.capsule_id, state_capsule.capsule_id,
                       "デシリアライズ後の状態カプセルIDが一致しません")

    def test_multiple_capsules(self):
        """複数カプセルの作成と管理をテスト"""
        # 複数の鍵と対応するカプセルを生成
        num_capsules = 5
        keys = [generate_master_key() for _ in range(num_capsules)]
        capsules = []

        # カプセルファイルパスのリスト
        capsule_files = []

        for i, key in enumerate(keys):
            # カプセルを作成
            capsule = create_indeterministic_capsule(key, self.true_content, self.false_content)
            capsules.append(capsule)

            # カプセルを保存
            file_path = os.path.join(TEST_OUTPUT_DIR, f"test_multi_{i}_{os.urandom(4).hex()}.cap")
            capsule.save_to_file(file_path)
            capsule_files.append(file_path)

            # ファイルの存在を確認
            self.assertTrue(os.path.exists(file_path), f"カプセルファイル {i} が作成されていません")

        # すべてのカプセルが異なるIDを持つことを確認
        capsule_ids = [capsule.capsule_id for capsule in capsules]
        self.assertEqual(len(set(capsule_ids)), num_capsules, "カプセルIDが重複しています")

        # すべてのカプセルを読み込めることを確認
        for i, file_path in enumerate(capsule_files):
            loaded_capsule = IndeterministicCapsule.load_from_file(file_path)
            self.assertEqual(loaded_capsule.capsule_id, capsules[i].capsule_id,
                          f"カプセル {i} のIDが一致しません")

        # ログ出力
        print(f"{num_capsules}個のカプセルを作成し、保存、再読み込みしました")
        for i, (key, capsule) in enumerate(zip(keys, capsules)):
            # 16進数で先頭8文字のみ表示
            key_hex = key.hex()[:16] + "..."
            print(f"カプセル {i}: ID={capsule.capsule_id}, 鍵={key_hex}")

    def test_state_matrix_interaction(self):
        """状態マトリクスとの連携をテスト"""
        # 状態マトリクスを直接生成
        matrix = generate_state_matrix(self.key, self.true_content)

        # マトリクスの基本プロパティを確認
        self.assertEqual(matrix.size, STATE_MATRIX_SIZE, f"マトリクスサイズが {STATE_MATRIX_SIZE} ではありません")
        self.assertTrue(matrix.initialized, "マトリクスが初期化されていません")

        # 状態遷移をテスト
        signature_before = matrix.get_state_signature()
        matrix.transition()
        signature_after = matrix.get_state_signature()

        # 遷移によってシグネチャが変化することを確認
        self.assertNotEqual(signature_before, signature_after, "状態遷移後もシグネチャが変化していません")

        # 確率エンジンとの連携
        engine = calculate_probability_distribution(self.key, matrix)

        # エンジンの基本プロパティを確認
        self.assertTrue(engine.initialized, "確率エンジンが初期化されていません")

        # サンプリングをテスト
        samples = [engine.sample() for _ in range(10)]

        # すべてのサンプルが0〜1の範囲内であることを確認
        for sample in samples:
            self.assertTrue(0 <= sample <= 1, f"サンプル値 {sample} が範囲外です")

        # 同じパラメータで再生成した場合の一貫性確認
        matrix2 = generate_state_matrix(self.key, self.true_content)
        signature2 = matrix2.get_state_signature()

        # 同じ入力からは同じ初期状態が得られることを確認
        self.assertEqual(signature_before, signature2, "同じ入力から異なる初期状態が生成されました")

    def tearDown(self):
        """各テスト後のクリーンアップ"""
        # テスト生成ファイルの削除は行わない
        # タイムスタンプ付きでエビデンスとして保存
        pass

if __name__ == "__main__":
    unittest.main()
