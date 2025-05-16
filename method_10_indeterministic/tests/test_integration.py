"""
不確定性転写暗号化方式 - 統合テスト

このスクリプトは、encrypt.py、decrypt.py、StateCapsuleとCapsuleAnalyzerの
連携テストを行います。
"""

import os
import sys
import time
import hashlib
import unittest
import matplotlib.pyplot as plt
import numpy as np
import datetime
import random
from collections import Counter

# プロジェクトルートをインポートパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
method_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(method_dir)
sys.path.insert(0, project_root)

# 内部モジュールのインポート
from method_10_indeterministic.state_capsule import StateCapsule, BLOCK_TYPE_SEQUENTIAL, BLOCK_TYPE_INTERLEAVE
from method_10_indeterministic.capsule_analyzer import CapsuleAnalyzer
from method_10_indeterministic.encrypt import encrypt_file, encrypt_text
from method_10_indeterministic.decrypt import decrypt_file, decrypt_text

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = os.path.join(project_root, "test_output")
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)


class IntegrationTests(unittest.TestCase):
    """統合テストクラス"""

    def setUp(self):
        # テスト用の一時ファイルパス
        self.true_text_path = os.path.join(TEST_OUTPUT_DIR, "test_true.txt")
        self.false_text_path = os.path.join(TEST_OUTPUT_DIR, "test_false.txt")
        self.encrypted_path = os.path.join(TEST_OUTPUT_DIR, "test_encrypted.indt")
        self.key_path = os.path.join(TEST_OUTPUT_DIR, "test_encrypted.key")
        self.decrypted_true_path = os.path.join(TEST_OUTPUT_DIR, f"test_encrypted.indt_true_decrypted.txt")
        self.decrypted_false_path = os.path.join(TEST_OUTPUT_DIR, f"test_encrypted.indt_false_decrypted.txt")

        # テスト用のデータを生成
        self.true_text = """
この文書は「正規パス（true path）」用のテストデータです。
このデータは暗号化され、正規パスで復号された場合に表示されるべき内容です。
暗号化処理では、正規データと非正規データの両方を一つのカプセルに格納し、
どちらが本物かを第三者が判別できないようにします。

これは不確定性転写暗号化方式のテストです。
"""

        self.false_text = """
この文書は「非正規パス（false path）」用のテストデータです。
このデータは暗号化され、非正規パスで復号された場合に表示されるべき内容です。
実際の用途では、攻撃者が強制的に復号を試みた場合にこのデータが表示されます。

両方のデータが同じカプセル内に存在していますが、どちらが本物かは判別できません。
"""

        # テスト用のファイルを作成
        with open(self.true_text_path, "w", encoding="utf-8") as f:
            f.write(self.true_text)

        with open(self.false_text_path, "w", encoding="utf-8") as f:
            f.write(self.false_text)

    def tearDown(self):
        # テスト後のクリーンアップは行わない（ファイルを残しておく）
        pass

    def test_full_encryption_decryption_file(self):
        """ファイルの暗号化と復号の完全なフローをテスト"""
        # 暗号化
        encrypt_file(
            true_file=self.true_text_path,
            false_file=self.false_text_path,
            output_file=self.encrypted_path,
            key_file=self.key_path,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size=32,
            use_shuffle=True
        )

        # ファイルが生成されたことを確認
        self.assertTrue(os.path.exists(self.encrypted_path))
        self.assertTrue(os.path.exists(self.key_path))

        # true パスでの復号
        decrypt_file(
            encrypted_file=self.encrypted_path,
            key_file=self.key_path,
            output_file=self.decrypted_true_path,
            path_type="true"
        )

        # false パスでの復号
        decrypt_file(
            encrypted_file=self.encrypted_path,
            key_file=self.key_path,
            output_file=self.decrypted_false_path,
            path_type="false"
        )

        # 復号されたファイルの内容を検証
        with open(self.decrypted_true_path, "r", encoding="utf-8") as f:
            decrypted_true_content = f.read()

        with open(self.decrypted_false_path, "r", encoding="utf-8") as f:
            decrypted_false_content = f.read()

        # 元のテキストと復号されたテキストが一致するか確認
        self.assertEqual(self.true_text, decrypted_true_content)
        self.assertEqual(self.false_text, decrypted_false_content)

        # 暗号化されたファイルを分析
        self._analyze_encrypted_file(self.encrypted_path)

    def test_encryption_decryption_text(self):
        """テキストの暗号化と復号をテスト"""
        # 暗号化
        encrypted_data, key = encrypt_text(
            true_text=self.true_text,
            false_text=self.false_text,
            block_type=BLOCK_TYPE_INTERLEAVE,
            entropy_block_size=24,
            use_shuffle=True
        )

        # 暗号化されたデータと鍵が生成されたことを確認
        self.assertIsNotNone(encrypted_data)
        self.assertIsNotNone(key)

        # 復号
        decrypted_true = decrypt_text(
            encrypted_data=encrypted_data,
            key=key,
            path_type="true"
        )

        decrypted_false = decrypt_text(
            encrypted_data=encrypted_data,
            key=key,
            path_type="false"
        )

        # 復号されたテキストが元のテキストと一致するか確認
        self.assertEqual(self.true_text, decrypted_true)
        self.assertEqual(self.false_text, decrypted_false)

    def test_different_block_types(self):
        """異なるブロック処理タイプでの暗号化・復号をテスト"""
        # 順次配置での暗号化
        sequential_encrypted, sequential_key = encrypt_text(
            true_text=self.true_text,
            false_text=self.false_text,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size=16,
            use_shuffle=True
        )

        # インターリーブ配置での暗号化
        interleaved_encrypted, interleaved_key = encrypt_text(
            true_text=self.true_text,
            false_text=self.false_text,
            block_type=BLOCK_TYPE_INTERLEAVE,
            entropy_block_size=16,
            use_shuffle=True
        )

        # 各方式での復号と検証
        sequential_true = decrypt_text(sequential_encrypted, sequential_key, "true")
        sequential_false = decrypt_text(sequential_encrypted, sequential_key, "false")

        interleaved_true = decrypt_text(interleaved_encrypted, interleaved_key, "true")
        interleaved_false = decrypt_text(interleaved_encrypted, interleaved_key, "false")

        # 復号結果の検証
        self.assertEqual(self.true_text, sequential_true)
        self.assertEqual(self.false_text, sequential_false)
        self.assertEqual(self.true_text, interleaved_true)
        self.assertEqual(self.false_text, interleaved_false)

        # 暗号文サイズと解析耐性の比較
        analyzer = CapsuleAnalyzer()
        sequential_analysis = analyzer.analyze_capsule(sequential_encrypted)
        analyzer.analyze_capsule(interleaved_encrypted)
        interleaved_resistance = analyzer.get_resistance_level()

        # 結果の可視化
        self._compare_and_visualize(sequential_encrypted, interleaved_encrypted)

        # 両方のデータが同じ長さの入力から生成されたにも関わらず、異なるサイズと特性を持っていることを確認
        self.assertNotEqual(len(sequential_encrypted), len(interleaved_encrypted))

    def _analyze_encrypted_file(self, file_path):
        """暗号化されたファイルを解析"""
        # ファイルを読み込む
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        # 解析器でカプセルを分析
        analyzer = CapsuleAnalyzer()
        analysis_results = analyzer.analyze_capsule(encrypted_data)

        # 解析結果の可視化
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(TEST_OUTPUT_DIR, f"integration_test_{timestamp}.png")

        # 可視化用の図を作成
        plt.figure(figsize=(12, 8))

        # エントロピー分布の可視化
        plt.subplot(2, 2, 1)
        entropy_per_block = analysis_results["entropy_analysis"]["entropy_per_block"]
        plt.plot(entropy_per_block, 'g-')
        plt.title('ブロック別エントロピー分布')
        plt.xlabel('ブロック番号')
        plt.ylabel('正規化エントロピー')
        plt.grid(True, alpha=0.3)

        # バイト分布の可視化
        plt.subplot(2, 2, 2)
        distribution = analysis_results["byte_distribution"]["distribution"]
        byte_values = list(range(256))
        byte_counts = [distribution.get(str(b), 0) for b in byte_values]
        plt.bar(byte_values[::4], byte_counts[::4], color='blue', alpha=0.7)  # 4バイト毎に表示
        plt.title('バイト値分布')
        plt.xlabel('バイト値')
        plt.ylabel('出現頻度')
        plt.grid(True, alpha=0.3)

        # ヘッダー情報の表示
        plt.subplot(2, 2, 3)
        header_info = analysis_results["header"]
        plt.axis('off')
        header_text = (
            f"ブロック処理タイプ: {'順次配置' if header_info['block_type'] == BLOCK_TYPE_SEQUENTIAL else 'インターリーブ'}\n"
            f"エントロピーブロックサイズ: {header_info['entropy_block_size']}バイト\n"
            f"署名検証: {'成功' if header_info['signature_valid'] else '失敗'}\n"
            f"バージョン: {header_info['version']}"
        )
        plt.text(0.5, 0.5, header_text, ha='center', va='center', fontsize=12)

        # 解析耐性スコアの表示
        plt.subplot(2, 2, 4)
        resistance_score = analysis_results["resistance_score"]
        categories = ['エントロピー', '分布均一性', 'ブロック構造']
        scores = [
            resistance_score["entropy_score"],
            resistance_score["distribution_score"],
            resistance_score["block_score"]
        ]
        plt.bar(categories, scores, color=['green', 'blue', 'purple'])
        plt.title(f'解析耐性スコア (合計: {resistance_score["total"]:.2f}/10)')
        plt.ylabel('スコア')
        plt.ylim(0, 4)

        # 全体のタイトル
        plt.suptitle('不確定性転写暗号化方式 - 統合テスト分析結果', fontsize=16)

        # 保存
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        plt.savefig(output_file)
        print(f"統合テスト分析結果を保存しました: {output_file}")

    def _compare_and_visualize(self, sequential_data, interleaved_data):
        """2つの暗号化手法の比較結果を可視化"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(TEST_OUTPUT_DIR, f"block_type_comparison_{timestamp}.png")

        # 解析
        analyzer = CapsuleAnalyzer()
        sequential_analysis = analyzer.analyze_capsule(sequential_data)
        interleaved_analysis = analyzer.analyze_capsule(interleaved_data)

        # 可視化用の図を作成
        plt.figure(figsize=(12, 8))

        # ファイルサイズの比較
        plt.subplot(2, 2, 1)
        sizes = [len(sequential_data), len(interleaved_data)]
        plt.bar(['順次配置', 'インターリーブ'], sizes, color=['blue', 'green'])
        plt.title('暗号化データサイズの比較')
        plt.ylabel('サイズ (バイト)')
        for i, size in enumerate(sizes):
            plt.text(i, size + 50, str(size), ha='center')

        # エントロピーの比較
        plt.subplot(2, 2, 2)
        entropy_values = [
            sequential_analysis["entropy_analysis"]["normalized_entropy"],
            interleaved_analysis["entropy_analysis"]["normalized_entropy"]
        ]
        plt.bar(['順次配置', 'インターリーブ'], entropy_values, color=['blue', 'green'])
        plt.title('正規化エントロピーの比較')
        plt.ylabel('正規化エントロピー')
        plt.ylim(0, 1)
        for i, val in enumerate(entropy_values):
            plt.text(i, val + 0.05, f"{val:.3f}", ha='center')

        # 解析耐性スコアの比較
        plt.subplot(2, 2, 3)
        scores = [
            sequential_analysis["resistance_score"]["total"],
            interleaved_analysis["resistance_score"]["total"]
        ]
        plt.bar(['順次配置', 'インターリーブ'], scores, color=['blue', 'green'])
        plt.title('解析耐性スコアの比較')
        plt.ylabel('総合スコア (0-10)')
        plt.ylim(0, 10)
        for i, score in enumerate(scores):
            plt.text(i, score + 0.3, f"{score:.2f}", ha='center')

        # ブロック類似性の比較
        plt.subplot(2, 2, 4)
        similarities = [
            sequential_analysis["block_analysis"]["avg_block_similarity"],
            interleaved_analysis["block_analysis"]["avg_block_similarity"]
        ]
        plt.bar(['順次配置', 'インターリーブ'], similarities, color=['blue', 'green'])
        plt.title('ブロック間類似性の比較')
        plt.ylabel('平均類似性 (0-1)')
        plt.ylim(0, 1)
        for i, sim in enumerate(similarities):
            plt.text(i, sim + 0.05, f"{sim:.3f}", ha='center')

        # 全体のタイトル
        plt.suptitle('不確定性転写暗号化方式 - ブロック処理方式の比較', fontsize=16)

        # 保存
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        plt.savefig(output_file)
        print(f"ブロック処理方式の比較結果を保存しました: {output_file}")


if __name__ == "__main__":
    unittest.main()