#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
不確定性転写暗号化方式 - 状態カプセルのテスト

このモジュールはStateCapsuleクラスの機能をテストします。
様々なカプセル化のオプションとデータ抽出方法を検証します。
"""

import os
import sys
import time
import random
import hashlib
import binascii
import unittest
import matplotlib
matplotlib.use('Agg')  # GUIを使用せずに保存
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from collections import Counter

# プロジェクトルートをインポートパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
method_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(method_dir)
sys.path.insert(0, project_root)

# 内部モジュールのインポート
from method_10_indeterministic.state_capsule import (
    StateCapsule, BLOCK_TYPE_SEQUENTIAL, BLOCK_TYPE_INTERLEAVE
)
from method_10_indeterministic.capsule_analyzer import CapsuleAnalyzer
from method_10_indeterministic.tests.test_utils import (
    TestResult, get_timestamp_str, TEST_OUTPUT_DIR
)

# 乱数生成の初期化
RANDOM_SEED = 12345
random.seed(RANDOM_SEED)

# 出力ディレクトリの設定
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)


def test_state_capsule_basic():
    """StateCapsuleの基本機能テスト"""
    results = TestResult()

    # テスト用データの作成
    true_data = os.urandom(1024)
    false_data = os.urandom(1024)
    entropy_block_size = 32

    # テスト1: 基本的なカプセル作成（順次処理方式）
    try:
        capsule = StateCapsule()

        sequential_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size, False
        )

        # カプセルが作成されたことを確認
        is_created = len(sequential_capsule) > 0
        results.add_result(
            "順次処理方式カプセル作成",
            is_created,
            f"カプセルサイズ: {len(sequential_capsule)} バイト"
        )

        # カプセルのサイズが元データよりも大きいことを確認（エントロピー追加のため）
        is_larger = len(sequential_capsule) > len(true_data) + len(false_data)
        results.add_result(
            "カプセルサイズの検証",
            is_larger,
            f"期待値: >{len(true_data) + len(false_data)}, 実際: {len(sequential_capsule)}"
        )

    except Exception as e:
        results.add_result("順次処理方式カプセル作成", False, f"例外発生: {str(e)}")

    # テスト2: インターリーブ処理方式でのカプセル作成
    try:
        capsule = StateCapsule()

        interleave_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_INTERLEAVE,
            entropy_block_size, False
        )

        # カプセルが作成されたことを確認
        is_created = len(interleave_capsule) > 0
        results.add_result(
            "インターリーブ処理方式カプセル作成",
            is_created,
            f"カプセルサイズ: {len(interleave_capsule)} バイト"
        )

        # 順次方式とインターリーブ方式で異なるサイズのカプセルが生成されることを確認
        is_different = len(sequential_capsule) != len(interleave_capsule)
        results.add_result(
            "処理方式によるカプセルサイズの差異",
            is_different,
            f"順次: {len(sequential_capsule)}, インターリーブ: {len(interleave_capsule)}"
        )

    except Exception as e:
        results.add_result("インターリーブ処理方式カプセル作成", False, f"例外発生: {str(e)}")

    # テスト3: シャッフル処理の有無によるカプセルの差異
    try:
        capsule = StateCapsule()

        # シャッフルなしのカプセル
        no_shuffle_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size, False
        )

        # シャッフルありのカプセル
        shuffle_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size, True
        )

        # シャッフルの有無でカプセルが異なることを確認
        is_different = no_shuffle_capsule != shuffle_capsule
        results.add_result(
            "シャッフル処理の効果検証",
            is_different,
            "シャッフルによりカプセルデータが変化することを確認"
        )

    except Exception as e:
        results.add_result("シャッフル処理検証", False, f"例外発生: {str(e)}")

    # テスト4: データ抽出機能（正規パス）
    try:
        capsule = StateCapsule()

        sequential_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size, False
        )

        # 正規パスでデータを抽出
        extracted_true = capsule.extract_data(sequential_capsule, "true")

        # 抽出されたデータが元の正規データと一致することを確認
        is_same = extracted_true == true_data
        results.add_result(
            "正規パスでのデータ抽出",
            is_same,
            f"データ長: 期待値 {len(true_data)}, 実際 {len(extracted_true)}"
        )

    except Exception as e:
        results.add_result("正規パスでのデータ抽出", False, f"例外発生: {str(e)}")

    # テスト5: データ抽出機能（非正規パス）
    try:
        capsule = StateCapsule()

        sequential_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size, False
        )

        # 非正規パスでデータを抽出
        extracted_false = capsule.extract_data(sequential_capsule, "false")

        # 抽出されたデータが元の非正規データと一致することを確認
        is_same = extracted_false == false_data
        results.add_result(
            "非正規パスでのデータ抽出",
            is_same,
            f"データ長: 期待値 {len(false_data)}, 実際 {len(extracted_false)}"
        )

    except Exception as e:
        results.add_result("非正規パスでのデータ抽出", False, f"例外発生: {str(e)}")

    # テスト6: シャッフル処理を含むカプセルからのデータ抽出
    try:
        capsule = StateCapsule()

        shuffle_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size, True
        )

        # 正規パスでデータを抽出
        extracted_true = capsule.extract_data(shuffle_capsule, "true")

        # 非正規パスでデータを抽出
        extracted_false = capsule.extract_data(shuffle_capsule, "false")

        # 抽出されたデータが元のデータと一致することを確認
        is_true_same = extracted_true == true_data
        is_false_same = extracted_false == false_data

        results.add_result(
            "シャッフル処理後の正規パス抽出",
            is_true_same,
            "シャッフルされたカプセルからの正規データ抽出"
        )

        results.add_result(
            "シャッフル処理後の非正規パス抽出",
            is_false_same,
            "シャッフルされたカプセルからの非正規データ抽出"
        )

    except Exception as e:
        results.add_result("シャッフル処理後のデータ抽出", False, f"例外発生: {str(e)}")

    # テスト7: インターリーブ処理方式でのデータ抽出
    try:
        capsule = StateCapsule()

        interleave_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_INTERLEAVE,
            entropy_block_size, False
        )

        # 正規パスでデータを抽出
        extracted_true = capsule.extract_data(interleave_capsule, "true")

        # 非正規パスでデータを抽出
        extracted_false = capsule.extract_data(interleave_capsule, "false")

        # 抽出されたデータが元のデータと一致することを確認
        is_true_same = extracted_true == true_data
        is_false_same = extracted_false == false_data

        results.add_result(
            "インターリーブ方式での正規パス抽出",
            is_true_same,
            "インターリーブカプセルからの正規データ抽出"
        )

        results.add_result(
            "インターリーブ方式での非正規パス抽出",
            is_false_same,
            "インターリーブカプセルからの非正規データ抽出"
        )

    except Exception as e:
        results.add_result("インターリーブ方式でのデータ抽出", False, f"例外発生: {str(e)}")

    # テスト8: 異なるエントロピーブロックサイズの効果
    try:
        capsule = StateCapsule()

        # 小さいエントロピーブロックサイズ
        small_block_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            16, False
        )

        # 大きいエントロピーブロックサイズ
        large_block_capsule = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL,
            64, False
        )

        # エントロピーブロックサイズの違いでカプセルサイズが変わることを確認
        is_different = len(small_block_capsule) != len(large_block_capsule)
        results.add_result(
            "エントロピーブロックサイズの効果",
            is_different,
            f"16バイトブロック: {len(small_block_capsule)}, 64バイトブロック: {len(large_block_capsule)}"
        )

        # 両方のカプセルからのデータ抽出を検証
        small_extracted = capsule.extract_data(small_block_capsule, "true")
        large_extracted = capsule.extract_data(large_block_capsule, "true")

        is_small_valid = small_extracted == true_data
        is_large_valid = large_extracted == true_data

        results.add_result(
            "小エントロピーブロックサイズでのデータ抽出",
            is_small_valid,
            "16バイトブロックからの正規データ抽出"
        )

        results.add_result(
            "大エントロピーブロックサイズでのデータ抽出",
            is_large_valid,
            "64バイトブロックからの正規データ抽出"
        )

    except Exception as e:
        results.add_result("エントロピーブロックサイズテスト", False, f"例外発生: {str(e)}")

    # テスト9: 異なるカプセルの解析耐性比較
    try:
        capsule = StateCapsule()
        analyzer = CapsuleAnalyzer()

        # 4種類のカプセルを生成
        capsule_basic = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL, 32, False
        )

        capsule_shuffle = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL, 32, True
        )

        capsule_interleave = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_INTERLEAVE, 32, False
        )

        capsule_interleave_shuffle = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_INTERLEAVE, 32, True
        )

        # 各カプセルの解析を実行
        analysis_basic = analyzer.analyze_capsule(capsule_basic)
        analysis_shuffle = analyzer.analyze_capsule(capsule_shuffle)
        analysis_interleave = analyzer.analyze_capsule(capsule_interleave)
        analysis_interleave_shuffle = analyzer.analyze_capsule(capsule_interleave_shuffle)

        # 解析耐性スコアを取得
        score_basic = analysis_basic["resistance_score"]["total"]
        score_shuffle = analysis_shuffle["resistance_score"]["total"]
        score_interleave = analysis_interleave["resistance_score"]["total"]
        score_interleave_shuffle = analysis_interleave_shuffle["resistance_score"]["total"]

        # シャッフル処理によって耐性が向上することを検証
        shuffle_improves = score_shuffle > score_basic
        results.add_result(
            "シャッフル処理による解析耐性向上",
            shuffle_improves,
            f"基本: {score_basic:.2f}, シャッフル後: {score_shuffle:.2f}"
        )

        # インターリーブ処理によって耐性が向上することを検証
        interleave_improves = score_interleave > score_basic
        results.add_result(
            "インターリーブ処理による解析耐性向上",
            interleave_improves,
            f"基本: {score_basic:.2f}, インターリーブ: {score_interleave:.2f}"
        )

        # 両方の処理を組み合わせた時の効果を検証
        combined_improves = score_interleave_shuffle > score_basic
        results.add_result(
            "インターリーブとシャッフルの組み合わせ効果",
            combined_improves,
            f"基本: {score_basic:.2f}, 両方適用: {score_interleave_shuffle:.2f}"
        )

        # 結果の可視化
        visualize_capsule_comparison(
            results,
            [capsule_basic, capsule_shuffle, capsule_interleave, capsule_interleave_shuffle],
            [score_basic, score_shuffle, score_interleave, score_interleave_shuffle]
        )

    except Exception as e:
        results.add_result("カプセル解析耐性テスト", False, f"例外発生: {str(e)}")

    # 結果の表示
    results.print_summary()

    return results


def visualize_capsule_comparison(results, capsules, resistance_scores):
    """
    異なるカプセル処理方式の比較結果を可視化

    Args:
        results: テスト結果オブジェクト
        capsules: 比較するカプセルのリスト
        resistance_scores: 各カプセルの解析耐性スコア
    """
    timestamp = get_timestamp_str()
    output_file = os.path.join(TEST_OUTPUT_DIR, f"capsule_comparison_{timestamp}.png")

    plt.figure(figsize=(15, 10))

    # 左上: テスト結果のサマリー
    plt.subplot(2, 2, 1)
    labels = ['成功', '失敗']
    sizes = [results.passed, results.failed]
    colors = ['#4CAF50', '#F44336'] if results.failed == 0 else ['#FFEB3B', '#F44336']
    explode = (0.1, 0) if results.failed == 0 else (0, 0.1)

    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=90)
    plt.axis('equal')
    plt.title('テスト結果概要')

    # 右上: カプセルサイズの比較
    plt.subplot(2, 2, 2)
    methods = ['基本', 'シャッフル', 'インターリーブ', 'インターリーブ\n+シャッフル']
    sizes = [len(c) for c in capsules]

    plt.bar(methods, sizes, color='blue', alpha=0.7)
    plt.title('カプセルサイズの比較')
    plt.ylabel('サイズ (バイト)')
    plt.xticks(rotation=45, ha='right')
    plt.grid(True, alpha=0.3)

    # 左下: 解析耐性スコアの比較
    plt.subplot(2, 2, 3)
    plt.bar(methods, resistance_scores, color='purple', alpha=0.7)
    plt.title('解析耐性スコアの比較')
    plt.ylabel('スコア (0-10)')
    plt.ylim(0, 10)
    plt.xticks(rotation=45, ha='right')
    plt.grid(True, alpha=0.3)

    # 右下: エントロピー分布の可視化
    plt.subplot(2, 2, 4)
    analyzer = CapsuleAnalyzer()

    entropy_values = []
    labels = []

    for i, capsule in enumerate(capsules):
        analysis = analyzer.analyze_capsule(capsule)
        entropy = analysis["entropy_analysis"]["shannon_entropy"]
        entropy_values.append(entropy)
        labels.append(methods[i])

    plt.bar(labels, entropy_values, color='green', alpha=0.7)
    plt.title('エントロピー値の比較')
    plt.ylabel('シャノンエントロピー (ビット/バイト)')
    plt.ylim(0, 8)
    plt.xticks(rotation=45, ha='right')
    plt.grid(True, alpha=0.3)

    # 全体のタイトル
    plt.suptitle('不確定性転写暗号化方式 - カプセル処理方式の比較', fontsize=16)
    plt.tight_layout(rect=[0, 0, 1, 0.95])

    # 保存
    plt.savefig(output_file)
    print(f"カプセル処理方式の比較結果を保存しました: {output_file}")

    return output_file


# 既存のテストクラスはそのまま保持（必要に応じて後で更新）
class TestStateCapsule(unittest.TestCase):
    """StateCapsuleのテストケース"""

    def setUp(self):
        """テスト前の準備"""
        # テスト用の鍵とソルト
        self.key = os.urandom(32)
        self.salt = os.urandom(16)

        # テスト用データ（サイズ違い）
        self.small_data = os.urandom(1024)  # 1KB
        self.medium_data = os.urandom(64 * 1024)  # 64KB
        self.large_data = os.urandom(1024 * 1024)  # 1MB

        # テスト用のファイルパス
        self.test_files = []

    def tearDown(self):
        """テスト後のクリーンアップ"""
        # テスト用ファイルの削除
        for file_path in self.test_files:
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    print(f"警告: テストファイル '{file_path}' の削除に失敗しました: {e}", file=sys.stderr)

    def test_basic_capsule_operations(self):
        """基本的なカプセル化・抽出操作のテスト"""
        # StateCapsuleの初期化
        capsule = StateCapsule()

        # テスト用のデータとシグネチャ
        true_data = b"This is true data for testing"
        false_data = b"This is false data for testing"

        # カプセル化
        capsule_data = capsule.create_capsule(
            true_data, false_data, BLOCK_TYPE_SEQUENTIAL, 32, False
        )

        # データが実際にカプセル化されていることを確認
        self.assertIsNotNone(capsule_data)
        self.assertTrue(len(capsule_data) > 0)

        # 正規パスからデータを抽出
        extracted_true_data = capsule.extract_data(capsule_data, "true")

        # 非正規パスからデータを抽出
        extracted_false_data = capsule.extract_data(capsule_data, "false")

        # 抽出データを検証
        self.assertEqual(true_data, extracted_true_data)
        self.assertEqual(false_data, extracted_false_data)


if __name__ == "__main__":
    print("=== 状態カプセルのテスト ===")
    results = test_state_capsule_basic()
    print("\n=== unittest形式のテスト ===")
    unittest.main()