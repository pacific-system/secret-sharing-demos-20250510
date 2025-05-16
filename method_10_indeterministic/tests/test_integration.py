"""
不確定性転写暗号化方式 - 統合テスト

暗号化・復号の一連の流れをテストし、以下を検証します:
1. 同じ鍵で暗号化・復号すると元のファイルが取得できる
2. 異なる鍵で復号すると異なるファイルが取得される
3. 各鍵に対して適切なTRUE/FALSEテキストが取得される
4. 実行パスが毎回変化する
"""

import os
import sys
import time
import tempfile
import hashlib
import unittest
import matplotlib.pyplot as plt
import numpy as np
import json
import base64
from typing import Dict, List, Tuple, Any

# プロジェクトルートをインポートパスに追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# 内部モジュールのインポート
from method_10_indeterministic.encrypt import encrypt_file
from method_10_indeterministic.decrypt import decrypt_file
from method_10_indeterministic.tests.test_utils import (
    generate_random_key, create_temp_file, cleanup_temp_file,
    ensure_test_files, get_timestamp_str, TestResult, TEST_OUTPUT_DIR
)
from method_10_indeterministic.probability_engine import (
    ProbabilisticExecutionEngine, create_engine_from_key, TRUE_PATH, FALSE_PATH
)


def test_encryption_decryption():
    """暗号化・復号の統合テスト"""
    results = TestResult()

    # テストファイルの準備
    ensure_test_files()

    # 一時ファイルの作成
    true_content = "これは正規のテスト内容です。".encode('utf-8')
    false_content = "これは非正規のテスト内容です。".encode('utf-8')

    true_file = create_temp_file(true_content)
    false_file = create_temp_file(false_content)
    encrypted_file = os.path.join(tempfile.gettempdir(), "test_encrypted.indet")

    try:
        # テスト1: 暗号化と同一鍵での復号
        try:
            # 暗号化
            key, _ = encrypt_file(true_file, false_file, encrypted_file)

            # 同一鍵での復号
            true_output = os.path.join(tempfile.gettempdir(), "test_true_decrypted.txt")
            decrypt_file(encrypted_file, key, true_output)

            # 結果の検証
            with open(true_output, 'rb') as f:
                decrypted_content = f.read()

            # 正規テキストが含まれるか検証
            true_match = true_content in decrypted_content

            results.add_result(
                "同一鍵での暗号化・復号",
                true_match,
                "暗号化と同一鍵での復号で元のコンテンツが取得できるか"
            )

        except Exception as e:
            results.add_result("同一鍵での暗号化・復号", False, f"例外発生: {str(e)}")

        # テスト2: 異なる鍵での復号
        try:
            # 非正規鍵の生成（元の鍵を少し変更）
            false_key = bytearray(key)
            false_key[0] ^= 0xFF  # 最初のバイトを反転
            false_key = bytes(false_key)

            # 非正規鍵での復号
            false_output = os.path.join(tempfile.gettempdir(), "test_false_decrypted.txt")
            decrypt_file(encrypted_file, false_key, false_output)

            # 結果の検証
            with open(false_output, 'rb') as f:
                false_decrypted = f.read()

            # 非正規テキストが含まれるか検証
            false_match = false_content in false_decrypted

            # 真偽テキストが相互に含まれていないか（コンタミがないか）
            no_contamination = (
                true_content not in false_decrypted and
                false_content not in decrypted_content
            )

            results.add_result(
                "異なる鍵での復号",
                false_match,
                "異なる鍵での復号で非正規コンテンツが取得できるか"
            )

            results.add_result(
                "コンテンツ分離",
                no_contamination,
                "正規/非正規コンテンツが混合していないか"
            )

        except Exception as e:
            results.add_result("異なる鍵での復号", False, f"例外発生: {str(e)}")

        # テスト3: 実行パスの非決定性
        try:
            # 同じ鍵で複数回エンジンを実行し、パスが毎回異なることを確認
            test_key = generate_random_key()
            paths = []

            for i in range(3):
                # 5回エンジンを実行
                engine = create_engine_from_key(test_key, TRUE_PATH)
                engine.run_execution()
                paths.append(tuple(engine.path_manager.path_history))

            # 各実行パスが異なることを確認
            all_different = len(set(paths)) == len(paths)

            results.add_result(
                "実行パスの非決定性",
                all_different,
                "同じ鍵でも毎回異なる実行パスが生成されるか"
            )

        except Exception as e:
            results.add_result("実行パスの非決定性", False, f"例外発生: {str(e)}")

        # テスト4: 異なる鍵での収束性
        try:
            # 異なる鍵で復号した結果、同一パスタイプの場合に類似した状態に収束するか
            similar_paths = []

            # 5つの異なる鍵を生成
            for i in range(5):
                test_key = generate_random_key()
                engine1 = create_engine_from_key(test_key, TRUE_PATH)
                engine1.run_execution()

                engine2 = create_engine_from_key(test_key, TRUE_PATH)  # 同じ鍵、同じパスタイプ
                engine2.run_execution()

                # 最終状態が同じか類似しているか
                final1 = engine1.path_manager.current_state_id
                final2 = engine2.path_manager.current_state_id

                # 最終状態が同じか、または「近い」（±2以内）かを検証
                is_similar = final1 == final2 or abs(final1 - final2) <= 2
                similar_paths.append(is_similar)

            # 80%以上の確率で類似した結果になるかどうか
            good_convergence = sum(similar_paths) >= len(similar_paths) * 0.8

            results.add_result(
                "同一パスタイプの収束性",
                good_convergence,
                "同じ鍵・同じパスタイプで類似状態に収束するか"
            )

        except Exception as e:
            results.add_result("同一パスタイプの収束性", False, f"例外発生: {str(e)}")

        # テスト5: 異なるパスタイプの分離
        try:
            # 同じ鍵で異なるパスタイプの場合に異なる状態に収束するか
            test_key = generate_random_key()

            true_finals = []
            false_finals = []

            for i in range(3):
                # 同じ鍵での異なるパスタイプ
                true_engine = create_engine_from_key(test_key, TRUE_PATH)
                true_engine.run_execution()
                true_finals.append(true_engine.path_manager.current_state_id)

                false_engine = create_engine_from_key(test_key, FALSE_PATH)
                false_engine.run_execution()
                false_finals.append(false_engine.path_manager.current_state_id)

            # TRUE/FALSEパスが明確に分離されているか
            distinct_paths = len(set(true_finals) & set(false_finals)) == 0

            results.add_result(
                "パスタイプの分離",
                distinct_paths,
                "TRUE/FALSEパスが明確に区別されるか"
            )

        except Exception as e:
            results.add_result("パスタイプの分離", False, f"例外発生: {str(e)}")

    finally:
        # テスト用の一時ファイルを削除
        cleanup_temp_file(true_file)
        cleanup_temp_file(false_file)
        # 暗号化ファイルも削除
        try:
            os.unlink(encrypted_file)
        except:
            pass

    # 結果を可視化
    try:
        visualize_test_results(results)
    except Exception as e:
        print(f"結果の可視化に失敗しました: {e}")

    return results


def visualize_test_results(results):
    """テスト結果を可視化"""
    # タイムスタンプを取得
    timestamp = get_timestamp_str()

    # 出力ファイル名
    output_file = os.path.join(TEST_OUTPUT_DIR, f"integration_test_{timestamp}.png")

    # プロットの設定
    plt.figure(figsize=(12, 8))

    # グラフサイズを設定
    ax1 = plt.subplot2grid((2, 3), (0, 0), colspan=1, rowspan=1)
    ax2 = plt.subplot2grid((2, 3), (0, 1), colspan=2, rowspan=1)
    ax3 = plt.subplot2grid((2, 3), (1, 0), colspan=3, rowspan=1)

    # 成功/失敗の円グラフ
    labels = ['成功', '失敗']
    sizes = [results.passed, results.failed]
    colors = ['#4CAF50', '#F44336'] if results.failed == 0 else ['#FFEB3B', '#F44336']
    explode = (0.1, 0) if results.failed == 0 else (0, 0.1)

    ax1.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=90)
    ax1.axis('equal')
    ax1.set_title('テスト結果概要')

    # 成功率の横棒グラフ
    success_rate = results.passed / results.total * 100 if results.total > 0 else 0
    ax2.barh(["成功率"], [success_rate], color='#2196F3')
    ax2.set_xlim(0, 100)
    for i, v in enumerate([success_rate]):
        ax2.text(v + 2, i, f"{v:.1f}%", va='center')
    ax2.set_title('テスト成功率')

    # 各テストの成功/失敗の棒グラフ
    test_names = [r['name'] for r in results.results]
    test_results = [1 if r['passed'] else 0 for r in results.results]

    y_pos = np.arange(len(test_names))
    colors = ['#4CAF50' if res else '#F44336' for res in test_results]

    ax3.barh(y_pos, test_results, align='center', color=colors)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(test_names)
    ax3.invert_yaxis()  # 最初のテストを上に表示
    ax3.set_xticks([0, 1])
    ax3.set_xticklabels(['失敗', '成功'])
    ax3.set_title('各テストの結果')

    # タイトルと情報
    plt.suptitle(f'不確定性転写暗号化方式 - 統合テスト結果', fontsize=16)
    plt.figtext(0.5, 0.01, f'全テスト: {results.total}, 成功: {results.passed}, 失敗: {results.failed}, ' +
                f'成功率: {(results.passed/results.total*100):.1f}% (実行日時: {timestamp})',
                ha='center', fontsize=10)

    # 保存
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(output_file)
    print(f"テスト結果の可視化を保存しました: {output_file}")

    # ファイルの絶対パスを返す
    return os.path.abspath(output_file)


if __name__ == "__main__":
    print("=== 不確定性転写暗号化方式 - 統合テスト ===")
    results = test_encryption_decryption()
    results.print_summary()

    # 終了コードを設定（テスト失敗なら1、成功なら0）
    sys.exit(0 if results.all_passed() else 1)