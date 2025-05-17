"""
不確定性転写暗号化方式 - テスト実行スクリプト

このスクリプトは、StateCapsuleとCapsuleAnalyzerのテストを実行し、
テスト結果および分析結果を視覚化します。
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
import io
import datetime
import random

# プロジェクトルートをインポートパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

# 内部モジュールのインポート
from method_10_indeterministic.state_capsule import StateCapsule, BLOCK_TYPE_SEQUENTIAL, BLOCK_TYPE_INTERLEAVE
from method_10_indeterministic.capsule_analyzer import CapsuleAnalyzer

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = os.path.join(project_root, "test_output")
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)


def run_capsule_tests() -> Dict[str, Any]:
    """
    StateCapsuleとCapsuleAnalyzerのテストを実行し、結果を返す

    Returns:
        Dict[str, Any]: テスト結果
    """
    results = {
        "basic_capsule": test_basic_capsule(),
        "sequential_capsule": test_sequential_capsule(),
        "interleaved_capsule": test_interleaved_capsule(),
        "shuffle_effectiveness": test_shuffle_effectiveness(),
        "analyzer_integration": test_analyzer_integration(),
        "large_data": test_large_data_capsule(),
        "timestamp": datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    }

    # 成功率の計算
    total_tests = len(results) - 1  # timestampを除く
    passed_tests = sum(1 for k, v in results.items() if k != "timestamp" and v.get("success", False))
    results["success_rate"] = (passed_tests / total_tests) * 100 if total_tests > 0 else 0

    # 結果の視覚化
    results["visualization"] = visualize_test_results(results)

    return results


def test_basic_capsule() -> Dict[str, Any]:
    """
    基本的なカプセル化・抽出操作をテストする

    Returns:
        Dict[str, Any]: テスト結果
    """
    try:
        # テストデータ
        true_data = b"This is true data for testing"
        false_data = b"This is false data for testing"

        # StateCapsuleのインスタンス化
        capsule = StateCapsule()

        # カプセル化（シャッフルなし）
        capsule_data = capsule.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            use_shuffle=False
        )

        # 抽出
        extracted_true_data, true_signature = capsule.extract_data(capsule_data, "true")
        extracted_false_data, false_signature = capsule.extract_data(capsule_data, "false")

        # 検証
        true_match = true_data == extracted_true_data
        false_match = false_data == extracted_false_data

        return {
            "success": true_match and false_match,
            "true_match": true_match,
            "false_match": false_match,
            "capsule_size": len(capsule_data),
            "true_signature_valid": hashlib.sha256(true_signature).hexdigest()[:8],
            "false_signature_valid": hashlib.sha256(false_signature).hexdigest()[:8]
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def test_sequential_capsule() -> Dict[str, Any]:
    """
    順次配置モードでのカプセル化をテストする

    Returns:
        Dict[str, Any]: テスト結果
    """
    try:
        # テストデータ
        true_data = b"Sequential true data for testing with some extra content to make it longer"
        false_data = b"Sequential false data with different content from the true data"

        # StateCapsuleのインスタンス化
        capsule = StateCapsule()

        # 順次配置でカプセル化
        capsule_data = capsule.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            use_shuffle=True  # シャッフル有効
        )

        # 抽出
        extracted_true_data, true_signature = capsule.extract_data(capsule_data, "true")
        extracted_false_data, false_signature = capsule.extract_data(capsule_data, "false")

        # 検証
        true_match = true_data == extracted_true_data
        false_match = false_data == extracted_false_data

        # ブロック処理タイプとエントロピーブロックサイズの取得
        block_type = capsule.block_type
        entropy_block_size = capsule.entropy_block_size

        return {
            "success": true_match and false_match,
            "true_match": true_match,
            "false_match": false_match,
            "block_type": block_type,
            "entropy_block_size": entropy_block_size,
            "capsule_size": len(capsule_data),
            "compression_ratio": len(capsule_data) / (len(true_data) + len(false_data))
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def test_interleaved_capsule() -> Dict[str, Any]:
    """
    インターリーブモードでのカプセル化をテストする

    Returns:
        Dict[str, Any]: テスト結果
    """
    try:
        # テストデータ
        true_data = b"Interleaved true data for testing with some extra content"
        false_data = b"Interleaved false data with different content than true"

        # StateCapsuleのインスタンス化
        capsule = StateCapsule()

        # インターリーブ配置でカプセル化
        capsule_data = capsule.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_INTERLEAVE,
            use_shuffle=True  # シャッフル有効
        )

        # 抽出
        extracted_true_data, true_signature = capsule.extract_data(capsule_data, "true")
        extracted_false_data, false_signature = capsule.extract_data(capsule_data, "false")

        # 検証
        true_match = true_data == extracted_true_data
        false_match = false_data == extracted_false_data

        # ブロック処理タイプとエントロピーブロックサイズの取得
        block_type = capsule.block_type
        entropy_block_size = capsule.entropy_block_size

        return {
            "success": true_match and false_match,
            "true_match": true_match,
            "false_match": false_match,
            "block_type": block_type,
            "entropy_block_size": entropy_block_size,
            "capsule_size": len(capsule_data),
            "compression_ratio": len(capsule_data) / (len(true_data) + len(false_data))
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def test_shuffle_effectiveness() -> Dict[str, Any]:
    """
    シャッフル機能の有効性をテストする

    Returns:
        Dict[str, Any]: テスト結果
    """
    try:
        # テストデータ（特徴的なパターンを含む）
        pattern = b"ABABABABABABABABABABABABABABAB"
        true_data = pattern * 10  # 高い規則性を持つデータ
        false_data = pattern * 10  # 高い規則性を持つデータ

        # シャッフルなしのカプセル
        capsule_no_shuffle = StateCapsule()
        capsule_data_no_shuffle = capsule_no_shuffle.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            use_shuffle=False
        )

        # シャッフルありのカプセル
        capsule_with_shuffle = StateCapsule()
        capsule_data_with_shuffle = capsule_with_shuffle.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            use_shuffle=True
        )

        # 両方のデータからエントロピーを計算
        analyzer = CapsuleAnalyzer()
        entropy_no_shuffle = analyzer._calculate_shannon_entropy(capsule_data_no_shuffle)
        entropy_with_shuffle = analyzer._calculate_shannon_entropy(capsule_data_with_shuffle)

        # バイト分布分析
        byte_counts_no_shuffle = Counter(capsule_data_no_shuffle)
        byte_counts_with_shuffle = Counter(capsule_data_with_shuffle)

        # 分散を計算
        variance_no_shuffle = np.var(list(byte_counts_no_shuffle.values()))
        variance_with_shuffle = np.var(list(byte_counts_with_shuffle.values()))

        # データサイズで正規化
        normalized_variance_no_shuffle = variance_no_shuffle / len(capsule_data_no_shuffle)
        normalized_variance_with_shuffle = variance_with_shuffle / len(capsule_data_with_shuffle)

        # エントロピー向上率
        entropy_improvement = ((entropy_with_shuffle - entropy_no_shuffle) / entropy_no_shuffle) * 100 if entropy_no_shuffle > 0 else 0

        # シャッフル後のデータを視覚化
        visualization_file = _visualize_byte_distribution(
            capsule_data_no_shuffle,
            capsule_data_with_shuffle
        )

        return {
            "success": entropy_with_shuffle > entropy_no_shuffle,
            "entropy_no_shuffle": entropy_no_shuffle,
            "entropy_with_shuffle": entropy_with_shuffle,
            "entropy_improvement_percent": entropy_improvement,
            "normalized_variance_no_shuffle": normalized_variance_no_shuffle,
            "normalized_variance_with_shuffle": normalized_variance_with_shuffle,
            "visualization_file": visualization_file
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def test_analyzer_integration() -> Dict[str, Any]:
    """
    CapsuleAnalyzerとの統合テストを行う

    Returns:
        Dict[str, Any]: テスト結果
    """
    try:
        # より複雑なデータを生成
        rng = random.Random(42)  # 再現性のため固定シード
        true_data = bytes(rng.randint(0, 255) for _ in range(30000))
        false_data = bytes(rng.randint(0, 255) for _ in range(30000))

        # 異なるブロック処理タイプとエントロピーブロックサイズでカプセル化
        sequential_capsule = StateCapsule()
        interleave_capsule = StateCapsule()

        sequential_data = sequential_capsule.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size=32,
            use_shuffle=True
        )

        interleave_data = interleave_capsule.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_INTERLEAVE,
            entropy_block_size=32,
            use_shuffle=True
        )

        # 抽出テスト
        sequential_true, _ = sequential_capsule.extract_data(sequential_data, "true")
        sequential_false, _ = sequential_capsule.extract_data(sequential_data, "false")

        interleave_true, _ = interleave_capsule.extract_data(interleave_data, "true")
        interleave_false, _ = interleave_capsule.extract_data(interleave_data, "false")

        # 検証
        sequential_match = (true_data == sequential_true) and (false_data == sequential_false)
        interleave_match = (true_data == interleave_true) and (false_data == interleave_false)

        # 解析
        analyzer = CapsuleAnalyzer()
        sequential_analysis = analyzer.analyze_capsule(sequential_data)
        interleave_analysis = analyzer.analyze_capsule(interleave_data)

        # 解析耐性レベル
        sequential_resistance = analyzer.get_resistance_level()
        analyzer.analyze_capsule(interleave_data)
        interleave_resistance = analyzer.get_resistance_level()

        # 分析結果の視覚化
        visualization_file = _visualize_analysis_comparison(
            sequential_analysis,
            interleave_analysis
        )

        return {
            "success": sequential_match and interleave_match,
            "sequential_match": sequential_match,
            "interleave_match": interleave_match,
            "sequential_resistance": sequential_resistance,
            "sequential_resistance_score": sequential_analysis["resistance_score"]["total"],
            "interleave_resistance": interleave_resistance,
            "interleave_resistance_score": interleave_analysis["resistance_score"]["total"],
            "visualization_file": visualization_file
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def test_large_data_capsule() -> Dict[str, Any]:
    """
    大きなデータのカプセル化テスト

    Returns:
        Dict[str, Any]: テスト結果
    """
    try:
        # 大きめのテストデータ生成（～200KB）
        rng = random.Random(123)  # 再現性のため固定シード
        true_data = bytes(rng.randint(0, 255) for _ in range(200000))
        false_data = bytes(rng.randint(0, 255) for _ in range(190000))

        # メモリ使用量と時間計測の準備
        start_time = time.time()
        import psutil
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / 1024 / 1024  # MB

        # カプセル化
        capsule = StateCapsule()
        capsule_data = capsule.create_capsule(
            true_data,
            false_data,
            block_type=BLOCK_TYPE_SEQUENTIAL,
            entropy_block_size=64,  # 大きめのブロックサイズ
            use_shuffle=True
        )

        # 処理時間とメモリ使用量
        time_taken = time.time() - start_time
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = memory_after - memory_before

        # 抽出と検証
        extract_start = time.time()
        extracted_true_data, _ = capsule.extract_data(capsule_data, "true")
        extracted_false_data, _ = capsule.extract_data(capsule_data, "false")
        extract_time = time.time() - extract_start

        # 検証
        true_match = true_data == extracted_true_data
        false_match = false_data == extracted_false_data

        # キャプスル化効率（圧縮率の評価）
        raw_size = len(true_data) + len(false_data)
        capsule_size = len(capsule_data)
        expansion_ratio = capsule_size / raw_size

        return {
            "success": true_match and false_match,
            "true_match": true_match,
            "false_match": false_match,
            "true_data_size": len(true_data),
            "false_data_size": len(false_data),
            "capsule_size": capsule_size,
            "expansion_ratio": expansion_ratio,
            "creation_time": time_taken,
            "extraction_time": extract_time,
            "memory_increase_mb": memory_increase
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def visualize_test_results(results: Dict[str, Any]) -> str:
    """
    テスト結果を視覚化する

    Args:
        results: テスト結果辞書

    Returns:
        str: 生成された画像ファイルのパス
    """
    # タイムスタンプを含む出力ファイル名
    timestamp = results["timestamp"]
    output_file = os.path.join(TEST_OUTPUT_DIR, f"state_capsule_test_{timestamp}.png")

    # プロットの設定
    plt.figure(figsize=(12, 10))

    # グラフのレイアウト設定
    grid = plt.GridSpec(3, 3, wspace=0.4, hspace=0.3)

    # テスト成功率の円グラフ
    success_rate = results["success_rate"]
    ax1 = plt.subplot(grid[0, 0])
    ax1.pie(
        [success_rate, 100 - success_rate],
        labels=["成功", "失敗"],
        colors=["#4CAF50", "#F44336"] if success_rate == 100 else ["#FFEB3B", "#F44336"],
        autopct='%1.1f%%',
        startangle=90
    )
    ax1.set_title('テスト成功率')

    # カプセルサイズの棒グラフ
    ax2 = plt.subplot(grid[0, 1:])
    test_names = ["基本カプセル", "順次配置", "インターリーブ", "大容量"]
    capsule_sizes = [
        results["basic_capsule"].get("capsule_size", 0),
        results["sequential_capsule"].get("capsule_size", 0),
        results["interleaved_capsule"].get("capsule_size", 0),
        results["large_data"].get("capsule_size", 0) / 1000  # KB単位
    ]
    ax2.bar(test_names, capsule_sizes, color="#2196F3")
    ax2.set_ylabel('カプセルサイズ (バイト/KB)')
    ax2.set_title('各テストのカプセルサイズ')
    # 最後の項目のみ単位を変更
    for i, size in enumerate(capsule_sizes):
        if i == len(capsule_sizes) - 1:
            ax2.text(i, size + max(capsule_sizes) * 0.05, f"{size:.1f}KB", ha='center')
        else:
            ax2.text(i, size + max(capsule_sizes) * 0.05, f"{size}", ha='center')

    # エントロピー比較（シャッフル効果）
    ax3 = plt.subplot(grid[1, :])
    if "shuffle_effectiveness" in results and results["shuffle_effectiveness"].get("success", False):
        shuffle_data = results["shuffle_effectiveness"]
        entropy_labels = ["シャッフルなし", "シャッフルあり"]
        entropy_values = [
            shuffle_data.get("entropy_no_shuffle", 0),
            shuffle_data.get("entropy_with_shuffle", 0)
        ]
        ax3.bar(entropy_labels, entropy_values, color=["#FF9800", "#4CAF50"])
        ax3.set_ylabel('エントロピー値')
        ax3.set_title('シャッフル効果の比較')
        for i, v in enumerate(entropy_values):
            ax3.text(i, v + 0.1, f"{v:.2f}", ha='center')

        # 改善率の表示
        improvement = shuffle_data.get("entropy_improvement_percent", 0)
        ax3.text(0.5, max(entropy_values) * 1.2,
                f"エントロピー向上率: {improvement:.2f}%",
                ha='center', fontsize=12, bbox=dict(facecolor='yellow', alpha=0.5))
    else:
        ax3.text(0.5, 0.5, "シャッフル効果テストのデータがありません",
                ha='center', va='center', fontsize=12)

    # 解析耐性スコアの比較
    ax4 = plt.subplot(grid[2, :])
    if "analyzer_integration" in results and results["analyzer_integration"].get("success", False):
        analyzer_data = results["analyzer_integration"]
        resistance_labels = ["順次配置方式", "インターリーブ方式"]
        resistance_scores = [
            analyzer_data.get("sequential_resistance_score", 0),
            analyzer_data.get("interleave_resistance_score", 0)
        ]

        # スコアの内訳を積み上げ棒グラフで表示
        bar_width = 0.35
        component_names = ["エントロピー", "分布均一性", "ブロック構造"]
        sequential_components = [3.0, 3.0, 4.0]  # ダミーデータ
        interleave_components = [3.0, 3.0, 4.0]  # ダミーデータ

        # 棒グラフの位置
        r1 = np.arange(len(resistance_labels))

        # 積み上げ棒グラフ描画
        ax4.bar(r1, resistance_scores, bar_width, color="#673AB7")

        # ラベルと凡例
        ax4.set_xticks(r1)
        ax4.set_xticklabels(resistance_labels)
        ax4.set_ylabel('解析耐性スコア (0-10)')
        ax4.set_title('カプセル方式別の解析耐性スコア比較')
        ax4.set_ylim(0, 10)  # スコアは0-10の範囲

        # スコア表示
        for i, score in enumerate(resistance_scores):
            ax4.text(i, score + 0.3, f"{score:.1f}", ha='center')
            # 耐性レベルも表示
            level = analyzer_data.get(f"sequential_resistance" if i == 0 else "interleave_resistance", "不明")
            ax4.text(i, score / 2, f"耐性: {level}", ha='center', color='white', fontweight='bold')
    else:
        ax4.text(0.5, 0.5, "解析耐性テストのデータがありません",
                ha='center', va='center', fontsize=12)

    # タイトルと情報
    plt.suptitle('不確定性転写暗号化方式 - カプセル化テスト結果', fontsize=16)
    plt.figtext(0.5, 0.01,
                f'テスト実施日時: {timestamp}  |  成功率: {success_rate:.1f}%',
                ha='center', fontsize=10)

    # 保存
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(output_file)
    print(f"テスト結果の可視化を保存しました: {output_file}")

    return output_file


def _visualize_byte_distribution(data_no_shuffle: bytes, data_with_shuffle: bytes) -> str:
    """
    シャッフル前後のバイト分布を視覚化する

    Args:
        data_no_shuffle: シャッフルなしのデータ
        data_with_shuffle: シャッフルありのデータ

    Returns:
        str: 生成された画像ファイルのパス
    """
    # タイムスタンプを含む出力ファイル名
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(TEST_OUTPUT_DIR, f"byte_distribution_comparison_{timestamp}.png")

    # バイト分布のカウント
    count_no_shuffle = Counter(data_no_shuffle)
    count_with_shuffle = Counter(data_with_shuffle)

    # 分布データの準備
    all_bytes = list(range(256))
    values_no_shuffle = [count_no_shuffle.get(b, 0) for b in all_bytes]
    values_with_shuffle = [count_with_shuffle.get(b, 0) for b in all_bytes]

    # 表示用にデータを間引く
    step = 8  # 8バイト毎に表示
    x_ticks = all_bytes[::step]

    # プロット
    plt.figure(figsize=(14, 6))

    # シャッフルなしの分布
    plt.subplot(1, 2, 1)
    plt.bar(all_bytes, values_no_shuffle, color='blue', alpha=0.7)
    plt.title('シャッフルなしのバイト分布')
    plt.xlabel('バイト値')
    plt.ylabel('出現頻度')
    plt.xticks(x_ticks)
    plt.grid(True, alpha=0.3)

    # シャッフルありの分布
    plt.subplot(1, 2, 2)
    plt.bar(all_bytes, values_with_shuffle, color='green', alpha=0.7)
    plt.title('シャッフルありのバイト分布')
    plt.xlabel('バイト値')
    plt.ylabel('出現頻度')
    plt.xticks(x_ticks)
    plt.grid(True, alpha=0.3)

    # 保存
    plt.tight_layout()
    plt.savefig(output_file)

    return output_file


def _visualize_analysis_comparison(sequential_analysis: Dict[str, Any], interleave_analysis: Dict[str, Any]) -> str:
    """
    順次配置とインターリーブのカプセル分析結果を比較する可視化

    Args:
        sequential_analysis: 順次配置の分析結果
        interleave_analysis: インターリーブの分析結果

    Returns:
        str: 生成された画像ファイルのパス
    """
    # タイムスタンプを含む出力ファイル名
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(TEST_OUTPUT_DIR, f"capsule_analysis_comparison_{timestamp}.png")

    # プロット
    plt.figure(figsize=(14, 10))

    # 解析耐性スコアの比較（レーダーチャート）
    plt.subplot(2, 2, 1, polar=True)

    # スコアの要素
    categories = ['エントロピー', '分布均一性', 'ブロック構造']
    N = len(categories)

    # 各方式のスコア
    sequential_scores = [
        sequential_analysis["resistance_score"]["entropy_score"],
        sequential_analysis["resistance_score"]["distribution_score"],
        sequential_analysis["resistance_score"]["block_score"]
    ]

    interleave_scores = [
        interleave_analysis["resistance_score"]["entropy_score"],
        interleave_analysis["resistance_score"]["distribution_score"],
        interleave_analysis["resistance_score"]["block_score"]
    ]

    # 角度の計算
    angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
    angles += angles[:1]  # 閉じた図形にするため最初の点を追加

    # スコアを閉じた図形にする
    sequential_scores += sequential_scores[:1]
    interleave_scores += interleave_scores[:1]

    # プロット描画
    plt.polar(angles, sequential_scores, 'b-', linewidth=2, label='順次配置')
    plt.polar(angles, interleave_scores, 'g-', linewidth=2, label='インターリーブ')
    plt.fill(angles, sequential_scores, 'b', alpha=0.1)
    plt.fill(angles, interleave_scores, 'g', alpha=0.1)

    # ラベル配置
    plt.thetagrids(np.degrees(angles[:-1]), categories)
    plt.ylim(0, 4)  # スコアの最大値に合わせる
    plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    plt.title('解析耐性スコアの比較')

    # エントロピーの比較（棒グラフ）
    plt.subplot(2, 2, 2)
    labels = ['順次配置', 'インターリーブ']
    entropy_values = [
        sequential_analysis["entropy_analysis"]["normalized_entropy"],
        interleave_analysis["entropy_analysis"]["normalized_entropy"]
    ]
    plt.bar(labels, entropy_values, color=['blue', 'green'])
    plt.ylabel('正規化エントロピー')
    plt.title('カプセル方式別のエントロピー比較')
    plt.ylim(0, 1)  # 正規化エントロピーは0-1

    # ブロック類似性の比較
    plt.subplot(2, 2, 3)
    similarity_values = [
        sequential_analysis["block_analysis"]["avg_block_similarity"],
        interleave_analysis["block_analysis"]["avg_block_similarity"]
    ]
    plt.bar(labels, similarity_values, color=['blue', 'green'])
    plt.ylabel('平均ブロック類似性')
    plt.title('ブロック間の類似性比較')
    plt.ylim(0, 1)  # 類似性は0-1

    # 総合スコアの比較
    plt.subplot(2, 2, 4)
    total_scores = [
        sequential_analysis["resistance_score"]["total"],
        interleave_analysis["resistance_score"]["total"]
    ]
    colors = ['blue', 'green']
    plt.barh(labels, total_scores, color=colors)
    plt.xlabel('総合解析耐性スコア')
    plt.title('カプセル方式別の総合スコア')
    plt.xlim(0, 10)  # 総合スコアは0-10

    # 各バーにスコアを表示
    for i, score in enumerate(total_scores):
        plt.text(score + 0.1, i, f"{score:.2f}", va='center')

    # 保存
    plt.tight_layout()
    plt.savefig(output_file)

    return output_file


if __name__ == "__main__":
    print("=== 不確定性転写暗号化方式 - カプセル化テスト ===")

    results = run_capsule_tests()

    # 結果の表示
    print(f"\n-- テスト結果サマリー --")
    print(f"テスト実施日時: {results['timestamp']}")
    print(f"成功率: {results['success_rate']:.1f}%")
    print("\n各テストの結果:")

    for test_name, test_results in results.items():
        if test_name not in ["timestamp", "success_rate", "visualization"]:
            success = test_results.get("success", False)
            status = "✅ 成功" if success else "❌ 失敗"
            print(f"- {test_name}: {status}")

            if not success and "error" in test_results:
                print(f"  エラー: {test_results['error']}")

    print(f"\n詳細な視覚化結果: {results['visualization']}")

    # 終了コード設定
    sys.exit(0 if results["success_rate"] == 100 else 1)