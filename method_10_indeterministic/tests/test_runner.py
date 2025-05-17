"""
不確定性転写暗号化方式のテストランナー

StateCapsuleとCapsuleAnalyzerのテストを実行して結果を表示します。
"""

import os
import sys
import hashlib
import time
import random
import matplotlib
matplotlib.use('Agg')  # GUIを使用せずにプロットを保存するため
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Tuple, Optional, Any

# プロジェクトのルートディレクトリをインポートパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, project_root)

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = os.path.join(project_root, "test_output")
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

# テスト対象のクラスをインポート
try:
    from state_capsule import StateCapsule, BLOCK_TYPE_SEQUENTIAL, BLOCK_TYPE_INTERLEAVE
    from capsule_analyzer import CapsuleAnalyzer
except ImportError:
    try:
        from method_10_indeterministic.state_capsule import StateCapsule, BLOCK_TYPE_SEQUENTIAL, BLOCK_TYPE_INTERLEAVE
        from method_10_indeterministic.capsule_analyzer import CapsuleAnalyzer
    except ImportError:
        print("エラー: StateCapsuleまたはCapsuleAnalyzerクラスをインポートできません。")
        print("プロジェクトのルートディレクトリから実行してください。")
        sys.exit(1)

# テスト関数
def test_state_capsule_basic():
    """基本的なStateCapsuleのテスト"""
    print("\n[基本的な状態カプセル化テスト]")

    # テストデータ
    key = os.urandom(32)
    salt = os.urandom(16)
    true_data = "これは正規パスのメッセージです。正しい鍵で表示されます。".encode('utf-8') * 3
    false_data = "これは非正規パスのメッセージです。間違った鍵で表示されます。".encode('utf-8') * 2

    # カプセル化と抽出のテスト
    capsule_obj = StateCapsule()

    # シーケンシャル方式でカプセル化
    capsule_sequential = capsule_obj.create_capsule(
        true_data,
        false_data,
        BLOCK_TYPE_SEQUENTIAL,
        32,
        True
    )

    # 正規パスでの抽出
    extracted_true, _ = capsule_obj.extract_data(capsule_sequential, "true")
    # 非正規パスでの抽出
    extracted_false, _ = capsule_obj.extract_data(capsule_sequential, "false")

    # 検証
    true_success = extracted_true == true_data
    false_success = extracted_false == false_data

    print(f"シーケンシャル方式:")
    print(f"  - 正規データ復元: {'成功' if true_success else '失敗'}")
    print(f"  - 非正規データ復元: {'成功' if false_success else '失敗'}")
    print(f"  - カプセルサイズ: {len(capsule_sequential)} バイト")

    # インターリーブ方式でカプセル化
    capsule_obj.block_type = BLOCK_TYPE_INTERLEAVE
    capsule_interleave = capsule_obj.create_capsule(
        true_data,
        false_data,
        BLOCK_TYPE_INTERLEAVE,
        32,
        True
    )

    # 正規パスでの抽出
    extracted_true_interleave, _ = capsule_obj.extract_data(capsule_interleave, "true")
    # 非正規パスでの抽出
    extracted_false_interleave, _ = capsule_obj.extract_data(capsule_interleave, "false")

    # 検証
    true_success_interleave = extracted_true_interleave == true_data
    false_success_interleave = extracted_false_interleave == false_data

    print(f"インターリーブ方式:")
    print(f"  - 正規データ復元: {'成功' if true_success_interleave else '失敗'}")
    print(f"  - 非正規データ復元: {'成功' if false_success_interleave else '失敗'}")
    print(f"  - カプセルサイズ: {len(capsule_interleave)} バイト")

    return {
        "sequential": {
            "true_success": true_success,
            "false_success": false_success,
            "size": len(capsule_sequential)
        },
        "interleave": {
            "true_success": true_success_interleave,
            "false_success": false_success_interleave,
            "size": len(capsule_interleave)
        }
    }

def test_capsule_analyzer():
    """CapsuleAnalyzerのテスト"""
    print("\n[カプセル解析テスト]")

    # テストデータ
    key = os.urandom(32)
    salt = os.urandom(16)
    true_data = os.urandom(1024)  # ランダムデータ
    false_data = os.urandom(1024)

    capsule_obj = StateCapsule()

    # 異なる方式でカプセル化
    capsule_sequential = capsule_obj.create_capsule(true_data, false_data, BLOCK_TYPE_SEQUENTIAL, 32, True)
    capsule_interleave = capsule_obj.create_capsule(true_data, false_data, BLOCK_TYPE_INTERLEAVE, 32, True)

    # 解析
    analyzer = CapsuleAnalyzer()

    # シーケンシャル方式の解析
    seq_results = analyzer.analyze_capsule(capsule_sequential)

    # インターリーブ方式の解析
    int_results = analyzer.analyze_capsule(capsule_interleave)

    # 結果表示
    print("解析結果:")
    print(f"シーケンシャル方式:")
    print(f"  - エントロピー: {seq_results['entropy_analysis']['shannon_entropy']:.4f} ビット/バイト")
    print(f"  - 解析耐性スコア: {seq_results['resistance_score']['total']:.2f}/10.0")

    print(f"インターリーブ方式:")
    print(f"  - エントロピー: {int_results['entropy_analysis']['shannon_entropy']:.4f} ビット/バイト")
    print(f"  - 解析耐性スコア: {int_results['resistance_score']['total']:.2f}/10.0")

    # 結果の辞書に変換
    seq_dict = {
        "entropy": {
            "shannon": seq_results['entropy_analysis']['shannon_entropy'],
            "normalized": seq_results['entropy_analysis']['normalized_entropy']
        },
        "overall": {
            "analysis_quality_score": seq_results['resistance_score']['total']
        },
        "autocorrelation": {
            "independence_score": 10.0 * (1.0 - abs(seq_results['block_analysis']['avg_block_similarity'])) if 'avg_block_similarity' in seq_results['block_analysis'] else 8.0
        }
    }

    int_dict = {
        "entropy": {
            "shannon": int_results['entropy_analysis']['shannon_entropy'],
            "normalized": int_results['entropy_analysis']['normalized_entropy']
        },
        "overall": {
            "analysis_quality_score": int_results['resistance_score']['total']
        },
        "autocorrelation": {
            "independence_score": 10.0 * (1.0 - abs(int_results['block_analysis']['avg_block_similarity'])) if 'avg_block_similarity' in int_results['block_analysis'] else 8.0
        }
    }

    return {
        "sequential": seq_dict,
        "interleave": int_dict
    }

def visualize_test_results(basic_results, analyzer_results):
    """テスト結果の可視化"""
    print("\n[テスト結果の可視化]")

    # 1. 基本テスト結果の可視化（成功率、サイズ比較）
    plt.figure(figsize=(12, 8))

    # 1.1 成功率
    plt.subplot(2, 2, 1)
    methods = ['Sequential', 'Interleave']
    true_success = [
        int(basic_results['sequential']['true_success']),
        int(basic_results['interleave']['true_success'])
    ]
    false_success = [
        int(basic_results['sequential']['false_success']),
        int(basic_results['interleave']['false_success'])
    ]

    x = np.arange(len(methods))
    width = 0.35

    plt.bar(x - width/2, true_success, width, label='正規パス')
    plt.bar(x + width/2, false_success, width, label='非正規パス')
    plt.title('カプセル化・抽出の成功率')
    plt.xlabel('方式')
    plt.ylabel('成功 (1=成功, 0=失敗)')
    plt.xticks(x, methods)
    plt.ylim(0, 1.1)
    plt.legend()

    # 1.2 カプセルサイズ比較
    plt.subplot(2, 2, 2)
    sizes = [
        basic_results['sequential']['size'],
        basic_results['interleave']['size']
    ]
    plt.bar(methods, sizes, color='skyblue')
    plt.title('カプセルサイズ比較')
    plt.xlabel('方式')
    plt.ylabel('バイト数')
    for i, v in enumerate(sizes):
        plt.text(i, v + 10, str(v), ha='center')

    # 2. 解析結果の可視化

    # 2.1 エントロピー比較
    plt.subplot(2, 2, 3)
    entropy_values = [
        analyzer_results['sequential']['entropy']['shannon'],
        analyzer_results['interleave']['entropy']['shannon']
    ]
    plt.bar(methods, entropy_values, color='lightgreen')
    plt.title('エントロピー比較')
    plt.xlabel('方式')
    plt.ylabel('エントロピー (ビット/バイト)')
    plt.ylim(0, 8.1)  # 最大エントロピーは8ビット
    for i, v in enumerate(entropy_values):
        plt.text(i, v + 0.1, f"{v:.2f}", ha='center')

    # 2.2 解析耐性スコア
    plt.subplot(2, 2, 4)
    scores = [
        analyzer_results['sequential']['overall']['analysis_quality_score'],
        analyzer_results['interleave']['overall']['analysis_quality_score']
    ]
    plt.bar(methods, scores, color='salmon')
    plt.title('解析耐性スコア比較')
    plt.xlabel('方式')
    plt.ylabel('スコア (0-10)')
    plt.ylim(0, 10.1)
    for i, v in enumerate(scores):
        plt.text(i, v + 0.1, f"{v:.2f}", ha='center')

    plt.tight_layout()

    # 画像保存
    timestamp = int(time.time())
    image_path = os.path.join(TEST_OUTPUT_DIR, f"state_capsule_test_{timestamp}.png")
    plt.savefig(image_path)
    print(f"テスト結果のグラフを保存しました: {image_path}")

    return image_path

def visualize_byte_distribution(capsule_data, method_name):
    """バイト分布の可視化"""
    analyzer = CapsuleAnalyzer()
    # 直接analyze_capsule()を呼び出すが、結果は使用しなくても良い
    # 結果はヒストグラム生成のために手動で計算する
    analyzer.analyze_capsule(capsule_data)

    # バイト分布の計算
    hist_data = {i: 0 for i in range(256)}
    for b in capsule_data:
        hist_data[b] = hist_data.get(b, 0) + 1

    # プロット
    plt.figure(figsize=(12, 6))
    plt.bar(hist_data.keys(), hist_data.values(), width=1.0, color='blue', alpha=0.6)
    plt.title(f'{method_name}方式のバイト分布')
    plt.xlabel('バイト値 (0-255)')
    plt.ylabel('出現頻度')
    plt.xlim(0, 255)

    # 理想的な均一分布を重ねてプロット
    total_bytes = len(capsule_data)
    ideal_freq = total_bytes / 256
    plt.axhline(y=ideal_freq, color='r', linestyle='--', label='理想的な均一分布')
    plt.legend()

    plt.tight_layout()

    # 画像保存
    timestamp = int(time.time())
    image_path = os.path.join(TEST_OUTPUT_DIR, f"byte_distribution_{method_name}_{timestamp}.png")
    plt.savefig(image_path)
    print(f"{method_name}方式のバイト分布グラフを保存しました: {image_path}")

    return image_path

def visualize_capsule_analysis_comparison():
    """カプセル解析結果の比較可視化"""
    # テストデータ生成
    print("\n[カプセル解析比較]")

    key = os.urandom(32)
    salt = os.urandom(16)

    # 通常のテキストデータ
    text_data = "これは不確定性転写暗号化方式のテストデータです。".encode('utf-8') * 20

    # 低エントロピーデータ（パターンの繰り返し）
    low_entropy_data = b"ABCDEFG" * 200

    capsule_obj = StateCapsule()

    # 各方式でカプセル化
    text_sequential = capsule_obj.create_capsule(text_data, low_entropy_data, BLOCK_TYPE_SEQUENTIAL, 32, False)
    text_sequential_shuffled = capsule_obj.create_capsule(text_data, low_entropy_data, BLOCK_TYPE_SEQUENTIAL, 32, True)
    text_interleave = capsule_obj.create_capsule(text_data, low_entropy_data, BLOCK_TYPE_INTERLEAVE, 32, True)

    # 解析
    analyzer = CapsuleAnalyzer()

    results = {}
    for name, data in [
        ("テキスト（順次・シャッフルなし）", text_sequential),
        ("テキスト（順次・シャッフルあり）", text_sequential_shuffled),
        ("テキスト（インターリーブ）", text_interleave),
    ]:
        # 直接analyze_capsuleメソッドにデータを渡す
        result = analyzer.analyze_capsule(data)
        results[name] = result

    # 結果表示
    for name, result in results.items():
        entropy = result['entropy_analysis']['shannon_entropy']
        score = result['resistance_score']['total']
        print(f"{name}: エントロピー={entropy:.2f}, スコア={score:.2f}")

    # 可視化
    plt.figure(figsize=(12, 10))

    # スコア比較
    plt.subplot(2, 1, 1)
    names = list(results.keys())
    scores = [results[name]['resistance_score']['total'] for name in names]
    plt.bar(names, scores, color=['lightblue', 'skyblue', 'royalblue'])
    plt.title('解析耐性スコア比較')
    plt.ylabel('スコア (0-10)')
    plt.ylim(0, 10.1)
    plt.xticks(rotation=15, ha='right')
    for i, v in enumerate(scores):
        plt.text(i, v + 0.1, f"{v:.2f}", ha='center')

    # エントロピー比較
    plt.subplot(2, 1, 2)
    entropy_values = [results[name]['entropy_analysis']['shannon_entropy'] for name in names]
    normalized_values = [results[name]['entropy_analysis']['normalized_entropy'] for name in names]

    x = np.arange(len(names))
    width = 0.35

    plt.bar(x - width/2, entropy_values, width, label='エントロピー (ビット/バイト)', color='lightgreen')
    plt.bar(x + width/2, normalized_values, width, label='正規化エントロピー (0-1)', color='green')
    plt.title('エントロピー値比較')
    plt.xticks(x, names, rotation=15, ha='right')
    plt.legend()
    plt.tight_layout()

    # 画像保存
    timestamp = int(time.time())
    image_path = os.path.join(TEST_OUTPUT_DIR, f"capsule_analysis_comparison_{timestamp}.png")
    plt.savefig(image_path)
    print(f"解析比較グラフを保存しました: {image_path}")

    return image_path, results

def run_all_tests():
    """すべてのテストを実行"""
    print("===== 不確定性転写暗号化方式テスト =====")

    try:
        # 基本テスト
        basic_results = test_state_capsule_basic()

        # 解析テスト
        analyzer_results = test_capsule_analyzer()

        # テスト結果の可視化
        visualize_test_results(basic_results, analyzer_results)

        # バイト分布の可視化
        # テストデータ生成
        key = os.urandom(32)
        salt = os.urandom(16)
        data = "日本語も含むテストデータです。不確定性転写暗号化方式のテスト。".encode('utf-8') * 20
        data2 = os.urandom(len(data))

        capsule_obj = StateCapsule()
        sequential_capsule = capsule_obj.create_capsule(data, data2, BLOCK_TYPE_SEQUENTIAL, 32, True)
        interleave_capsule = capsule_obj.create_capsule(data, data2, BLOCK_TYPE_INTERLEAVE, 32, True)

        visualize_byte_distribution(sequential_capsule, "sequential")
        visualize_byte_distribution(interleave_capsule, "interleave")

        # カプセル解析比較
        visualize_capsule_analysis_comparison()

        print("\n✅ すべてのテストが正常に完了しました")
        return True

    except Exception as e:
        print(f"\n❌ テスト実行中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    run_all_tests()