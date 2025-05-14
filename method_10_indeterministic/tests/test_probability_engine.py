#!/usr/bin/env python3
"""
確率的実行エンジンのテスト

不確定性転写暗号化方式の確率的実行エンジンをテストします。
"""

import os
import sys
import time
import hashlib
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List, Any, Tuple

# プロジェクトルートを追加
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)

# テスト対象のモジュールをインポート
sys.path.append(parent_dir)
from probability_engine import (
    ProbabilityController, ProbabilisticExecutionEngine,
    TRUE_PATH, FALSE_PATH, create_engine_from_key,
    obfuscate_execution_path, generate_anti_analysis_noise
)


def test_basic_execution():
    """
    基本的な実行エンジンのテスト
    """
    # テスト鍵の生成
    test_key = os.urandom(32)
    print(f"テスト鍵: {test_key.hex()[:16]}...")

    # 各パスタイプでエンジンを作成・実行
    results = {}

    for path_type in [TRUE_PATH, FALSE_PATH]:
        print(f"\n=== {path_type} パスの実行 ===")

        # エンジンの作成
        engine = create_engine_from_key(test_key, path_type)

        # 実行
        path = engine.run_execution()

        # 結果の表示
        print(f"初期状態: {path[0]}")
        print(f"最終状態: {path[-1]}")
        print(f"パス長: {len(path)}")
        print(f"パス: {path}")

        # 実行署名の取得
        signature = engine.get_execution_signature()
        print(f"実行署名: {signature.hex()[:16]}...")

        # 実行統計の取得
        stats = engine.path_manager.get_path_statistics()
        print(f"収束: {'あり' if stats.get('is_converged', False) else 'なし'}")

        # エンジン状態の取得
        state = engine.get_engine_state()
        print(f"バイアス強度: {state['bias_strength']:.4f}")

        # 結果を保存
        results[path_type] = {
            "path": path,
            "signature": signature,
            "stats": stats,
            "state": state
        }

    # パスタイプによる違いの検証
    true_final = results[TRUE_PATH]["path"][-1]
    false_final = results[FALSE_PATH]["path"][-1]

    print("\n=== 検証結果 ===")
    print(f"TRUE パス最終状態: {true_final}")
    print(f"FALSE パス最終状態: {false_final}")
    print(f"異なる最終状態: {'はい' if true_final != false_final else 'いいえ'}")

    # 結果の評価
    assert true_final != false_final, "TRUE/FALSEパスは異なる最終状態に収束する必要があります"

    return results


def test_convergence():
    """
    実行パスの収束性をテスト
    """
    # テスト鍵の生成
    test_key = os.urandom(32)
    print("\n=== 収束性検証（複数回実行） ===")

    iterations = 10
    true_finals = []
    false_finals = []

    for i in range(iterations):
        # TRUEパス
        true_engine = create_engine_from_key(test_key, TRUE_PATH)
        true_path = true_engine.run_execution()
        true_finals.append(true_path[-1])

        # FALSEパス
        false_engine = create_engine_from_key(test_key, FALSE_PATH)
        false_path = false_engine.run_execution()
        false_finals.append(false_path[-1])

    print(f"TRUE パス最終状態一覧: {true_finals}")
    print(f"FALSE パス最終状態一覧: {false_finals}")

    # 収束性の評価（同じ状態が複数回出現するか）
    true_convergence = len(set(true_finals)) < iterations
    false_convergence = len(set(false_finals)) < iterations

    print(f"TRUEパス収束傾向: {'あり' if true_convergence else 'なし'}")
    print(f"FALSEパス収束傾向: {'あり' if false_convergence else 'なし'}")

    # TRUEとFALSEで異なる状態に収束することを確認
    true_common = max(set(true_finals), key=true_finals.count)
    false_common = max(set(false_finals), key=false_finals.count)

    print(f"TRUE最頻出状態: {true_common}")
    print(f"FALSE最頻出状態: {false_common}")

    # 結果の評価
    assert true_convergence, "TRUEパスは収束傾向を示す必要があります"
    assert false_convergence, "FALSEパスは収束傾向を示す必要があります"
    assert true_common != false_common, "TRUE/FALSEパスは異なる状態に収束する必要があります"

    return {"true_finals": true_finals, "false_finals": false_finals}


def test_path_nondeterminism():
    """
    実行パスの非決定性をテスト
    """
    # テスト鍵の生成
    test_key = os.urandom(32)
    print("\n=== 実行パスの非決定性検証 ===")

    # 同じパラメータで複数回実行
    iterations = 5
    path_histories = []

    for i in range(iterations):
        engine = create_engine_from_key(test_key, TRUE_PATH)
        engine.run_execution()
        path_histories.append(engine.path_manager.path_history)

    # すべてのパスが同一かチェック
    all_same = all(tuple(path) == tuple(path_histories[0]) for path in path_histories)
    print(f"すべてのパスが同一: {'はい' if all_same else 'いいえ'}")

    # パスの類似性を評価
    similarities = []
    for i in range(len(path_histories)):
        for j in range(i + 1, len(path_histories)):
            # ジャロ・ウィンクラー類似度の代わりに簡易的な類似度計算
            path1 = path_histories[i]
            path2 = path_histories[j]
            min_len = min(len(path1), len(path2))

            # 一致する要素の数を数える
            matches = sum(1 for k in range(min_len) if path1[k] == path2[k])
            similarity = matches / min_len if min_len > 0 else 0
            similarities.append(similarity)

    avg_similarity = sum(similarities) / len(similarities) if similarities else 0
    print(f"パス間の平均類似度: {avg_similarity:.4f}")

    # 結果の評価
    assert not all_same, "実行パスは毎回異なるべきです"
    assert avg_similarity < 0.95, "実行パスは十分に異なるべきです"

    return {"path_histories": path_histories, "avg_similarity": avg_similarity}


def test_obfuscation():
    """
    実行パス難読化機能をテスト
    """
    # テスト鍵の生成
    test_key = os.urandom(32)
    print("\n=== 実行パス難読化テスト ===")

    # エンジンの作成と実行
    engine = create_engine_from_key(test_key, TRUE_PATH)
    engine.run_execution()
    original_path = engine.path_manager.path_history.copy()
    original_state = engine.path_manager.current_state_id

    # 難読化を適用
    obfuscate_execution_path(engine)

    # 難読化後の状態確認
    paths_preserved = (original_path == engine.path_manager.path_history)
    state_preserved = (original_state == engine.path_manager.current_state_id)

    print(f"パスが保持されている: {'はい' if paths_preserved else 'いいえ'}")
    print(f"状態が保持されている: {'はい' if state_preserved else 'いいえ'}")

    # 結果の評価
    assert paths_preserved, "難読化後もパス履歴は保持されるべきです"
    assert state_preserved, "難読化後も現在の状態は保持されるべきです"

    return {"paths_preserved": paths_preserved, "state_preserved": state_preserved}


def test_anti_analysis_noise():
    """
    解析対策ノイズ生成機能をテスト
    """
    # テスト鍵の生成
    test_key = os.urandom(32)
    print("\n=== 解析対策ノイズ生成テスト ===")

    # 異なるパスタイプで生成
    true_noise = generate_anti_analysis_noise(test_key, TRUE_PATH)
    false_noise = generate_anti_analysis_noise(test_key, FALSE_PATH)

    # 同じ鍵・パスタイプで再生成
    true_noise2 = generate_anti_analysis_noise(test_key, TRUE_PATH)

    # 異なる鍵で生成
    different_key = os.urandom(32)
    diff_noise = generate_anti_analysis_noise(different_key, TRUE_PATH)

    print(f"TRUEノイズサイズ: {len(true_noise)}バイト")
    print(f"FALSEノイズサイズ: {len(false_noise)}バイト")

    # ノイズの一意性確認
    true_false_same = (true_noise == false_noise)
    true_true2_same = (true_noise == true_noise2)
    true_diff_same = (true_noise == diff_noise)

    print(f"TRUE/FALSEノイズが同一: {'はい' if true_false_same else 'いいえ'}")
    print(f"同じパラメータで生成したノイズが同一: {'はい' if true_true2_same else 'いいえ'}")
    print(f"異なる鍵で生成したノイズが同一: {'はい' if true_diff_same else 'いいえ'}")

    # ノイズのエントロピー評価
    true_entropy = calculate_entropy(true_noise)
    false_entropy = calculate_entropy(false_noise)
    diff_entropy = calculate_entropy(diff_noise)

    print(f"TRUEノイズエントロピー: {true_entropy:.4f}")
    print(f"FALSEノイズエントロピー: {false_entropy:.4f}")
    print(f"異なる鍵のノイズエントロピー: {diff_entropy:.4f}")

    # 結果の評価
    assert not true_false_same, "TRUE/FALSEで異なるノイズが生成されるべきです"
    assert true_true2_same, "同じパラメータでは同じノイズが生成されるべきです"
    assert not true_diff_same, "異なる鍵では異なるノイズが生成されるべきです"
    assert true_entropy > 7.0, "ノイズは高いエントロピーを持つべきです"

    return {
        "true_entropy": true_entropy,
        "false_entropy": false_entropy,
        "diff_entropy": diff_entropy
    }


def calculate_entropy(data: bytes) -> float:
    """
    データのエントロピーを計算

    Args:
        data: エントロピーを計算するデータ

    Returns:
        ビットあたりのエントロピー値
    """
    if not data:
        return 0.0

    # バイト出現頻度を計算
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1

    # 確率を計算
    probabilities = [count / len(data) for count in counts.values()]

    # シャノンエントロピーを計算
    entropy = 0.0
    for p in probabilities:
        entropy -= p * (np.log2(p) if p > 0 else 0)

    return entropy


def visualize_results(results: Dict[str, Any], timestamp: str) -> str:
    """
    テスト結果を可視化

    Args:
        results: テスト結果
        timestamp: タイムスタンプ

    Returns:
        生成された画像ファイルのパス
    """
    # 出力ディレクトリ作成
    output_dir = os.path.join(root_dir, "test_output")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"probability_engine_test_{timestamp}.png")

    # グラフの初期化
    plt.figure(figsize=(15, 10), dpi=100)
    plt.suptitle("確率的実行エンジンテスト結果", fontsize=16)

    # 1. 収束性グラフ
    if "convergence" in results:
        convergence = results["convergence"]
        true_finals = convergence.get("true_finals", [])
        false_finals = convergence.get("false_finals", [])

        plt.subplot(2, 2, 1)
        # 状態IDの頻度カウント
        true_counts = {}
        false_counts = {}
        for state in true_finals:
            true_counts[state] = true_counts.get(state, 0) + 1
        for state in false_finals:
            false_counts[state] = false_counts.get(state, 0) + 1

        # グラフ描画
        true_states = list(true_counts.keys())
        false_states = list(false_counts.keys())
        true_freq = [true_counts[s] for s in true_states]
        false_freq = [false_counts[s] for s in false_states]

        plt.bar([str(s) for s in true_states], true_freq, color='blue', alpha=0.6, label='TRUE')
        plt.bar([str(s) for s in false_states], false_freq, color='red', alpha=0.6, label='FALSE')
        plt.title("状態収束分布")
        plt.xlabel("状態ID")
        plt.ylabel("頻度")
        plt.legend()
        plt.grid(alpha=0.3)

    # 2. 実行パス可視化
    if "path_nondeterminism" in results:
        nondeterminism = results["path_nondeterminism"]
        path_histories = nondeterminism.get("path_histories", [])

        plt.subplot(2, 2, 2)
        for i, path in enumerate(path_histories[:5]):  # 最大5つまで表示
            plt.plot(path, label=f"実行{i+1}", marker='o', markersize=3, linewidth=1, alpha=0.7)
        plt.title("実行パスの変動")
        plt.xlabel("ステップ")
        plt.ylabel("状態ID")
        plt.legend()
        plt.grid(alpha=0.3)

    # 3. エントロピー比較
    if "anti_analysis" in results:
        anti_analysis = results["anti_analysis"]
        true_entropy = anti_analysis.get("true_entropy", 0)
        false_entropy = anti_analysis.get("false_entropy", 0)
        diff_entropy = anti_analysis.get("diff_entropy", 0)

        plt.subplot(2, 2, 3)
        entropy_data = [true_entropy, false_entropy, diff_entropy]
        plt.bar(["TRUE", "FALSE", "異なる鍵"], entropy_data, color=['blue', 'red', 'green'])
        plt.title("ノイズエントロピー比較")
        plt.ylabel("エントロピー")
        plt.axhline(y=7.0, color='r', linestyle='--', label='目標閾値')
        plt.ylim(0, 8.5)
        plt.grid(axis='y', alpha=0.3)

    # 4. 基本実行の結果
    if "basic" in results:
        basic = results["basic"]
        true_path = basic.get(TRUE_PATH, {}).get("path", [])
        false_path = basic.get(FALSE_PATH, {}).get("path", [])

        plt.subplot(2, 2, 4)
        plt.plot(true_path, 'b-', label='TRUE')
        plt.plot(false_path, 'r--', label='FALSE')
        plt.title("基本実行パス比較")
        plt.xlabel("ステップ")
        plt.ylabel("状態ID")
        plt.legend()
        plt.grid(alpha=0.3)

    # グラフを保存
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(output_path)
    plt.close()

    print(f"可視化結果を保存しました: {output_path}")
    return output_path


def run_all_tests():
    """
    すべてのテストを実行
    """
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    print(f"テスト開始時刻: {timestamp}")

    results = {}

    # 基本実行テスト
    try:
        print("\n========== 基本実行テスト ==========")
        results["basic"] = test_basic_execution()
    except Exception as e:
        print(f"基本実行テスト失敗: {e}")
        results["basic"] = {"error": str(e)}

    # 収束性テスト
    try:
        print("\n========== 収束性テスト ==========")
        results["convergence"] = test_convergence()
    except Exception as e:
        print(f"収束性テスト失敗: {e}")
        results["convergence"] = {"error": str(e)}

    # 非決定性テスト
    try:
        print("\n========== 非決定性テスト ==========")
        results["path_nondeterminism"] = test_path_nondeterminism()
    except Exception as e:
        print(f"非決定性テスト失敗: {e}")
        results["path_nondeterminism"] = {"error": str(e)}

    # 難読化テスト
    try:
        print("\n========== 難読化テスト ==========")
        results["obfuscation"] = test_obfuscation()
    except Exception as e:
        print(f"難読化テスト失敗: {e}")
        results["obfuscation"] = {"error": str(e)}

    # 解析対策ノイズテスト
    try:
        print("\n========== 解析対策ノイズテスト ==========")
        results["anti_analysis"] = test_anti_analysis_noise()
    except Exception as e:
        print(f"解析対策ノイズテスト失敗: {e}")
        results["anti_analysis"] = {"error": str(e)}

    # 結果の可視化
    visual_path = visualize_results(results, timestamp)

    print("\n========== テスト完了 ==========")
    print(f"結果可視化: {visual_path}")

    # エラーがあったかチェック
    errors = [k for k, v in results.items() if isinstance(v, dict) and "error" in v]
    if errors:
        print(f"\n警告: {len(errors)}個のテストでエラーが発生しました: {', '.join(errors)}")
        return False
    else:
        print("\nすべてのテストが正常に完了しました。")
        return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)