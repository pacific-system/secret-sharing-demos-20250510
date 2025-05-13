#!/usr/bin/env python3
"""
鍵検証のタイミング攻撃耐性検証スクリプト
実行日時: 2025年5月14日
"""

import os
import sys
import time
import datetime
import statistics
from typing import List, Tuple

# プロジェクトのルートディレクトリをPythonパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 必要なモジュールをインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters, derive_keys_from_trapdoor,
    KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.key_verification import verify_key_and_select_path, KeyVerifier

# タイムスタンプを取得
TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def run_timing_test(iterations: int = 30) -> Tuple[List[float], List[float]]:
    """
    正規鍵と非正規鍵の検証時間を測定するタイミングテスト

    Args:
        iterations: 繰り返し回数

    Returns:
        (true_times, false_times): 正規鍵と非正規鍵の検証時間リスト
    """
    print(f"タイミング攻撃耐性テストを開始します（{iterations}回の繰り返し）...")

    # マスターキーとパラメータの生成
    master_key = create_master_key()
    params = create_trapdoor_parameters(master_key)
    keys, salt = derive_keys_from_trapdoor(params)

    # KeyVerifierの初期化
    verifier = KeyVerifier(params, salt)

    true_times = []
    false_times = []

    print("正規鍵の検証時間を測定中...")
    for i in range(iterations):
        start_time = time.perf_counter()
        true_key_type = verifier.verify_key(keys[KEY_TYPE_TRUE])
        elapsed = time.perf_counter() - start_time
        true_times.append(elapsed)

    print("非正規鍵の検証時間を測定中...")
    for i in range(iterations):
        start_time = time.perf_counter()
        false_key_type = verifier.verify_key(keys[KEY_TYPE_FALSE])
        elapsed = time.perf_counter() - start_time
        false_times.append(elapsed)

    return true_times, false_times

def analyze_timing_data(true_times: List[float], false_times: List[float]) -> dict:
    """
    タイミングデータを分析し、統計情報を返す

    Args:
        true_times: 正規鍵の検証時間リスト
        false_times: 非正規鍵の検証時間リスト

    Returns:
        統計情報を含む辞書
    """
    # 基本統計量を計算
    avg_true = sum(true_times) / len(true_times)
    avg_false = sum(false_times) / len(false_times)
    time_diff = abs(avg_true - avg_false)

    # 詳細な統計情報
    stats = {
        "true_min": min(true_times),
        "true_max": max(true_times),
        "true_avg": avg_true,
        "true_median": statistics.median(true_times),
        "true_stdev": statistics.stdev(true_times) if len(true_times) > 1 else 0,

        "false_min": min(false_times),
        "false_max": max(false_times),
        "false_avg": avg_false,
        "false_median": statistics.median(false_times),
        "false_stdev": statistics.stdev(false_times) if len(false_times) > 1 else 0,

        "time_diff": time_diff,
        "time_diff_percent": (time_diff / avg_true) * 100
    }

    return stats



def generate_ascii_graph(true_times: List[float], false_times: List[float], stats: dict, output_path: str):
    """
    タイミングデータのASCIIアートグラフを生成する

    Args:
        true_times: 正規鍵の検証時間リスト
        false_times: 非正規鍵の検証時間リスト
        stats: 統計情報辞書
        output_path: 出力ファイルパス
    """
    # ヒストグラムの準備
    all_times = true_times + false_times
    min_time = min(all_times)
    max_time = max(all_times)
    bins = 20
    bin_width = (max_time - min_time) / bins if max_time > min_time else 0.001

    # カウント用の配列を初期化
    true_hist = [0] * bins
    false_hist = [0] * bins

    # データをビンに振り分ける
    for t in true_times:
        bin_idx = min(bins - 1, int((t - min_time) / bin_width)) if bin_width > 0 else 0
        true_hist[bin_idx] += 1

    for t in false_times:
        bin_idx = min(bins - 1, int((t - min_time) / bin_width)) if bin_width > 0 else 0
        false_hist[bin_idx] += 1

    # 最大カウント値を取得
    max_count = max(max(true_hist), max(false_hist)) if true_hist and false_hist else 1

    # ASCIIグラフの高さ
    height = 15

    with open(output_path, 'w') as f:
        # タイトル
        f.write("鍵検証処理のタイミング分布 (ASCIIグラフ)\n")
        f.write(f"平均時間差: {stats['time_diff']:.6f}秒 ({stats['time_diff_percent']:.2f}%)\n\n")

        # Y軸ラベル
        f.write("頻度\n")

        # グラフ本体
        for i in range(height, 0, -1):
            line = ""
            threshold = i * max_count / height

            for j in range(bins):
                if true_hist[j] >= threshold and false_hist[j] >= threshold:
                    line += "X"  # 両方
                elif true_hist[j] >= threshold:
                    line += "T"  # 正規鍵のみ
                elif false_hist[j] >= threshold:
                    line += "F"  # 非正規鍵のみ
                else:
                    line += " "  # 空白

            f.write(f"{line}\n")

        # X軸
        f.write("-" * bins + "\n")
        f.write("検証時間 (秒)\n\n")

        # 凡例
        f.write("T: 正規鍵  F: 非正規鍵  X: 両方\n\n")

        # 統計情報
        f.write(f"正規鍵平均検証時間: {stats['true_avg']:.6f}秒 (最小: {stats['true_min']:.6f}, 最大: {stats['true_max']:.6f})\n")
        f.write(f"非正規鍵平均検証時間: {stats['false_avg']:.6f}秒 (最小: {stats['false_min']:.6f}, 最大: {stats['false_max']:.6f})\n")
        f.write(f"平均時間差: {stats['time_diff']:.6f}秒\n")
        f.write(f"標準偏差 - 正規鍵: {stats['true_stdev']:.6f}, 非正規鍵: {stats['false_stdev']:.6f}\n")

    print(f"ASCIIグラフを保存しました: {output_path}")

def generate_timing_report(stats: dict) -> str:
    """
    タイミング分析レポートを生成する

    Args:
        stats: 統計情報辞書

    Returns:
        レポート内容
    """
    report = f"## 鍵検証タイミング分析レポート ({TIMESTAMP})\n\n"

    # 統計情報
    report += "### 統計情報\n\n"
    report += f"正規鍵平均検証時間: {stats['true_avg']:.6f}秒 (最小: {stats['true_min']:.6f}, 最大: {stats['true_max']:.6f})\n"
    report += f"非正規鍵平均検証時間: {stats['false_avg']:.6f}秒 (最小: {stats['false_min']:.6f}, 最大: {stats['false_max']:.6f})\n"
    report += f"平均時間差: {stats['time_diff']:.6f}秒 ({stats['time_diff_percent']:.2f}%)\n\n"

    # 標準偏差
    report += f"標準偏差 - 正規鍵: {stats['true_stdev']:.6f}, 非正規鍵: {stats['false_stdev']:.6f}\n\n"

    # 結論
    threshold = 0.001  # 閾値（1ミリ秒）
    if stats['time_diff'] < threshold:
        report += f"### 結論: タイミング攻撃に対して十分な耐性あり ✅\n\n"
        report += f"平均時間差が{threshold}秒未満であり、タイミング攻撃に対して十分な耐性があります。\n"
    else:
        report += f"### 結論: タイミング攻撃に対する耐性が不十分 ⚠️\n\n"
        report += f"平均時間差が{threshold}秒以上であり、タイミング攻撃のリスクがあります。改善が必要です。\n"

    # 保存
    report_path = f"key_verification_timing_data_{TIMESTAMP}.txt"
    with open(report_path, 'w') as f:
        f.write(report)

    print(f"タイミングレポートを保存しました: {report_path}")
    return report

def main():
    """メイン関数"""
    print(f"=== 鍵検証タイミング攻撃耐性テスト ({TIMESTAMP}) ===")

    # タイミングテストを実行
    iterations = 30
    true_times, false_times = run_timing_test(iterations)

    # 結果を分析
    stats = analyze_timing_data(true_times, false_times)

    # ASCIIグラフを生成
    ascii_graph_path = f"key_verification_timing_graph.txt"
    generate_ascii_graph(true_times, false_times, stats, ascii_graph_path)

    # レポートを生成
    report = generate_timing_report(stats)

    # 結果を表示
    print("\n=== テスト結果 ===")
    print(f"正規鍵平均検証時間: {stats['true_avg']:.6f}秒")
    print(f"非正規鍵平均検証時間: {stats['false_avg']:.6f}秒")
    print(f"平均時間差: {stats['time_diff']:.6f}秒 ({stats['time_diff_percent']:.2f}%)")

    # 結論
    threshold = 0.001  # 閾値（1ミリ秒）
    if stats['time_diff'] < threshold:
        print(f"\n✅ タイミング攻撃に対して十分な耐性があります。")
    else:
        print(f"\n⚠️ タイミング攻撃のリスクがあります。改善が必要です。")

    print(f"\n詳細なレポートとグラフを生成しました。")

if __name__ == "__main__":
    main()