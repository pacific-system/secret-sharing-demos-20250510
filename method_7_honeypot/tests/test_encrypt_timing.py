#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - 暗号化プログラムのタイミング耐性テスト

暗号化処理のタイミング攻撃耐性を検証するためのスクリプトです。
正規鍵と非正規鍵を使った暗号化処理時間に有意な差がないことを確認します。
"""

import os
import sys
import time
import statistics
import random
import argparse
from datetime import datetime
from typing import List, Tuple, Dict, Any

# テスト対象のモジュールへのパスを追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# テスト対象のモジュールをインポート
from method_7_honeypot.encrypt import (
    read_file, symmetric_encrypt, encrypt_files
)
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)

# matplotlibが利用可能な場合のみインポート
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def measure_encryption_times(iterations: int = 20) -> Tuple[List[float], List[float]]:
    """
    正規鍵と非正規鍵を使った暗号化処理の時間を測定

    Args:
        iterations: 繰り返し回数

    Returns:
        (true_times, false_times): 正規鍵と非正規鍵の暗号化時間リスト
    """
    # テスト用のデータを準備
    data = os.urandom(1024)  # 1KBのランダムデータ

    true_times = []
    false_times = []

    print(f"暗号化処理のタイミング測定を開始（{iterations}回繰り返し）...")

    for i in range(iterations):
        # マスター鍵とトラップドアパラメータを生成（毎回新しく生成）
        master_key = create_master_key()
        params = create_trapdoor_parameters(master_key)
        keys, salt = derive_keys_from_trapdoor(params)

        # 正規鍵での暗号化時間測定
        start_time = time.perf_counter()
        true_encrypted, _ = symmetric_encrypt(data, keys[KEY_TYPE_TRUE])
        true_time = time.perf_counter() - start_time
        true_times.append(true_time)

        # 処理間の時間を空ける（キャッシュの影響を減らす）
        time.sleep(random.uniform(0.01, 0.05))

        # 非正規鍵での暗号化時間測定
        start_time = time.perf_counter()
        false_encrypted, _ = symmetric_encrypt(data, keys[KEY_TYPE_FALSE])
        false_time = time.perf_counter() - start_time
        false_times.append(false_time)

        # 進捗表示
        if (i + 1) % 5 == 0:
            print(f"進捗: {i + 1}/{iterations}回完了")

    return true_times, false_times


def analyze_timing_data(true_times: List[float], false_times: List[float]) -> Dict[str, float]:
    """
    タイミングデータを分析し、統計情報を返す

    Args:
        true_times: 正規鍵の暗号化時間リスト
        false_times: 非正規鍵の暗号化時間リスト

    Returns:
        統計情報を含む辞書
    """
    # 基本統計量を計算
    true_avg = sum(true_times) / len(true_times)
    false_avg = sum(false_times) / len(false_times)
    time_diff_abs = abs(true_avg - false_avg)
    time_diff_pct = (time_diff_abs / true_avg) * 100 if true_avg > 0 else 0

    # 詳細な統計情報
    stats = {
        "true_min": min(true_times),
        "true_max": max(true_times),
        "true_avg": true_avg,
        "true_median": statistics.median(true_times),
        "true_stdev": statistics.stdev(true_times) if len(true_times) > 1 else 0,

        "false_min": min(false_times),
        "false_max": max(false_times),
        "false_avg": false_avg,
        "false_median": statistics.median(false_times),
        "false_stdev": statistics.stdev(false_times) if len(false_times) > 1 else 0,

        "diff_abs": time_diff_abs,
        "diff_pct": time_diff_pct
    }

    return stats


def create_timing_graph(true_times: List[float], false_times: List[float], stats: Dict[str, float], output_path: str):
    """
    タイミング測定結果のグラフを生成

    Args:
        true_times: 正規鍵の暗号化時間リスト
        false_times: 非正規鍵の暗号化時間リスト
        stats: 統計情報辞書
        output_path: 出力ファイルパス
    """
    if not HAS_MATPLOTLIB:
        print("警告: matplotlibがインストールされていないため、グラフを生成できません")
        return False

    # グラフの設定
    plt.figure(figsize=(12, 8))
    plt.style.use('dark_background')

    # ヒストグラムの設定
    bins = 15
    alpha = 0.6

    # 正規鍵の暗号化時間のヒストグラム
    plt.hist(true_times, bins=bins, alpha=alpha, color='#6699ff', label='正規鍵')
    # 非正規鍵の暗号化時間のヒストグラム
    plt.hist(false_times, bins=bins, alpha=alpha, color='#ff6666', label='非正規鍵')

    # グラフの装飾
    plt.title('暗号化処理のタイミング分布', fontsize=16)
    plt.xlabel('暗号化時間（秒）', fontsize=14)
    plt.ylabel('頻度', fontsize=14)
    plt.grid(alpha=0.3)
    plt.legend(fontsize=12)

    # 統計情報をグラフに追加
    info_text = (
        f"正規鍵平均: {stats['true_avg']:.6f}秒\n"
        f"非正規鍵平均: {stats['false_avg']:.6f}秒\n"
        f"時間差: {stats['diff_abs']:.6f}秒 ({stats['diff_pct']:.2f}%)\n"
        f"標準偏差 - 正規: {stats['true_stdev']:.6f}, 非正規: {stats['false_stdev']:.6f}"
    )
    plt.annotate(info_text, xy=(0.02, 0.95), xycoords='axes fraction',
                 fontsize=12, color='white', verticalalignment='top',
                 bbox=dict(boxstyle='round,pad=0.5', facecolor='black', alpha=0.5))

    # 結論を追加
    threshold = 0.001  # 閾値（1ミリ秒）
    if stats['diff_abs'] < threshold:
        conclusion = "✓ タイミング攻撃耐性あり"
        color = 'green'
    else:
        conclusion = "✗ タイミング攻撃耐性不足"
        color = 'red'

    plt.annotate(conclusion, xy=(0.98, 0.05), xycoords='axes fraction',
                 fontsize=14, color=color, horizontalalignment='right',
                 bbox=dict(boxstyle='round,pad=0.5', facecolor='black', alpha=0.5))

    # グラフを保存
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"グラフを保存しました: {output_path}")

    # プロットをクローズ
    plt.close()

    return True


def create_ascii_graph(true_times: List[float], false_times: List[float], stats: Dict[str, float], output_path: str):
    """
    タイミングデータのASCIIアートグラフを生成する（matplotlibが使えない環境用）

    Args:
        true_times: 正規鍵の暗号化時間リスト
        false_times: 非正規鍵の暗号化時間リスト
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
        f.write("暗号化処理のタイミング分布 (ASCIIグラフ)\n")
        f.write(f"平均時間差: {stats['diff_abs']:.6f}秒 ({stats['diff_pct']:.2f}%)\n\n")

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
        f.write("暗号化時間 (秒)\n\n")

        # 凡例
        f.write("T: 正規鍵  F: 非正規鍵  X: 両方\n\n")

        # 統計情報
        f.write(f"正規鍵平均暗号化時間: {stats['true_avg']:.6f}秒 (最小: {stats['true_min']:.6f}, 最大: {stats['true_max']:.6f})\n")
        f.write(f"非正規鍵平均暗号化時間: {stats['false_avg']:.6f}秒 (最小: {stats['false_min']:.6f}, 最大: {stats['false_max']:.6f})\n")
        f.write(f"平均時間差: {stats['diff_abs']:.6f}秒 ({stats['diff_pct']:.2f}%)\n")
        f.write(f"標準偏差 - 正規鍵: {stats['true_stdev']:.6f}, 非正規鍵: {stats['false_stdev']:.6f}\n\n")

        # 結論
        threshold = 0.001  # 閾値（1ミリ秒）
        if stats['diff_abs'] < threshold:
            f.write("✓ タイミング攻撃耐性あり: 暗号化時間の差が閾値（1ミリ秒）未満です\n")
        else:
            f.write("✗ タイミング攻撃耐性不足: 暗号化時間の差が閾値（1ミリ秒）以上です\n")

    print(f"ASCIIグラフを保存しました: {output_path}")


def create_timing_report(stats: Dict[str, float], output_path: str):
    """
    タイミング分析レポートを生成する

    Args:
        stats: 統計情報辞書
        output_path: 出力ファイルパス
    """
    timestamp = datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")

    with open(output_path, 'w') as f:
        f.write(f"# 暗号化処理のタイミング分析レポート\n\n")
        f.write(f"実行日時: {timestamp}\n\n")

        f.write("## 測定結果\n\n")
        f.write("| 統計項目 | 正規鍵 | 非正規鍵 |\n")
        f.write("| --- | --- | --- |\n")
        f.write(f"| 最小時間 | {stats['true_min']:.6f}秒 | {stats['false_min']:.6f}秒 |\n")
        f.write(f"| 最大時間 | {stats['true_max']:.6f}秒 | {stats['false_max']:.6f}秒 |\n")
        f.write(f"| 平均時間 | {stats['true_avg']:.6f}秒 | {stats['false_avg']:.6f}秒 |\n")
        f.write(f"| 中央値 | {stats['true_median']:.6f}秒 | {stats['false_median']:.6f}秒 |\n")
        f.write(f"| 標準偏差 | {stats['true_stdev']:.6f} | {stats['false_stdev']:.6f} |\n\n")

        f.write("## 分析\n\n")
        f.write(f"- 平均時間の絶対差: **{stats['diff_abs']:.6f}秒**\n")
        f.write(f"- 平均時間の相対差: **{stats['diff_pct']:.2f}%**\n\n")

        # 結論
        threshold = 0.001  # 閾値（1ミリ秒）
        f.write("## 結論\n\n")
        if stats['diff_abs'] < threshold:
            f.write(f"✅ **タイミング攻撃耐性あり**: 正規鍵と非正規鍵の暗号化時間の差が閾値({threshold}秒)未満です。\n\n")
            f.write("暗号化処理はタイミング攻撃に対して十分な耐性を有していると判断できます。\n")
        else:
            f.write(f"⚠️ **タイミング攻撃耐性不足**: 正規鍵と非正規鍵の暗号化時間の差が閾値({threshold}秒)以上です。\n\n")
            f.write("暗号化処理のタイミングに有意な差があり、タイミング攻撃のリスクがあります。処理時間を均一化するための改善が必要です。\n")

    print(f"タイミング分析レポートを保存しました: {output_path}")


def parse_arguments():
    """コマンドライン引数を解析"""
    parser = argparse.ArgumentParser(description="暗号化処理のタイミング攻撃耐性テスト")

    parser.add_argument(
        "--iterations", "-i",
        type=int,
        default=20,
        help="測定の繰り返し回数（デフォルト: 20）"
    )

    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="test_output",
        help="出力ディレクトリのパス（デフォルト: test_output）"
    )

    parser.add_argument(
        "--ascii-only",
        action="store_true",
        help="ASCIIグラフのみ生成（matplotlibを使用しない）"
    )

    return parser.parse_args()


def main():
    """メイン関数"""
    # 引数を解析
    args = parse_arguments()

    # matplotlibが利用できない場合はASCIIグラフのみ生成
    if not HAS_MATPLOTLIB:
        args.ascii_only = True

    # 出力ディレクトリを確認・作成
    os.makedirs(args.output_dir, exist_ok=True)

    # タイムスタンプを取得
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 出力ファイルパスを生成
    graph_path = os.path.join(args.output_dir, f"encrypt_timing_graph_{timestamp}.png") if not args.ascii_only else None
    ascii_path = os.path.join(args.output_dir, f"encrypt_timing_ascii_{timestamp}.txt")
    report_path = os.path.join(args.output_dir, f"encrypt_timing_report_{timestamp}.md")

    # タイミング測定
    true_times, false_times = measure_encryption_times(args.iterations)

    # タイミングデータの分析
    stats = analyze_timing_data(true_times, false_times)

    # グラフの生成
    graph_created = False
    if not args.ascii_only and graph_path:
        graph_created = create_timing_graph(true_times, false_times, stats, graph_path)

    # ASCIIグラフの生成
    create_ascii_graph(true_times, false_times, stats, ascii_path)

    # レポートの生成
    create_timing_report(stats, report_path)

    # 結果の表示
    print("\n暗号化処理のタイミング分析結果:")
    print(f"正規鍵平均時間: {stats['true_avg']:.6f}秒")
    print(f"非正規鍵平均時間: {stats['false_avg']:.6f}秒")
    print(f"時間差: {stats['diff_abs']:.6f}秒 ({stats['diff_pct']:.2f}%)")

    # 結論
    threshold = 0.001  # 閾値（1ミリ秒）
    if stats['diff_abs'] < threshold:
        print(f"\n✅ タイミング攻撃耐性あり: 暗号化時間の差が閾値({threshold}秒)未満です")
    else:
        print(f"\n⚠️ タイミング攻撃耐性不足: 暗号化時間の差が閾値({threshold}秒)以上です")

    print(f"\nレポート: {report_path}")
    print(f"ASCIIグラフ: {ascii_path}")
    if graph_created:
        print(f"グラフ画像: {graph_path}")

    # 結果パスを返却（Gitコメント用など）
    return {
        "report": report_path,
        "ascii": ascii_path,
        "graph": graph_path if graph_created else None
    }


if __name__ == "__main__":
    main()