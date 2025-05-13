#!/usr/bin/env python3
"""
ハニーポットカプセルテスト結果可視化スクリプト

このスクリプトは、ハニーポットカプセルのテスト結果を
分かりやすい画像としてレンダリングします。
"""

import os
import sys
import time
import subprocess
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.patches as patches

# 親ディレクトリをPythonパスに追加
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# テスト結果のログファイル
LOG_FILE = "test_output/honeypot_inspection/inspection_results.log"
OUTPUT_IMAGE = "test_output/honeypot_inspection/honeypot_inspection_test.png"

def run_tests_and_capture_output():
    """テストを実行して出力をキャプチャ"""
    script_path = Path(__file__).parent / "inspect_capsule.py"

    # ログファイルを作成
    with open(LOG_FILE, 'w') as f:
        # Python3でテストスクリプトを実行し、出力をファイルにリダイレクト
        subprocess.run(
            ["python3", str(script_path)],
            stdout=f,
            stderr=subprocess.STDOUT,
            check=True
        )

    # ログファイルから内容を読み込む
    with open(LOG_FILE, 'r') as f:
        return f.read()

def parse_test_results(output):
    """テスト結果を解析"""
    results = {
        'true_false_test': {
            'success': False,
            'true_data_ok': False,
            'false_data_ok': False,
            'details': {}
        },
        'bind_token_test': {
            'success': False,
            'details': {}
        },
        'large_file_test': {
            'success': False,
            'true_data_ok': False,
            'false_data_ok': False,
            'details': {}
        }
    }

    # 真偽テストの結果を解析
    if "正規データの復号に成功しました（データが一致）" in output:
        results['true_false_test']['true_data_ok'] = True

    if "非正規データの復号に成功しました（データが一致）" in output:
        results['true_false_test']['false_data_ok'] = True

    results['true_false_test']['success'] = (
        results['true_false_test']['true_data_ok'] and
        results['true_false_test']['false_data_ok']
    )

    # トークン結合テストの結果を解析
    if "結合・抽出テスト成功: データが正しく復元されました" in output:
        results['bind_token_test']['success'] = True

    # 大きなファイル処理テストの結果を解析
    if "正規データの読み込みテスト成功: データが正しく復元されました" in output:
        results['large_file_test']['true_data_ok'] = True

    if "非正規データの読み込みテスト成功: データが正しく復元されました" in output:
        results['large_file_test']['false_data_ok'] = True

    results['large_file_test']['success'] = (
        results['large_file_test']['true_data_ok'] and
        results['large_file_test']['false_data_ok']
    )

    # 詳細情報を抽出
    # カプセルサイズ
    import re
    capsule_size_match = re.search(r'ハニーポットカプセルをファイルに保存しました: .+ \((\d+) バイト\)', output)
    if capsule_size_match:
        results['true_false_test']['details']['capsule_size'] = int(capsule_size_match.group(1))

    # 大きなファイルの処理時間
    processing_time_match = re.search(r'大きなファイルの処理に (\d+\.\d+) 秒かかりました', output)
    if processing_time_match:
        results['large_file_test']['details']['processing_time'] = float(processing_time_match.group(1))

    # 大きなファイルのサイズ
    file_size_match = re.search(r'生成されたファイルサイズ: (\d+\.\d+) MB', output)
    if file_size_match:
        results['large_file_test']['details']['file_size'] = float(file_size_match.group(1))

    return results

def create_result_image(results):
    """テスト結果を可視化した画像を作成"""
    # 画像サイズを設定
    plt.figure(figsize=(12, 8))

    # ダークモード風の背景色
    plt.style.use('dark_background')

    # タイトルと実行時間
    plt.suptitle('ハニーポットカプセル実装検証結果', fontsize=16)
    plt.title(f'実行日時: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', fontsize=10)

    # グリッドを作成
    gs = plt.GridSpec(3, 3, height_ratios=[1, 1, 1])

    # === 真偽テストの結果表示 ===
    ax1 = plt.subplot(gs[0, :])

    # ボックスの色を結果に応じて設定
    box_color = 'green' if results['true_false_test']['success'] else 'red'

    # ボックスを描画
    ax1.add_patch(
        patches.Rectangle(
            (0.01, 0.01),
            0.98, 0.98,
            fill=False,
            edgecolor=box_color,
            linewidth=2
        )
    )

    # タイトルと結果
    ax1.text(0.5, 0.9, '真偽テキストファイルテスト',
             horizontalalignment='center', fontsize=14)

    # 詳細結果
    status_true = "✓" if results['true_false_test']['true_data_ok'] else "✗"
    status_false = "✓" if results['true_false_test']['false_data_ok'] else "✗"
    ax1.text(0.1, 0.6, f"正規データの復号: {status_true}", fontsize=12)
    ax1.text(0.1, 0.4, f"非正規データの復号: {status_false}", fontsize=12)

    # カプセルサイズ情報があれば表示
    if 'capsule_size' in results['true_false_test']['details']:
        capsule_size = results['true_false_test']['details']['capsule_size']
        ax1.text(0.6, 0.5, f"カプセルサイズ: {capsule_size} バイト", fontsize=12)

    # 軸を非表示に
    ax1.axis('off')

    # === トークン結合テストの結果表示 ===
    ax2 = plt.subplot(gs[1, :])

    # ボックスの色を結果に応じて設定
    box_color = 'green' if results['bind_token_test']['success'] else 'red'

    # ボックスを描画
    ax2.add_patch(
        patches.Rectangle(
            (0.01, 0.01),
            0.98, 0.98,
            fill=False,
            edgecolor=box_color,
            linewidth=2
        )
    )

    # タイトルと結果
    ax2.text(0.5, 0.9, 'トークン結合・抽出テスト',
             horizontalalignment='center', fontsize=14)

    # 詳細結果
    status = "成功" if results['bind_token_test']['success'] else "失敗"
    ax2.text(0.1, 0.5, f"結合および抽出処理: {status}", fontsize=12)

    # 説明
    ax2.text(0.5, 0.3, "トークンとデータの暗号学的結合および分離機能の検証",
             horizontalalignment='center', fontsize=10, style='italic')

    # 軸を非表示に
    ax2.axis('off')

    # === 大きなファイル処理テストの結果表示 ===
    ax3 = plt.subplot(gs[2, :])

    # ボックスの色を結果に応じて設定
    box_color = 'green' if results['large_file_test']['success'] else 'red'

    # ボックスを描画
    ax3.add_patch(
        patches.Rectangle(
            (0.01, 0.01),
            0.98, 0.98,
            fill=False,
            edgecolor=box_color,
            linewidth=2
        )
    )

    # タイトルと結果
    ax3.text(0.5, 0.9, '大きなファイル処理テスト',
             horizontalalignment='center', fontsize=14)

    # 詳細結果
    status_true = "✓" if results['large_file_test']['true_data_ok'] else "✗"
    status_false = "✓" if results['large_file_test']['false_data_ok'] else "✗"
    ax3.text(0.1, 0.6, f"正規データの読み込み: {status_true}", fontsize=12)
    ax3.text(0.1, 0.4, f"非正規データの読み込み: {status_false}", fontsize=12)

    # 処理時間と生成ファイルサイズ
    details = results['large_file_test']['details']
    if 'processing_time' in details:
        ax3.text(0.6, 0.6, f"処理時間: {details['processing_time']:.2f} 秒", fontsize=12)

    if 'file_size' in details:
        ax3.text(0.6, 0.4, f"ファイルサイズ: {details['file_size']:.2f} MB", fontsize=12)

    # 軸を非表示に
    ax3.axis('off')

    # 全体の結論
    all_success = all([
        results['true_false_test']['success'],
        results['bind_token_test']['success'],
        results['large_file_test']['success']
    ])

    # 結論テキストの色を設定
    conclusion_color = 'lime' if all_success else 'red'

    # 結論テキスト
    conclusion = "すべてのテストに合格しました！" if all_success else "一部のテストに失敗しました"
    plt.figtext(0.5, 0.02, conclusion,
                color=conclusion_color, fontsize=14,
                horizontalalignment='center', bbox=dict(facecolor='black', alpha=0.5))

    # レイアウトを調整して保存
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(OUTPUT_IMAGE, dpi=150)
    print(f"テスト結果画像を保存しました: {OUTPUT_IMAGE}")

def main():
    """メイン関数"""
    print("ハニーポットカプセル検査の結果を可視化します...")

    try:
        # テストを実行して出力をキャプチャ
        output = run_tests_and_capture_output()

        # テスト結果を解析
        results = parse_test_results(output)

        # 結果画像を作成
        create_result_image(results)

        # 成功したかどうかを表示
        all_success = all([
            results['true_false_test']['success'],
            results['bind_token_test']['success'],
            results['large_file_test']['success']
        ])

        if all_success:
            print("✅ すべてのテストに合格しました！")
        else:
            print("❌ 一部のテストに失敗しました")

    except Exception as e:
        print(f"エラーが発生しました: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()