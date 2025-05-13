#!/usr/bin/env python3
"""
ハニーポットカプセル検査結果の可視化スクリプト

このスクリプトは、検証結果を分かりやすい画像として出力します。
"""

import os
import sys
import re
import datetime
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from pathlib import Path

# 出力ディレクトリ
OUTPUT_DIR = "test_output/honeypot_inspection_new"
LOG_PATTERN = "verification_*.log"
OUTPUT_IMAGE = f"{OUTPUT_DIR}/honeypot_verification_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"

def find_latest_log():
    """最新のログファイルを検索"""
    logs = list(Path(OUTPUT_DIR).glob(LOG_PATTERN))
    if not logs:
        print("ログファイルが見つかりません")
        sys.exit(1)
    return str(sorted(logs, key=os.path.getmtime)[-1])

def parse_log_file(log_file):
    """ログファイルを解析してテスト結果を抽出"""
    results = {
        "basic_functionality": False,
        "data_integrity": False,
        "token_binding": False,
        "true_encryption": False,
        "false_encryption": False,
        "large_file_handling": False,
        "security_analysis": False,
        "details": {}
    }

    try:
        with open(log_file, 'r') as f:
            content = f.read()

        # テスト結果の抽出
        result_section = re.search(r'=== テスト結果サマリー ===\n(.*?)\n総合結果:',
                                 content, re.DOTALL)
        if result_section:
            result_lines = result_section.group(1).strip().split('\n')
            for line in result_lines:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    key = key.strip().split('] ')[-1]  # タイムスタンプを除去
                    results[key] = (value.strip() == '成功')

        # 詳細情報の抽出
        details = {}

        # カプセルサイズ
        capsule_size_match = re.search(r'ハニーポットファイルを作成しました: .+ \((\d+) バイト\)', content)
        if capsule_size_match:
            details['capsule_size'] = int(capsule_size_match.group(1))

        # 大きなファイルの処理時間
        process_time_match = re.search(r'大きなファイルの暗号化に (\d+\.\d+) 秒かかりました', content)
        if process_time_match:
            details['large_file_process_time'] = float(process_time_match.group(1))

        # 暗号化ファイルサイズ
        file_size_match = re.search(r'暗号化されたファイルサイズ: (\d+\.\d+) MB', content)
        if file_size_match:
            details['large_file_size'] = float(file_size_match.group(1))

        # 実行時刻
        start_time_match = re.search(r'\[([\d\-\: ]+)\] ハニーポットカプセル検証を開始します', content)
        if start_time_match:
            details['start_time'] = start_time_match.group(1)

        results['details'] = details

        return results

    except Exception as e:
        print(f"ログファイルの解析中にエラーが発生しました: {e}")
        return results

def create_result_image(results):
    """テスト結果の画像を作成"""
    # 画像サイズを設定
    plt.figure(figsize=(12, 8))

    # ダークモード風の背景色
    plt.style.use('dark_background')

    # タイトルと実行時間
    start_time = results['details'].get('start_time', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    plt.suptitle('ハニーポットカプセル実装検証結果', fontsize=16)
    plt.title(f'実行日時: {start_time}', fontsize=10)

    # グリッドを作成
    gs = plt.GridSpec(4, 3, height_ratios=[1, 1, 1, 1])

    # === 基本機能テスト ===
    ax1 = plt.subplot(gs[0, :2])
    box_color = 'green' if results['basic_functionality'] else 'red'
    ax1.add_patch(
        patches.Rectangle(
            (0.01, 0.01), 0.98, 0.98,
            fill=False, edgecolor=box_color, linewidth=2
        )
    )
    ax1.text(0.5, 0.8, '基本機能テスト',
             horizontalalignment='center', fontsize=14)
    ax1.text(0.5, 0.5, '✓ データブロック追加・シリアライズ・デシリアライズ',
             horizontalalignment='center', fontsize=10)
    ax1.text(0.5, 0.3, '結果: ' + ('成功' if results['basic_functionality'] else '失敗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if results['basic_functionality'] else 'red')
    ax1.axis('off')

    # === データ整合性テスト ===
    ax2 = plt.subplot(gs[0, 2:])
    box_color = 'green' if results['data_integrity'] else 'red'
    ax2.add_patch(
        patches.Rectangle(
            (0.01, 0.01), 0.98, 0.98,
            fill=False, edgecolor=box_color, linewidth=2
        )
    )
    ax2.text(0.5, 0.8, 'データ整合性検証',
             horizontalalignment='center', fontsize=14)
    ax2.text(0.5, 0.5, '✓ 改ざん検出機能',
             horizontalalignment='center', fontsize=10)
    ax2.text(0.5, 0.3, '結果: ' + ('成功' if results['data_integrity'] else '失敗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if results['data_integrity'] else 'red')
    ax2.axis('off')

    # === トークン結合テスト ===
    ax3 = plt.subplot(gs[1, :])
    box_color = 'green' if results['token_binding'] else 'red'
    ax3.add_patch(
        patches.Rectangle(
            (0.01, 0.01), 0.98, 0.98,
            fill=False, edgecolor=box_color, linewidth=2
        )
    )
    ax3.text(0.5, 0.8, 'トークン結合機能テスト',
             horizontalalignment='center', fontsize=14)
    ax3.text(0.5, 0.6, '✓ トークンとデータの暗号学的結合',
             horizontalalignment='center', fontsize=10)
    ax3.text(0.5, 0.4, '✓ カプセルからのデータ抽出',
             horizontalalignment='center', fontsize=10)
    ax3.text(0.5, 0.2, '結果: ' + ('成功' if results['token_binding'] else '失敗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if results['token_binding'] else 'red')
    ax3.axis('off')

    # === 暗号化・復号テスト ===
    ax4 = plt.subplot(gs[2, :])
    true_success = results['true_encryption']
    false_success = results['false_encryption']
    box_color = 'green' if (true_success and false_success) else 'red'
    ax4.add_patch(
        patches.Rectangle(
            (0.01, 0.01), 0.98, 0.98,
            fill=False, edgecolor=box_color, linewidth=2
        )
    )
    ax4.text(0.5, 0.8, '暗号化・復号テスト',
             horizontalalignment='center', fontsize=14)

    ax4.text(0.3, 0.6, '正規データ: ' + ('✓' if true_success else '✗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if true_success else 'red')
    ax4.text(0.7, 0.6, '非正規データ: ' + ('✓' if false_success else '✗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if false_success else 'red')

    # カプセルサイズ
    if 'capsule_size' in results['details']:
        ax4.text(0.5, 0.4, f"カプセルサイズ: {results['details']['capsule_size']} バイト",
                 horizontalalignment='center', fontsize=10)

    ax4.text(0.5, 0.2, '結果: ' + ('成功' if (true_success and false_success) else '失敗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if (true_success and false_success) else 'red')
    ax4.axis('off')

    # === 大きなファイル処理テスト ===
    ax5 = plt.subplot(gs[3, :2])
    box_color = 'green' if results['large_file_handling'] else 'red'
    ax5.add_patch(
        patches.Rectangle(
            (0.01, 0.01), 0.98, 0.98,
            fill=False, edgecolor=box_color, linewidth=2
        )
    )
    ax5.text(0.5, 0.8, '大きなファイル処理テスト',
             horizontalalignment='center', fontsize=14)

    # 処理時間とファイルサイズ
    details = results['details']
    if 'large_file_process_time' in details:
        ax5.text(0.5, 0.6, f"処理時間: {details['large_file_process_time']:.2f} 秒",
                 horizontalalignment='center', fontsize=10)

    if 'large_file_size' in details:
        ax5.text(0.5, 0.4, f"ファイルサイズ: {details['large_file_size']:.2f} MB",
                 horizontalalignment='center', fontsize=10)

    ax5.text(0.5, 0.2, '結果: ' + ('成功' if results['large_file_handling'] else '失敗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if results['large_file_handling'] else 'red')
    ax5.axis('off')

    # === セキュリティテスト ===
    ax6 = plt.subplot(gs[3, 2:])
    box_color = 'green' if results['security_analysis'] else 'red'
    ax6.add_patch(
        patches.Rectangle(
            (0.01, 0.01), 0.98, 0.98,
            fill=False, edgecolor=box_color, linewidth=2
        )
    )
    ax6.text(0.5, 0.8, 'セキュリティテスト',
             horizontalalignment='center', fontsize=14)
    ax6.text(0.5, 0.6, '✓ 改ざん検出',
             horizontalalignment='center', fontsize=10)
    ax6.text(0.5, 0.4, '✓ バックドアなし',
             horizontalalignment='center', fontsize=10)
    ax6.text(0.5, 0.2, '結果: ' + ('成功' if results['security_analysis'] else '失敗'),
             horizontalalignment='center', fontsize=12,
             color='lime' if results['security_analysis'] else 'red')
    ax6.axis('off')

    # 全体の結論
    all_success = all([
        results['basic_functionality'],
        results['data_integrity'],
        results['token_binding'],
        results['true_encryption'],
        results['false_encryption'],
        results['large_file_handling'],
        results['security_analysis']
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

    return all_success

def main():
    """メイン関数"""
    print("ハニーポットカプセル検査の結果を可視化します...")

    try:
        # 最新のログファイルを検索
        log_file = find_latest_log()
        print(f"ログファイル: {log_file}")

        # ログファイルを解析
        results = parse_log_file(log_file)

        # 結果画像を作成
        success = create_result_image(results)

        if success:
            print("✅ すべてのテストに合格しました")
        else:
            print("❌ 一部のテストに失敗しました")

    except Exception as e:
        print(f"エラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()