import matplotlib.pyplot as plt
import matplotlib as mpl
import datetime
import sys
import textwrap

# テキストをテキストブロックに変換する関数
def wrap_text(text, width=80):
    return '\n'.join(textwrap.wrap(text, width))

# ターミナル風のテーマ設定
mpl.style.use('dark_background')
plt.rcParams['figure.facecolor'] = '#2e2e2e'
plt.rcParams['axes.facecolor'] = '#2e2e2e'
plt.rcParams['text.color'] = '#e0e0e0'

# タイムスタンプ作成
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

# テストログの読み込み
with open('test_output/honeypot_capsule_test.log', 'r') as f:
    test_log = f.read()

with open('test_output/honeypot_capsule_debug.log', 'r') as f:
    debug_log_parts = f.read().split('---')
    debug_log = '\n'.join(debug_log_parts[0:2]).strip() if len(debug_log_parts) > 1 else debug_log_parts[0]

# 画像サイズとDPI設定
plt.figure(figsize=(12, 12), dpi=100)

# サブプロットを作成
ax1 = plt.subplot(2, 1, 1)
ax1.text(0.05, 0.95, f'ハニーポットカプセルテスト結果 ({timestamp})', fontsize=14, fontweight='bold', va='top')
ax1.text(0.05, 0.85, test_log, fontsize=10, family='monospace', va='top')
ax1.axis('off')

ax2 = plt.subplot(2, 1, 2)
ax2.text(0.05, 0.95, 'ハニーポットカプセルデバッグ出力 (抜粋)', fontsize=14, fontweight='bold', va='top')
ax2.text(0.05, 0.85, debug_log[:1000] + '...', fontsize=9, family='monospace', va='top')
ax2.axis('off')

# 保存
plt.tight_layout()
output_file = f'test_output/honeypot_capsule_test_{timestamp}.png'
plt.savefig(output_file, bbox_inches='tight')
print(f'{output_file} に画像を保存しました')
print(f'https://github.com/pacific-system/secret-sharing-demos-20250510/blob/main/{output_file}?raw=true')