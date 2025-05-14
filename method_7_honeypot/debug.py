#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - デバッグ支援スクリプト

主要な機能の内部動作を可視化し、デバッグに役立つ情報を提供します。
開発・テスト用途のみに使用し、本番環境では使用しないでください。
"""

import os
import sys
import argparse
import binascii
import json
import time
import hashlib
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from pathlib import Path

# 内部モジュールのインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, generate_honey_token,
    evaluate_key_type, KEY_TYPE_TRUE, KEY_TYPE_FALSE
)
from method_7_honeypot.key_verification import (
    verify_key_and_select_path,
    KeyVerifier, HoneyTokenManager
)
from method_7_honeypot.deception import (
    verify_with_tamper_resistance,
    DynamicPathSelector, ObfuscatedVerifier
)
from method_7_honeypot.honeypot_capsule import (
    HoneypotCapsule, HoneypotCapsuleFactory,
    create_honeypot_file, read_data_from_honeypot_file
)

# matplotlib設定
plt.style.use('dark_background')


class DebugVisualizer:
    """デバッグ情報の視覚化を行うクラス"""

    def __init__(self, output_dir='test_output'):
        """初期化"""
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

    def save_key_verification_diagram(self, master_key, true_key, false_key, true_result, false_result):
        """鍵検証フローの図を生成"""
        # 図の作成
        fig, ax = plt.subplots(figsize=(10, 6))

        # データ
        keys = ['正規鍵', '非正規鍵']
        results = [1 if true_result == KEY_TYPE_TRUE else 0,
                   1 if false_result == KEY_TYPE_FALSE else 0]
        expected = [1, 1]

        # バーチャート
        x = np.arange(len(keys))
        width = 0.35

        ax.bar(x - width/2, results, width, label='検証結果', color='#03dac6')
        ax.bar(x + width/2, expected, width, label='期待値', color='#bb86fc')

        # 装飾
        ax.set_ylabel('検証結果 (1=正解, 0=不正解)')
        ax.set_title('鍵検証結果')
        ax.set_xticks(x)
        ax.set_xticklabels(keys)
        ax.legend()
        ax.grid(True, linestyle='--', alpha=0.7)

        # 図の保存
        output_file = os.path.join(self.output_dir, f'key_verification_{self.timestamp}.png')
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close(fig)

        return output_file

    def save_tamper_resistance_diagram(self, results, attempts=10):
        """改変耐性の図を生成"""
        # 図の作成
        fig, ax = plt.subplots(figsize=(10, 6))

        # データ準備
        categories = ['正規鍵判定', '非正規鍵判定']
        consistency = [
            sum(1 for r in results['true_results'] if r == KEY_TYPE_TRUE) / attempts * 100,
            sum(1 for r in results['false_results'] if r == KEY_TYPE_FALSE) / attempts * 100
        ]

        # バーチャート
        bars = ax.bar(categories, consistency, color=['#03dac6', '#cf6679'])

        # 装飾
        ax.set_ylabel('一貫性 (%)')
        ax.set_title('改変耐性テスト - 判定の一貫性')
        ax.set_ylim(0, 105)
        ax.grid(True, linestyle='--', alpha=0.7)

        # 数値を表示
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%',
                    ha='center', va='bottom')

        # 図の保存
        output_file = os.path.join(self.output_dir, f'tamper_resistance_{self.timestamp}.png')
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close(fig)

        return output_file

    def save_capsule_structure(self, capsule):
        """カプセル構造の図を生成"""
        # 図の作成
        fig, ax = plt.subplots(figsize=(12, 6))

        # ブロック情報の収集
        block_types = []
        block_sizes = []
        colors = []

        for block in capsule.blocks:
            if block['type'] == 1:  # DATA_TYPE_TRUE
                block_types.append("真のデータ")
                colors.append('#03dac6')
            elif block['type'] == 2:  # DATA_TYPE_FALSE
                block_types.append("偽のデータ")
                colors.append('#cf6679')
            elif block['type'] == 3:  # DATA_TYPE_META
                block_types.append("メタデータ")
                colors.append('#bb86fc')
            else:  # DATA_TYPE_DUMMY
                block_types.append("ダミーデータ")
                colors.append('#ffb86c')

            block_sizes.append(block['size'])

        # バーチャート（水平）
        y_pos = np.arange(len(block_types))
        bars = ax.barh(y_pos, block_sizes, color=colors)

        # 装飾
        ax.set_yticks(y_pos)
        ax.set_yticklabels(block_types)
        ax.set_xlabel('サイズ (バイト)')
        ax.set_title('ハニーポットカプセル構造')
        ax.grid(True, linestyle='--', alpha=0.7)

        # 数値を表示
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width + 1, bar.get_y() + bar.get_height()/2,
                    f'{width} bytes',
                    ha='left', va='center')

        # 図の保存
        output_file = os.path.join(self.output_dir, f'capsule_structure_{self.timestamp}.png')
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close(fig)

        return output_file


def debug_key_generation():
    """鍵生成と検証のデバッグ"""
    print("=== 鍵生成と検証のデバッグ ===")
    visualizer = DebugVisualizer()

    # マスター鍵の生成
    master_key = create_master_key()
    print(f"マスター鍵: {binascii.hexlify(master_key).decode()}")

    # トラップドアパラメータの生成
    params = create_trapdoor_parameters(master_key)
    print(f"パラメータ生成完了")
    print(f"モジュラス (n) ビット長: {params['n'].bit_length()}")

    # 鍵の導出
    keys, salt = derive_keys_from_trapdoor(params)
    print(f"正規鍵: {binascii.hexlify(keys[KEY_TYPE_TRUE]).decode()}")
    print(f"非正規鍵: {binascii.hexlify(keys[KEY_TYPE_FALSE]).decode()}")

    # ハニートークンの生成
    true_token = generate_honey_token(KEY_TYPE_TRUE, params)
    false_token = generate_honey_token(KEY_TYPE_FALSE, params)
    print(f"正規トークン: {binascii.hexlify(true_token[:16]).decode()}...")
    print(f"非正規トークン: {binascii.hexlify(false_token[:16]).decode()}...")

    # 鍵検証
    print("\n鍵検証テスト:")
    true_result = evaluate_key_type(keys[KEY_TYPE_TRUE], params, salt)
    false_result = evaluate_key_type(keys[KEY_TYPE_FALSE], params, salt)

    print(f"正規鍵の評価結果: {true_result}")
    print(f"非正規鍵の評価結果: {false_result}")

    # 鍵検証の図を生成
    diagram_file = visualizer.save_key_verification_diagram(
        master_key, keys[KEY_TYPE_TRUE], keys[KEY_TYPE_FALSE], true_result, false_result
    )
    print(f"鍵検証図: {diagram_file}")

    return {
        'master_key': master_key,
        'params': params,
        'keys': keys,
        'salt': salt,
        'tokens': {
            KEY_TYPE_TRUE: true_token,
            KEY_TYPE_FALSE: false_token
        }
    }


def debug_key_verification(key_data=None):
    """鍵検証機構のデバッグ"""
    print("\n=== 鍵検証機構のデバッグ ===")

    if key_data is None:
        # 新しい鍵データを生成
        key_data = debug_key_generation()

    params = key_data['params']
    keys = key_data['keys']
    salt = key_data['salt']

    # KeyVerifierのテスト
    verifier = KeyVerifier(params, salt)

    # 正規鍵の検証
    start_time = time.time()
    true_key_type = verifier.verify_key(keys[KEY_TYPE_TRUE])
    true_verify_time = time.time() - start_time

    # 非正規鍵の検証
    start_time = time.time()
    false_key_type = verifier.verify_key(keys[KEY_TYPE_FALSE])
    false_verify_time = time.time() - start_time

    print(f"正規鍵の検証結果: {true_key_type}, 時間: {true_verify_time:.6f}秒")
    print(f"非正規鍵の検証結果: {false_key_type}, 時間: {false_verify_time:.6f}秒")
    print(f"時間差: {abs(true_verify_time - false_verify_time):.6f}秒")

    # 完全な検証フロー
    print("\n完全な検証フロー:")
    true_key_type, true_context = verify_key_and_select_path(
        keys[KEY_TYPE_TRUE], params, salt
    )
    false_key_type, false_context = verify_key_and_select_path(
        keys[KEY_TYPE_FALSE], params, salt
    )

    print(f"正規鍵の処理パス: {true_context['path']}")
    print(f"非正規鍵の処理パス: {false_context['path']}")

    # HoneyTokenManagerのテスト
    token_manager = HoneyTokenManager(params)
    true_token = token_manager.get_token(KEY_TYPE_TRUE)
    false_token = token_manager.get_token(KEY_TYPE_FALSE)

    valid_true, key_type_true = token_manager.verify_token(true_token, keys[KEY_TYPE_TRUE])
    valid_false, key_type_false = token_manager.verify_token(false_token, keys[KEY_TYPE_FALSE])

    print(f"正規トークン検証: 有効={valid_true}, 鍵タイプ={key_type_true}")
    print(f"非正規トークン検証: 有効={valid_false}, 鍵タイプ={key_type_false}")


def debug_tamper_resistance(key_data=None):
    """改変耐性機構のデバッグ"""
    print("\n=== 改変耐性機構のデバッグ ===")
    visualizer = DebugVisualizer()

    if key_data is None:
        # 新しい鍵データを生成
        key_data = debug_key_generation()

    params = key_data['params']
    keys = key_data['keys']
    tokens = key_data['tokens']

    # DynamicPathSelectorのテスト
    print("\nDynamicPathSelector テスト:")
    selector = DynamicPathSelector(params['seed'])
    true_path = selector.select_path(keys[KEY_TYPE_TRUE], tokens[KEY_TYPE_TRUE])
    false_path = selector.select_path(keys[KEY_TYPE_FALSE], tokens[KEY_TYPE_FALSE])

    print(f"正規鍵の経路選択: {true_path}")
    print(f"非正規鍵の経路選択: {false_path}")

    # ObfuscatedVerifierのテスト
    print("\nObfuscatedVerifier テスト:")
    verifier = ObfuscatedVerifier(params['seed'])
    true_verify = verifier.verify(keys[KEY_TYPE_TRUE], tokens[KEY_TYPE_TRUE])
    false_verify = verifier.verify(keys[KEY_TYPE_FALSE], tokens[KEY_TYPE_FALSE])

    print(f"正規鍵の検証結果: {true_verify}")
    print(f"非正規鍵の検証結果: {false_verify}")

    # 改変耐性検証の一貫性テスト
    print("\n改変耐性の一貫性テスト:")
    attempts = 10
    true_results = []
    false_results = []

    for i in range(attempts):
        true_result = verify_with_tamper_resistance(
            keys[KEY_TYPE_TRUE], tokens[KEY_TYPE_TRUE], params
        )
        false_result = verify_with_tamper_resistance(
            keys[KEY_TYPE_FALSE], tokens[KEY_TYPE_FALSE], params
        )

        true_results.append(true_result)
        false_results.append(false_result)

    true_consistent = all(r == true_results[0] for r in true_results)
    false_consistent = all(r == false_results[0] for r in false_results)

    print(f"正規鍵の一貫性: {true_consistent} ({true_results.count(KEY_TYPE_TRUE)}/{attempts}が{KEY_TYPE_TRUE})")
    print(f"非正規鍵の一貫性: {false_consistent} ({false_results.count(KEY_TYPE_FALSE)}/{attempts}が{KEY_TYPE_FALSE})")

    # 改変耐性の図を生成
    results = {
        'true_results': true_results,
        'false_results': false_results
    }
    diagram_file = visualizer.save_tamper_resistance_diagram(results, attempts)
    print(f"改変耐性図: {diagram_file}")


def debug_honeypot_capsule(key_data=None):
    """ハニーポットカプセルのデバッグ"""
    print("\n=== ハニーポットカプセルのデバッグ ===")
    visualizer = DebugVisualizer()

    if key_data is None:
        # 新しい鍵データを生成
        key_data = debug_key_generation()

    params = key_data['params']

    # テストデータの作成
    true_data = b"This is the true data that should be revealed with the correct key."
    false_data = b"This is the false data that will be shown with an incorrect key."

    # メタデータの作成
    metadata = {
        "description": "Debug honeypot capsule",
        "timestamp": int(datetime.now().timestamp()),
        "version": "1.0",
        "debug": True
    }

    # カプセルの作成
    print("\nカプセル作成:")
    factory = HoneypotCapsuleFactory(params)
    capsule = factory.create_capsule(true_data, false_data, metadata)

    print(f"ブロック数: {len(capsule.blocks)}")

    # ブロック情報の表示
    for i, block in enumerate(capsule.blocks):
        block_type = "不明"
        if block['type'] == 1:
            block_type = "真のデータ"
        elif block['type'] == 2:
            block_type = "偽のデータ"
        elif block['type'] == 3:
            block_type = "メタデータ"
        elif block['type'] == 4:
            block_type = "ダミーデータ"

        print(f"ブロック {i+1}: タイプ={block_type}, サイズ={block['size']}バイト")

    # カプセル構造の図を生成
    diagram_file = visualizer.save_capsule_structure(capsule)
    print(f"カプセル構造図: {diagram_file}")

    # シリアライズとデシリアライズのテスト
    print("\nシリアライズとデシリアライズ:")
    serialized = capsule.serialize()
    print(f"シリアライズされたカプセルのサイズ: {len(serialized)}バイト")

    restored = HoneypotCapsule.deserialize(serialized)
    print(f"復元されたブロック数: {len(restored.blocks)}")
    print(f"メタデータ: {json.dumps(restored.metadata, indent=2)}")

    # ハニーポットファイル関数のテスト
    print("\nハニーポットファイル関数:")
    file_data = create_honeypot_file(true_data, false_data, params, metadata)
    print(f"ハニーポットファイルのサイズ: {len(file_data)}バイト")

    # データの読み込み
    true_extracted, meta = read_data_from_honeypot_file(file_data, KEY_TYPE_TRUE)
    false_extracted, _ = read_data_from_honeypot_file(file_data, KEY_TYPE_FALSE)

    print(f"抽出された真のデータ: {true_extracted.decode('utf-8')}")
    print(f"抽出された偽のデータ: {false_extracted.decode('utf-8')}")

    # データの検証
    true_match = true_extracted == true_data
    false_match = false_extracted == false_data
    print(f"真のデータ一致: {true_match}")
    print(f"偽のデータ一致: {false_match}")


def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(
        description="暗号学的ハニーポット方式のデバッグツール"
    )

    parser.add_argument(
        '--key-gen',
        action='store_true',
        help='鍵生成と検証のデバッグ'
    )

    parser.add_argument(
        '--key-verify',
        action='store_true',
        help='鍵検証機構のデバッグ'
    )

    parser.add_argument(
        '--tamper',
        action='store_true',
        help='改変耐性機構のデバッグ'
    )

    parser.add_argument(
        '--capsule',
        action='store_true',
        help='ハニーポットカプセルのデバッグ'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='すべての機能をデバッグ'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default='test_output',
        help='出力ディレクトリ'
    )

    args = parser.parse_args()

    # 出力ディレクトリの作成
    os.makedirs(args.output_dir, exist_ok=True)

    # デフォルトですべての機能をデバッグ
    if not (args.key_gen or args.key_verify or args.tamper or args.capsule):
        args.all = True

    # 鍵データを共有して効率化
    key_data = None

    if args.key_gen or args.all:
        key_data = debug_key_generation()

    if args.key_verify or args.all:
        debug_key_verification(key_data)

    if args.tamper or args.all:
        debug_tamper_resistance(key_data)

    if args.capsule or args.all:
        debug_honeypot_capsule(key_data)

    return 0


if __name__ == "__main__":
    sys.exit(main())