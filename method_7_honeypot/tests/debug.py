#!/usr/bin/env python3
"""
暗号学的ハニーポット方式 - デバッグ支援スクリプト

このスクリプトは、ハニーポット暗号方式の主要な機能の内部動作を
可視化し、デバッグを支援します。トラップドア関数、鍵判定、
ハニーポットカプセルなどの動作を段階的に表示します。
"""

import os
import sys
import time
import json
import base64
import hashlib
import binascii
import tempfile
import argparse
import datetime
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from typing import Dict, Tuple, Any, Optional, List, Union

# モジュールパスの設定
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ハニーポット方式のモジュールインポート
from method_7_honeypot.trapdoor import (
    create_master_key, create_trapdoor_parameters,
    derive_keys_from_trapdoor, KEY_TYPE_TRUE, KEY_TYPE_FALSE,
    generate_honey_token
)
from method_7_honeypot.key_verification import (
    verify_key_type, get_signature_key
)
from method_7_honeypot.deception import (
    DynamicPathSelector, ObfuscatedVerifier,
    verify_with_tamper_resistance
)
from method_7_honeypot.honeypot_capsule import (
    create_honeypot_file, extract_data_from_honeypot,
    validate_honeypot_signature
)
from method_7_honeypot.config import (
    SYMMETRIC_KEY_SIZE, DECISION_THRESHOLD,
    RANDOMIZATION_FACTOR, DYNAMIC_ROUTE_COUNT
)

# matplotlib設定
plt.style.use('dark_background')

# 出力ディレクトリの設定
OUTPUT_DIR = Path("test_output")
OUTPUT_DIR.mkdir(exist_ok=True)


def debug_trapdoor_function():
    """
    トラップドア関数のデバッグ
    """
    print("=== トラップドア関数のデバッグ ===")

    # マスター鍵の生成
    master_key = create_master_key()
    print(f"マスター鍵: {binascii.hexlify(master_key).decode()}")

    # トラップドアパラメータの生成
    params = create_trapdoor_parameters(master_key)
    print("\nトラップドアパラメータ:")
    for key, value in params.items():
        if isinstance(value, bytes):
            print(f"  {key}: {binascii.hexlify(value).decode()[:16]}... (バイナリデータ)")
        else:
            print(f"  {key}: {value}")

    # 鍵ペアの導出
    keys, salt = derive_keys_from_trapdoor(params)
    print(f"\n暗号用ソルト: {binascii.hexlify(salt).decode()}")
    print(f"正規鍵: {binascii.hexlify(keys[KEY_TYPE_TRUE]).decode()}")
    print(f"非正規鍵: {binascii.hexlify(keys[KEY_TYPE_FALSE]).decode()}")

    # 鍵の判別テスト
    signature_key = params.get('signature_key')
    if signature_key:
        true_result = verify_key_type(keys[KEY_TYPE_TRUE], signature_key, params)
        false_result = verify_key_type(keys[KEY_TYPE_FALSE], signature_key, params)
        print(f"\n鍵判別テスト:")
        print(f"  正規鍵の判別結果: {true_result}")
        print(f"  非正規鍵の判別結果: {false_result}")

    # ハニートークンの生成
    true_token = generate_honey_token(KEY_TYPE_TRUE, params)
    false_token = generate_honey_token(KEY_TYPE_FALSE, params)
    print(f"\nハニートークン:")
    print(f"  正規トークン: {binascii.hexlify(true_token).decode()[:16]}...")
    print(f"  非正規トークン: {binascii.hexlify(false_token).decode()[:16]}...")

    return master_key, params, keys, salt, true_token, false_token


def debug_dynamic_path_selection(master_key, true_key, false_key, true_token, false_token):
    """
    動的経路選択のデバッグ

    Args:
        master_key: マスター鍵
        true_key: 正規鍵
        false_key: 非正規鍵
        true_token: 正規トークン
        false_token: 非正規トークン
    """
    print("\n=== 動的経路選択のデバッグ ===")

    # 動的経路選択器のインスタンス化
    selector = DynamicPathSelector(master_key)
    print(f"経路選択器を初期化しました")
    print(f"判定関数の数: {len(selector.decision_functions)}")
    print(f"経路の数: {len(selector.paths)}")

    # 経路選択の結果
    true_path = selector.select_path(true_key, true_token)
    false_path = selector.select_path(false_key, false_token)
    print(f"\n経路選択結果:")
    print(f"  正規鍵の経路: {true_path}")
    print(f"  非正規鍵の経路: {false_path}")

    # 判定関数の詳細
    print("\n判定関数の詳細:")
    for i, (func, weight) in enumerate(selector.decision_functions):
        try:
            true_result = func(true_key, true_token)
            false_result = func(false_key, false_token)
            print(f"  関数 {i+1} (重み {weight}):")
            print(f"    正規鍵の判定: {true_result}")
            print(f"    非正規鍵の判定: {false_result}")
        except Exception as e:
            print(f"  関数 {i+1} (重み {weight}):")
            print(f"    エラー: {e}")

    # 判定結果グラフの作成
    plt.figure(figsize=(10, 6))

    # データ準備
    functions = [f"関数{i+1}" for i in range(len(selector.decision_functions))]
    weights = [weight for _, weight in selector.decision_functions]
    true_results = []
    false_results = []

    for func, _ in selector.decision_functions:
        try:
            true_results.append(1 if func(true_key, true_token) else 0)
            false_results.append(1 if func(false_key, false_token) else 0)
        except Exception:
            true_results.append(0)
            false_results.append(0)

    # グラフ作成
    bar_width = 0.35
    index = np.arange(len(functions))

    plt.bar(index, true_results, bar_width, color='#03dac6', label='正規鍵')
    plt.bar(index + bar_width, false_results, bar_width, color='#cf6679', label='非正規鍵')

    for i, w in enumerate(weights):
        plt.text(i-0.1, -0.1, f"w={w}", fontsize=9, rotation=45)

    plt.xlabel('判定関数')
    plt.ylabel('判定結果 (1=True, 0=False)')
    plt.title('各判定関数の判定結果')
    plt.xticks(index + bar_width/2, functions)
    plt.legend()
    plt.ylim(-0.2, 1.2)

    # グリッド追加
    plt.grid(axis='y', linestyle='--', alpha=0.3)

    # タイムスタンプ生成
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / f"dynamic_path_results_{timestamp}.png"

    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()

    print(f"\n判定関数の結果グラフを保存しました: {output_file}")


def debug_obfuscated_verifier(master_key, true_key, false_key, true_token, false_token):
    """
    難読化検証機構のデバッグ

    Args:
        master_key: マスター鍵
        true_key: 正規鍵
        false_key: 非正規鍵
        true_token: 正規トークン
        false_token: 非正規トークン
    """
    print("\n=== 難読化検証機構のデバッグ ===")

    # 難読化検証機構のインスタンス化
    verifier = ObfuscatedVerifier(master_key)
    print(f"難読化検証機構を初期化しました")

    # 検証結果
    true_verify = verifier.verify(true_key, true_token)
    false_verify = verifier.verify(false_key, false_token)
    print(f"\n検証結果:")
    print(f"  正規鍵の検証: {true_verify}")
    print(f"  非正規鍵の検証: {false_verify}")

    # ランダム鍵のテスト
    print("\nランダム鍵のテスト (10回):")
    authentic_count = 0
    for i in range(10):
        random_key = os.urandom(SYMMETRIC_KEY_SIZE)
        is_authentic = verifier.verify(random_key, true_token)
        print(f"  ランダム鍵 {i+1}: {'正規' if is_authentic else '非正規'}")
        if is_authentic:
            authentic_count += 1

    print(f"\nランダム鍵の正規判定率: {authentic_count/10:.1%}")


def debug_tamper_resistance(true_key, false_key, true_token, false_token, params):
    """
    改変耐性機能のデバッグ

    Args:
        true_key: 正規鍵
        false_key: 非正規鍵
        true_token: 正規トークン
        false_token: 非正規トークン
        params: トラップドアパラメータ
    """
    print("\n=== 改変耐性機能のデバッグ ===")

    # 通常の検証
    print("標準検証:")
    true_result = verify_with_tamper_resistance(true_key, true_token, params)
    false_result = verify_with_tamper_resistance(false_key, false_token, params)
    print(f"  正規鍵の検証結果: {true_result}")
    print(f"  非正規鍵の検証結果: {false_result}")

    # 閾値変動のシミュレーション
    print("\n閾値変動のシミュレーション (10回):")
    true_results = []
    false_results = []

    for i in range(10):
        # エントロピー要素を変える
        from method_7_honeypot.deception import _adjust_decision_threshold, _gather_entropy
        entropy = _gather_entropy()
        _adjust_decision_threshold(entropy)

        # 検証実行
        true_result = verify_with_tamper_resistance(true_key, true_token, params)
        false_result = verify_with_tamper_resistance(false_key, false_token, params)
        true_results.append(true_result)
        false_results.append(false_result)

        # 結果表示
        from method_7_honeypot.deception import _get_current_decision_threshold
        current_threshold = _get_current_decision_threshold()
        print(f"  試行 {i+1} (閾値={current_threshold}): 正規={true_result}, 非正規={false_result}")

    # 一貫性チェック
    true_consistent = all(r == true_results[0] for r in true_results)
    false_consistent = all(r == false_results[0] for r in false_results)
    print(f"\n一貫性チェック:")
    print(f"  正規鍵の一貫性: {'OK' if true_consistent else 'NG'}")
    print(f"  非正規鍵の一貫性: {'OK' if false_consistent else 'NG'}")


def debug_honeypot_capsule(true_key, false_key, params):
    """
    ハニーポットカプセルのデバッグ

    Args:
        true_key: 正規鍵
        false_key: 非正規鍵
        params: トラップドアパラメータ
    """
    print("\n=== ハニーポットカプセルのデバッグ ===")

    # テストデータの準備
    true_data = b"This is secret true data!"
    false_data = b"This is fake false data."

    # メタデータの作成
    metadata = {
        "format": "honeypot",
        "version": "1.0",
        "algorithm": "aes256-cbc",
        "timestamp": datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
        "true_size": len(true_data),
        "false_size": len(false_data),
        "true_iv": base64.b64encode(os.urandom(16)).decode('ascii'),
        "false_iv": base64.b64encode(os.urandom(16)).decode('ascii')
    }

    print("テストデータ:")
    print(f"  正規データ: {true_data}")
    print(f"  非正規データ: {false_data}")

    # ハニーポットカプセルの作成
    capsule_data = create_honeypot_file(true_data, false_data, params, metadata)
    print(f"\nハニーポットカプセル作成完了: {len(capsule_data)} バイト")

    # 署名検証
    is_valid = validate_honeypot_signature(metadata, capsule_data)
    print(f"署名検証結果: {'成功' if is_valid else '失敗'}")

    # カプセルからのデータ抽出
    try:
        true_extracted = extract_data_from_honeypot(capsule_data, true_key, metadata)
        print(f"\n正規鍵でのデータ抽出: {len(true_extracted)} バイト")
        print(f"  抽出データ: {true_extracted}")
    except Exception as e:
        print(f"\n正規鍵でのデータ抽出に失敗: {e}")

    try:
        false_extracted = extract_data_from_honeypot(capsule_data, false_key, metadata)
        print(f"\n非正規鍵でのデータ抽出: {len(false_extracted)} バイト")
        print(f"  抽出データ: {false_extracted}")
    except Exception as e:
        print(f"\n非正規鍵でのデータ抽出に失敗: {e}")

    # ランダム鍵でのテスト
    print("\nランダム鍵でのテスト:")
    random_key = os.urandom(SYMMETRIC_KEY_SIZE)
    try:
        random_extracted = extract_data_from_honeypot(capsule_data, random_key, metadata)
        print(f"  抽出データ: {random_extracted}")
    except Exception as e:
        print(f"  抽出失敗: {e}")


def main():
    """
    メイン関数
    """
    parser = argparse.ArgumentParser(description='暗号学的ハニーポット方式のデバッグツール')
    parser.add_argument('--all', action='store_true', help='すべてのデバッグを実行します')
    parser.add_argument('--trapdoor', action='store_true', help='トラップドア関数のデバッグ')
    parser.add_argument('--path', action='store_true', help='動的経路選択のデバッグ')
    parser.add_argument('--verifier', action='store_true', help='難読化検証機構のデバッグ')
    parser.add_argument('--tamper', action='store_true', help='改変耐性機能のデバッグ')
    parser.add_argument('--capsule', action='store_true', help='ハニーポットカプセルのデバッグ')

    args = parser.parse_args()

    # すべてのオプションが指定されていない場合は--allを設定
    if not (args.trapdoor or args.path or args.verifier or args.tamper or args.capsule):
        args.all = True

    # タイムスタンプ生成
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # ログファイルの設定
    log_file = OUTPUT_DIR / f"debug_log_{timestamp}.txt"

    # 元の標準出力を保存
    original_stdout = sys.stdout

    # 結果をファイルとコンソールの両方に出力
    with open(log_file, 'w') as f:
        # 多重出力クラス
        class MultiOutput:
            def write(self, s):
                original_stdout.write(s)
                f.write(s)
            def flush(self):
                original_stdout.flush()
                f.flush()

        sys.stdout = MultiOutput()

        try:
            print(f"=== 暗号学的ハニーポット方式 - デバッグツール ===")
            print(f"実行日時: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Python バージョン: {sys.version}")
            print(f"ログファイル: {log_file}")
            print()

            # トラップドア関数のデバッグ
            if args.all or args.trapdoor:
                master_key, params, keys, salt, true_token, false_token = debug_trapdoor_function()
            else:
                # 最小限のセットアップ
                master_key = create_master_key()
                params = create_trapdoor_parameters(master_key)
                keys, salt = derive_keys_from_trapdoor(params)
                true_token = generate_honey_token(KEY_TYPE_TRUE, params)
                false_token = generate_honey_token(KEY_TYPE_FALSE, params)

            # 動的経路選択のデバッグ
            if args.all or args.path:
                debug_dynamic_path_selection(
                    master_key,
                    keys[KEY_TYPE_TRUE],
                    keys[KEY_TYPE_FALSE],
                    true_token,
                    false_token
                )

            # 難読化検証機構のデバッグ
            if args.all or args.verifier:
                debug_obfuscated_verifier(
                    master_key,
                    keys[KEY_TYPE_TRUE],
                    keys[KEY_TYPE_FALSE],
                    true_token,
                    false_token
                )

            # 改変耐性機能のデバッグ
            if args.all or args.tamper:
                debug_tamper_resistance(
                    keys[KEY_TYPE_TRUE],
                    keys[KEY_TYPE_FALSE],
                    true_token,
                    false_token,
                    params
                )

            # ハニーポットカプセルのデバッグ
            if args.all or args.capsule:
                debug_honeypot_capsule(
                    keys[KEY_TYPE_TRUE],
                    keys[KEY_TYPE_FALSE],
                    params
                )

            print("\n=== デバッグ完了 ===")
            print(f"ログファイル: {log_file}")

        finally:
            # 標準出力を元に戻す
            sys.stdout = original_stdout

    print(f"デバッグが完了しました。ログファイル: {log_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())