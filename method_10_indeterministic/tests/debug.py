#!/usr/bin/env python3
"""
不確定性転写暗号化方式 - デバッグ支援スクリプト

主要な機能の内部動作を可視化します。
"""

import os
import sys
import time
import random
import argparse
import datetime
import binascii
import hashlib
import numpy as np
import matplotlib.pyplot as plt
from typing import List, Dict, Any, Tuple, Optional

# テスト用にモジュールパスを追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# テスト対象のモジュールをインポート
try:
    from method_10_indeterministic.config import (
        TRUE_TEXT_PATH, FALSE_TEXT_PATH, KEY_SIZE_BYTES,
        STATE_MATRIX_SIZE, STATE_TRANSITIONS, OUTPUT_EXTENSION,
        ENTROPY_POOL_SIZE, PROBABILITY_STEPS
    )
    from method_10_indeterministic.encrypt import encrypt_files, generate_master_key
    from method_10_indeterministic.decrypt import decrypt_file, determine_path_type

    # 以下のモジュールは、後続の子Issueで実装予定
    # ここではtryでインポートを試みる
    try:
        from method_10_indeterministic.indeterministic import create_indeterministic_capsule
        from method_10_indeterministic.state_matrix import generate_state_matrix
        from method_10_indeterministic.probability_engine import calculate_probability_distribution
        from method_10_indeterministic.entropy_injector import inject_entropy
        HAVE_ADVANCED_MODULES = True
    except ImportError:
        HAVE_ADVANCED_MODULES = False

except ImportError as e:
    print(f"エラー: モジュールのインポートに失敗しました: {e}")
    sys.exit(1)

# テスト出力ディレクトリ
TEST_OUTPUT_DIR = "test_output"

def setup():
    """
    デバッグ環境のセットアップ
    """
    # 出力ディレクトリの作成
    os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

    # テスト用ファイルの存在確認
    assert os.path.exists(TRUE_TEXT_PATH), f"真のテキストファイル {TRUE_TEXT_PATH} が見つかりません"
    assert os.path.exists(FALSE_TEXT_PATH), f"偽のテキストファイル {FALSE_TEXT_PATH} が見つかりません"

    # タイムスタンプ
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # デバッグログファイル
    log_file = os.path.join(TEST_OUTPUT_DIR, f"debug_log_{timestamp}.txt")

    return timestamp, log_file

def debug_key_generation(log_file: str):
    """
    鍵生成のデバッグ

    Args:
        log_file: ログファイルのパス
    """
    print("\n===== 鍵生成のデバッグ =====")

    with open(log_file, 'a') as f:
        f.write("\n===== 鍵生成のデバッグ =====\n")

        # 複数の鍵を生成
        keys = [generate_master_key() for _ in range(5)]

        # 鍵の情報を表示
        for i, key in enumerate(keys):
            key_hex = binascii.hexlify(key).decode('ascii')
            key_hash = hashlib.sha256(key).hexdigest()
            f.write(f"鍵 {i+1}:\n")
            f.write(f"  バイナリ: {key}\n")
            f.write(f"  16進数: {key_hex}\n")
            f.write(f"  SHA-256: {key_hash}\n")

            # パスタイプを決定
            path_type = determine_path_type(key)
            f.write(f"  パスタイプ: {path_type}\n\n")

            # 画面にも出力
            print(f"鍵 {i+1}:")
            print(f"  16進数: {key_hex[:8]}...{key_hex[-8:]}")
            print(f"  パスタイプ: {path_type}")

    print("鍵生成のデバッグが完了しました")

def debug_path_determination(log_file: str, timestamp: str):
    """
    パス決定メカニズムのデバッグ

    Args:
        log_file: ログファイルのパス
        timestamp: タイムスタンプ
    """
    print("\n===== パス決定メカニズムのデバッグ =====")

    # 多数の鍵を生成して統計を取る
    num_keys = 1000
    keys = [generate_master_key() for _ in range(num_keys)]

    # パスタイプをカウント
    path_types = [determine_path_type(key) for key in keys]
    true_count = path_types.count("true")
    false_count = path_types.count("false")

    # 結果をファイルに書き込み
    with open(log_file, 'a') as f:
        f.write("\n===== パス決定メカニズムのデバッグ =====\n")
        f.write(f"生成鍵数: {num_keys}\n")
        f.write(f"真のパス数: {true_count} ({true_count/num_keys*100:.2f}%)\n")
        f.write(f"偽のパス数: {false_count} ({false_count/num_keys*100:.2f}%)\n\n")

        # 最初の10鍵の詳細
        f.write("最初の10鍵の詳細:\n")
        for i in range(min(10, num_keys)):
            key_hex = binascii.hexlify(keys[i]).decode('ascii')
            f.write(f"鍵 {i+1}: {key_hex[:8]}...{key_hex[-8:]} -> {path_types[i]}\n")

    # 画面に出力
    print(f"生成鍵数: {num_keys}")
    print(f"真のパス数: {true_count} ({true_count/num_keys*100:.2f}%)")
    print(f"偽のパス数: {false_count} ({false_count/num_keys*100:.2f}%)")

    # 分布のグラフを作成
    plt.figure(figsize=(10, 6))
    plt.bar(['真のパス', '偽のパス'], [true_count, false_count], color=['blue', 'orange'])
    plt.title('パスタイプ分布')
    plt.ylabel('鍵の数')
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # 50%ラインを表示
    plt.axhline(y=num_keys/2, color='r', linestyle='-', alpha=0.3)
    plt.text(0.5, num_keys/2 + 20, '50%ライン', color='r')

    # グラフを保存
    graph_path = os.path.join(TEST_OUTPUT_DIR, f"dynamic_path_results_{timestamp}.png")
    plt.savefig(graph_path)
    plt.close()

    print(f"パスタイプ分布グラフを生成しました: {graph_path}")

def debug_encryption_workflow(log_file: str, timestamp: str):
    """
    暗号化ワークフローのデバッグ

    Args:
        log_file: ログファイルのパス
        timestamp: タイムスタンプ
    """
    print("\n===== 暗号化ワークフローのデバッグ =====")

    # テスト用の出力ファイル
    encrypted_file = os.path.join(TEST_OUTPUT_DIR, f"debug_encrypt_{timestamp}.indet")

    with open(log_file, 'a') as f:
        f.write("\n===== 暗号化ワークフローのデバッグ =====\n")
        f.write(f"真のファイル: {TRUE_TEXT_PATH}\n")
        f.write(f"偽のファイル: {FALSE_TEXT_PATH}\n")
        f.write(f"出力ファイル: {encrypted_file}\n\n")

        start_time = time.time()

        # 暗号化を実行
        try:
            keys, metadata = encrypt_files(
                TRUE_TEXT_PATH,
                FALSE_TEXT_PATH,
                encrypted_file,
                verbose=True
            )

            end_time = time.time()
            elapsed = end_time - start_time

            f.write(f"暗号化成功: {elapsed:.2f}秒\n")
            f.write(f"メタデータ: {metadata}\n")
            f.write(f"鍵情報: マスター鍵({len(keys['master_key'])}バイト)\n\n")

            # 暗号化ファイルの情報
            file_size = os.path.getsize(encrypted_file)
            f.write(f"暗号化ファイルサイズ: {file_size} バイト\n")

            # 鍵からパスタイプを決定
            path_type = determine_path_type(keys["master_key"])
            f.write(f"マスター鍵のパスタイプ: {path_type}\n")

            # 画面に出力
            print(f"暗号化成功: {elapsed:.2f}秒")
            print(f"暗号化ファイル: {encrypted_file} ({file_size} バイト)")
            print(f"マスター鍵のパスタイプ: {path_type}")

        except Exception as e:
            f.write(f"暗号化エラー: {e}\n")
            print(f"暗号化エラー: {e}")
            import traceback
            traceback.print_exc(file=f)
            traceback.print_exc()
            return

    # 画面に出力
    print("暗号化ワークフローのデバッグが完了しました")

def debug_decryption_workflow(log_file: str, timestamp: str):
    """
    復号ワークフローのデバッグ

    Args:
        log_file: ログファイルのパス
        timestamp: タイムスタンプ
    """
    print("\n===== 復号ワークフローのデバッグ =====")

    # テスト用のファイル
    encrypted_file = os.path.join(TEST_OUTPUT_DIR, f"debug_encrypt_{timestamp}.indet")

    # 暗号化ファイルが存在しない場合は暗号化を実行
    if not os.path.exists(encrypted_file):
        print(f"暗号化ファイルが見つかりません。先に暗号化を実行します。")
        keys, metadata = encrypt_files(
            TRUE_TEXT_PATH,
            FALSE_TEXT_PATH,
            encrypted_file,
            verbose=True
        )
    else:
        # 新しい鍵を生成
        keys = {"master_key": generate_master_key()}

    with open(log_file, 'a') as f:
        f.write("\n===== 復号ワークフローのデバッグ =====\n")
        f.write(f"暗号化ファイル: {encrypted_file}\n")

        # マスター鍵のパスタイプを決定
        master_key = keys["master_key"]
        master_path_type = determine_path_type(master_key)

        f.write(f"マスター鍵: {binascii.hexlify(master_key).decode('ascii')}\n")
        f.write(f"マスター鍵のパスタイプ: {master_path_type}\n\n")

        # 復号を実行
        try:
            decrypted_file = os.path.join(TEST_OUTPUT_DIR, f"debug_decrypt_{master_path_type}_{timestamp}.txt")

            f.write(f"復号出力ファイル: {decrypted_file}\n")

            start_time = time.time()

            # 復号実行
            output_file = decrypt_file(
                encrypted_file,
                master_key,
                decrypted_file,
                verbose=True
            )

            end_time = time.time()
            elapsed = end_time - start_time

            f.write(f"復号成功: {elapsed:.2f}秒\n")
            f.write(f"出力ファイル: {output_file}\n\n")

            # 復号ファイルの内容を確認
            with open(output_file, 'rb') as df:
                decrypted_content = df.read()

            with open(TRUE_TEXT_PATH, 'rb') as tf:
                true_content = tf.read()

            with open(FALSE_TEXT_PATH, 'rb') as ff:
                false_content = ff.read()

            matches_true = (decrypted_content == true_content)
            matches_false = (decrypted_content == false_content)

            f.write(f"復号結果は真のファイルと一致: {matches_true}\n")
            f.write(f"復号結果は偽のファイルと一致: {matches_false}\n")

            # 予想されるパスと実際の結果を比較
            expected_match = (
                (master_path_type == "true" and matches_true) or
                (master_path_type == "false" and matches_false)
            )

            f.write(f"予想されるパスタイプと実際の結果は一致: {expected_match}\n")

            # 画面に出力
            print(f"復号成功: {elapsed:.2f}秒")
            print(f"出力ファイル: {output_file}")
            print(f"パスタイプ: {master_path_type}")
            print(f"復号結果は真のファイルと一致: {matches_true}")
            print(f"復号結果は偽のファイルと一致: {matches_false}")

        except Exception as e:
            f.write(f"復号エラー: {e}\n")
            print(f"復号エラー: {e}")
            import traceback
            traceback.print_exc(file=f)
            traceback.print_exc()

    print("復号ワークフローのデバッグが完了しました")

def debug_advanced_features(log_file: str, timestamp: str):
    """
    高度な機能のデバッグ（状態マトリクス、確率エンジンなど）

    Args:
        log_file: ログファイルのパス
        timestamp: タイムスタンプ
    """
    if not HAVE_ADVANCED_MODULES:
        print("\n===== 高度な機能のデバッグ =====")
        print("注意: 高度な機能モジュールが見つかりません。後続の子Issueで実装予定です。")

        with open(log_file, 'a') as f:
            f.write("\n===== 高度な機能のデバッグ =====\n")
            f.write("注意: 高度な機能モジュールが見つかりません。後続の子Issueで実装予定です。\n")

        return

    # 高度な機能があれば、ここでデバッグを実行
    # 実際の実装は後続の子Issueで行われる予定

    # 動作のプレースホルダーとして簡易な状態マトリクスをシミュレート
    print("\n===== 高度な機能のデバッグ (シミュレーション) =====")
    print("注意: この出力は実際の実装をシミュレートしたものです")

    with open(log_file, 'a') as f:
        f.write("\n===== 高度な機能のデバッグ (シミュレーション) =====\n")
        f.write("注意: この出力は実際の実装をシミュレートしたものです\n\n")

        # 状態マトリクスのシミュレーション
        f.write("状態マトリクスのシミュレーション:\n")
        matrix_size = STATE_MATRIX_SIZE
        simulated_matrix = np.random.rand(matrix_size, matrix_size)

        f.write(f"マトリクスサイズ: {matrix_size}x{matrix_size}\n")
        f.write("マトリクス（最初の3x3部分）:\n")
        for i in range(min(3, matrix_size)):
            f.write(f"  {' '.join(f'{v:.2f}' for v in simulated_matrix[i, :3])}\n")

        # 確率分布のシミュレーション
        f.write("\n確率分布のシミュレーション:\n")
        prob_steps = PROBABILITY_STEPS
        simulated_probs = np.random.beta(2, 5, prob_steps)

        f.write(f"確率ステップ数: {prob_steps}\n")
        f.write(f"最小確率: {simulated_probs.min():.4f}\n")
        f.write(f"最大確率: {simulated_probs.max():.4f}\n")
        f.write(f"平均確率: {simulated_probs.mean():.4f}\n")

        # エントロピー注入のシミュレーション
        f.write("\nエントロピー注入のシミュレーション:\n")
        pool_size = ENTROPY_POOL_SIZE
        simulated_entropy = os.urandom(min(100, pool_size))

        f.write(f"エントロピープールサイズ: {pool_size}バイト\n")
        f.write(f"エントロピーサンプル（最初の20バイト）: {binascii.hexlify(simulated_entropy[:20]).decode('ascii')}\n")

        # 状態遷移シミュレーション
        f.write("\n状態遷移シミュレーション:\n")
        transitions = STATE_TRANSITIONS

        f.write(f"遷移回数: {transitions}\n")

        # 簡易的な遷移シミュレーション
        initial_state = np.random.randint(0, 255, size=8)
        current_state = initial_state.copy()

        f.write(f"初期状態: {initial_state}\n")

        for i in range(transitions):
            next_state = (current_state + np.random.randint(1, 10, size=8)) % 256
            current_state = next_state

            if i < 3 or i >= transitions - 3:
                f.write(f"遷移 {i+1}: {current_state}\n")
            elif i == 3:
                f.write("...\n")

        f.write(f"最終状態: {current_state}\n")

    # 画面出力
    print("高度な機能のシミュレーションが完了しました")

def parse_arguments():
    """
    コマンドライン引数を解析

    Returns:
        解析された引数
    """
    parser = argparse.ArgumentParser(description="不確定性転写暗号化方式のデバッグツール")

    parser.add_argument(
        "--all",
        action="store_true",
        help="すべてのデバッグ機能を実行"
    )

    parser.add_argument(
        "--keys",
        action="store_true",
        help="鍵生成のデバッグ"
    )

    parser.add_argument(
        "--paths",
        action="store_true",
        help="パス決定メカニズムのデバッグ"
    )

    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="暗号化ワークフローのデバッグ"
    )

    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="復号ワークフローのデバッグ"
    )

    parser.add_argument(
        "--advanced",
        action="store_true",
        help="高度な機能のデバッグ"
    )

    return parser.parse_args()

def main():
    """
    メイン関数
    """
    args = parse_arguments()
    timestamp, log_file = setup()

    print(f"デバッグログ: {log_file}")

    # デバッグ関数の実行フラグ
    run_all = args.all or (
        not args.keys and
        not args.paths and
        not args.encrypt and
        not args.decrypt and
        not args.advanced
    )

    if run_all or args.keys:
        debug_key_generation(log_file)

    if run_all or args.paths:
        debug_path_determination(log_file, timestamp)

    if run_all or args.encrypt:
        debug_encryption_workflow(log_file, timestamp)

    if run_all or args.decrypt:
        debug_decryption_workflow(log_file, timestamp)

    if run_all or args.advanced:
        debug_advanced_features(log_file, timestamp)

    print(f"\nデバッグが完了しました。ログファイル: {log_file}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
