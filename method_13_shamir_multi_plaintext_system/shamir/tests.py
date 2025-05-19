"""
セキュリティテストと自己診断ツール

このモジュールでは、シャミア秘密分散法システムのセキュリティテストと
自己診断ツールを提供します。統計的区別不可能性の検証、タイミング攻撃耐性のテスト
などが含まれています。
"""

import time
import json
import random
import hashlib
from typing import Dict, List, Any, Tuple
from gmpy2 import mpz

from .constants import ShamirConstants
from .core import (
    generate_polynomial, evaluate_polynomial, generate_shares,
    lagrange_interpolation, constant_time_select
)
from .partition import (
    generate_partition_map_key, PartitionManager,
    verify_statistical_indistinguishability, initialize_system
)
from .crypto import (
    preprocess_json_document, split_into_chunks,
    encrypt_json_document, decrypt_json_document
)


def test_share_value_distribution(
    threshold: int = 3,
    test_count: int = 100,
    show_details: bool = False
) -> Tuple[bool, Dict[str, Any]]:
    """
    シェア値の分布を検証するテスト

    Args:
        threshold: テストに使用する閾値
        test_count: 生成するシェアの数
        show_details: 詳細な分析情報を出力するかどうか

    Returns:
        (テスト成功フラグ, 詳細データ)
    """
    # テスト用のシェアIDを生成
    share_ids = list(range(1, test_count + 1))

    # 異なる秘密値でシェアを生成
    test_secrets = [
        mpz(1),
        mpz(100),
        mpz(10000),
        mpz(1000000),
        mpz(2**64)
    ]

    all_share_values = []
    for secret in test_secrets:
        shares = generate_shares(
            secret, threshold, share_ids, ShamirConstants.PRIME
        )
        # シェア値を正規化（下位ビットのみ使用して分布を分析）
        normalized_values = [int(value) % (2**32) for _, value in shares]
        all_share_values.extend(normalized_values)

    # 基本的な統計分析
    min_value = min(all_share_values)
    max_value = max(all_share_values)
    avg_value = sum(all_share_values) / len(all_share_values)

    # ヒストグラム分析（値域を10個のビンに分割）
    bin_size = (max_value - min_value) // 10
    if bin_size == 0:
        bin_size = 1

    histogram = [0] * 10
    for value in all_share_values:
        bin_idx = min(9, (value - min_value) // bin_size)
        histogram[bin_idx] += 1

    # 期待値（均一分布の場合）
    expected_count = len(all_share_values) / 10

    # カイ二乗検定
    chi_squared = sum(
        ((obs - expected_count) ** 2) / expected_count
        for obs in histogram
    )

    # 自由度9、有意水準0.05のカイ二乗臨界値は16.92
    is_uniform = chi_squared < 16.92

    # 詳細表示
    if show_details:
        print(f"シェア値の統計:")
        print(f"  最小値: {min_value}")
        print(f"  最大値: {max_value}")
        print(f"  平均値: {avg_value:.2f}")
        print(f"  カイ二乗値: {chi_squared:.2f}")
        print(f"  ヒストグラム: {histogram}")
        print(f"  均一分布と判定: {is_uniform}")

    return is_uniform, {
        "min_value": min_value,
        "max_value": max_value,
        "avg_value": avg_value,
        "chi_squared": chi_squared,
        "histogram": histogram,
        "is_uniform": is_uniform
    }


def test_timing_attack_resistance(
    iterations: int = 5,
    show_details: bool = False
) -> Tuple[bool, Dict[str, Any]]:
    """
    タイミング攻撃耐性をテスト

    Args:
        iterations: テスト反復回数
        show_details: 詳細な分析情報を出力するかどうか

    Returns:
        (テスト成功フラグ, 詳細データ)
    """
    # システム初期化
    system_info = initialize_system()
    partition_a_key = system_info['partition_a_key']

    # テスト用のダミーデータを作成
    test_data = {"name": "test_document", "value": "secret_data"}
    correct_password = "correct_password"
    wrong_password = "wrong_password"

    # パーティションマネージャーの初期化
    partition_manager = PartitionManager(
        partition_a_key=system_info['partition_a_key'],
        partition_b_key=system_info['partition_b_key']
    )

    # 文書を暗号化
    encrypted_file = encrypt_json_document(
        test_data,
        correct_password,
        partition_a_key,
        partition_manager.a_share_ids
    )

    # タイミング測定のためのデータ構造
    correct_times = []
    wrong_times = []

    # 複数回測定して平均を計算
    for _ in range(iterations):
        # 正しいパスワードでの復号時間を計測
        start_time = time.time()
        decrypt_json_document(encrypted_file, partition_a_key, correct_password)
        correct_times.append(time.time() - start_time)

        # 誤ったパスワードでの復号時間を計測
        start_time = time.time()
        decrypt_json_document(encrypted_file, partition_a_key, wrong_password)
        wrong_times.append(time.time() - start_time)

    # 平均と標準偏差を計算
    avg_correct = sum(correct_times) / len(correct_times)
    avg_wrong = sum(wrong_times) / len(wrong_times)

    std_dev_correct = (sum((t - avg_correct) ** 2 for t in correct_times) / len(correct_times)) ** 0.5
    std_dev_wrong = (sum((t - avg_wrong) ** 2 for t in wrong_times) / len(wrong_times)) ** 0.5

    # 時間差の絶対値
    time_diff = abs(avg_correct - avg_wrong)

    # 標準偏差の最大値と比較
    max_std_dev = max(std_dev_correct, std_dev_wrong)

    # 時間差が小さいことを確認（標準偏差の2倍以内なら統計的に有意でない）
    is_resistant = time_diff < (2 * max_std_dev)

    if show_details:
        print(f"タイミング攻撃耐性テスト:")
        print(f"  正しいパスワードでの平均時間: {avg_correct:.6f}秒")
        print(f"  誤ったパスワードでの平均時間: {avg_wrong:.6f}秒")
        print(f"  時間差: {time_diff:.6f}秒")
        print(f"  正しいパスワードの標準偏差: {std_dev_correct:.6f}秒")
        print(f"  誤ったパスワードの標準偏差: {std_dev_wrong:.6f}秒")
        print(f"  タイミング攻撃耐性あり: {is_resistant}")

    return is_resistant, {
        "avg_correct_time": avg_correct,
        "avg_wrong_time": avg_wrong,
        "time_diff": time_diff,
        "std_dev_correct": std_dev_correct,
        "std_dev_wrong": std_dev_wrong,
        "is_resistant": is_resistant
    }


def test_partition_independence(show_details: bool = False) -> Tuple[bool, Dict[str, Any]]:
    """
    パーティション空間の統計的独立性をテスト

    Args:
        show_details: 詳細な分析情報を出力するかどうか

    Returns:
        (テスト成功フラグ, 詳細データ)
    """
    # 複数のパーティション空間を生成して統計的独立性を検証
    success_count = 0
    trials = 5

    correlations = []

    for i in range(trials):
        # 2つの独立したシステムを初期化
        system1 = initialize_system()
        system2 = initialize_system()

        # パーティションマネージャーを初期化
        manager1 = PartitionManager(
            partition_a_key=system1['partition_a_key'],
            partition_b_key=system1['partition_b_key']
        )

        manager2 = PartitionManager(
            partition_a_key=system2['partition_a_key'],
            partition_b_key=system2['partition_b_key']
        )

        # ID の重複率を計算
        a1_set = set(manager1.a_share_ids)
        a2_set = set(manager2.a_share_ids)

        intersection = a1_set.intersection(a2_set)
        expected_overlap = len(a1_set) * len(a2_set) / ShamirConstants.SHARE_ID_SPACE

        # 実際の重複率と期待される重複率の比率
        overlap_ratio = len(intersection) / expected_overlap if expected_overlap > 0 else 0
        correlations.append(overlap_ratio)

        # 比率が0.8～1.2の範囲内であれば統計的に独立とみなす
        if 0.8 <= overlap_ratio <= 1.2:
            success_count += 1

    avg_correlation = sum(correlations) / len(correlations)
    is_independent = success_count >= trials * 0.8  # 80%以上のテストが成功すれば合格

    if show_details:
        print(f"パーティション独立性テスト:")
        print(f"  成功率: {success_count}/{trials}")
        print(f"  平均相関率: {avg_correlation:.2f}")
        print(f"  独立性あり: {is_independent}")

    return is_independent, {
        "success_rate": success_count / trials,
        "avg_correlation": avg_correlation,
        "correlations": correlations,
        "is_independent": is_independent
    }


def security_self_diagnostic(show_output: bool = True) -> Dict[str, Any]:
    """
    システムのセキュリティ自己診断ツール
    統計的区別不可能性やサイドチャネル攻撃耐性などを検証

    Args:
        show_output: 診断結果を標準出力に表示するかどうか

    Returns:
        診断結果を含む辞書
    """
    if show_output:
        print("=== シャミア秘密分散法 セキュリティ自己診断 ===\n")

    results = {}

    # 1. パーティション空間の検証
    if show_output:
        print("1. パーティション空間の検証")

    system_info = initialize_system()
    partition_manager = PartitionManager(
        partition_a_key=system_info["partition_a_key"],
        partition_b_key=system_info["partition_b_key"]
    )

    is_indistinguishable = verify_statistical_indistinguishability(
        partition_manager.a_share_ids,
        partition_manager.b_share_ids,
        partition_manager.unassigned_ids
    )

    results["partition_space"] = {
        "success": is_indistinguishable,
        "a_share_count": partition_manager.a_shares_count,
        "b_share_count": partition_manager.b_shares_count,
        "unassigned_count": partition_manager.unassigned_count
    }

    if show_output:
        if is_indistinguishable:
            print("✓ パーティション空間は統計的に区別不可能です")
        else:
            print("✗ パーティション空間に統計的な偏りがあります")

    # 2. シェア値の均一性検証
    if show_output:
        print("\n2. シェア値の均一性検証")

    is_uniform, share_stats = test_share_value_distribution(
        show_details=show_output
    )

    results["share_values"] = {
        "success": is_uniform,
        **share_stats
    }

    if show_output and not is_uniform:
        print("✗ シェア値の分布に偏りがあります")

    # 3. タイミング攻撃耐性検証
    if show_output:
        print("\n3. タイミング攻撃耐性検証")

    is_resistant, timing_stats = test_timing_attack_resistance(
        show_details=show_output
    )

    results["timing_attack"] = {
        "success": is_resistant,
        **timing_stats
    }

    if show_output and not is_resistant:
        print("✗ タイミング攻撃に対して脆弱である可能性があります")

    # 4. パーティション独立性検証
    if show_output:
        print("\n4. パーティション独立性検証")

    is_independent, independence_stats = test_partition_independence(
        show_details=show_output
    )

    results["partition_independence"] = {
        "success": is_independent,
        **independence_stats
    }

    if show_output and not is_independent:
        print("✗ パーティション空間間に統計的な依存関係がある可能性があります")

    # 総合評価
    overall_success = (
        is_indistinguishable and
        is_uniform and
        is_resistant and
        is_independent
    )

    results["overall"] = {
        "success": overall_success,
        "timestamp": time.time()
    }

    if show_output:
        print("\n=== 総合セキュリティ評価 ===")
        if overall_success:
            print("✓ セキュリティ要件を満たしています")
        else:
            print("✗ セキュリティに懸念があります。詳細な分析を確認してください")

    return results


if __name__ == "__main__":
    security_self_diagnostic(True)