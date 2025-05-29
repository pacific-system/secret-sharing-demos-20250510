#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
シャミア秘密分散法による複数平文復号システムのテスト実行スクリプト

【責務】
このスクリプトは、テスト設定ファイルに基づいてテストを実行し、
結果を分析してレポートを生成します。

【依存関係】
- os: ファイル操作に使用
- sys: プログラム終了に使用
- datetime: タイムスタンプ生成に使用
- importlib: 動的モジュールロードに使用
- logging: ログ出力に使用
- utils.config_loader: 設定ファイル読み込みに使用
- utils.report_generator: レポート生成に使用
- utils.test_logger: テストログ出力に使用

【使用方法】
python -m method_13_shamir_multi_plaintext_system.test.test_runner
"""

import os
import sys
import datetime
import importlib
import logging
import inspect
import glob
from typing import Dict, Any, List, Type, Optional

from utils.config_loader import load_config, is_test_enabled, is_analysis_enabled
from utils.report_generator import generate_report, save_report
from utils.test_logger import setup_logger, log_info, log_error, log_test_result, log_warning

# テストケースの基底クラス
from test_cases.base_test import BaseTest

# ログ設定
logger = setup_logger()

def discover_test_cases() -> Dict[str, Type[BaseTest]]:
    """
    テストケースを動的に検出する

    Returns:
        テストケースのディクショナリ（テストID -> テストクラス）
    """
    log_info("テストケースを検出しています...")
    test_cases = {}

    # テストケースのディレクトリパス
    test_dirs = [
        "test_cases/crypto_storage_creation",
        "test_cases/crypto_storage_update",
        "test_cases/crypto_storage_read"
    ]

    for test_dir in test_dirs:
        # ディレクトリが存在するか確認
        if not os.path.exists(test_dir):
            log_warning(f"テストディレクトリが見つかりません: {test_dir}")
            continue

        # Pythonファイルを検索
        search_pattern = os.path.join(test_dir, "test_*.py")
        for test_file in glob.glob(search_pattern):
            # ファイル名からモジュール名を作成
            rel_path = os.path.relpath(test_file)
            module_name = rel_path.replace(".py", "").replace("/", ".")

            try:
                # モジュールをインポート
                module = importlib.import_module(module_name)

                # モジュール内のクラスを検査
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # 基底クラスを継承しているか
                    if issubclass(obj, BaseTest) and obj != BaseTest:
                        # インスタンス化
                        test_instance = obj()
                        test_id = test_instance.test_id

                        # 有効なテストIDを持つかチェック
                        if test_id:
                            test_cases[test_id] = obj
                            log_info(f"テストケース {test_id} ({obj.__name__}) を検出しました")
            except Exception as e:
                log_error(f"モジュール {module_name} のロード中にエラーが発生しました: {str(e)}")

    if not test_cases:
        log_warning("テストケースが見つかりませんでした")
    else:
        log_info(f"検出されたテストケース数: {len(test_cases)}")

    return test_cases

def discover_analyzers() -> Dict[str, Any]:
    """
    分析モジュールを動的に検出する

    Returns:
        分析モジュールのディクショナリ（分析ID -> 分析クラス）
    """
    log_info("分析モジュールを検出しています...")
    analyzers = {}

    # 分析モジュールのディレクトリパス
    analyze_dir = "analysis"

    # ディレクトリが存在するか確認
    if not os.path.exists(analyze_dir):
        log_warning(f"分析モジュールディレクトリが見つかりません: {analyze_dir}")
        return analyzers

    # Pythonファイルを検索
    search_pattern = os.path.join(analyze_dir, "*_analyzer.py")
    for analyzer_file in glob.glob(search_pattern):
        # ファイル名からモジュール名を作成
        rel_path = os.path.relpath(analyzer_file)
        module_name = rel_path.replace(".py", "").replace("/", ".")

        try:
            # モジュールをインポート
            module = importlib.import_module(module_name)

            # モジュール内のクラスを検査
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # クラス名が *Analyzer で終わるか
                if name.endswith("Analyzer"):
                    # インスタンス化
                    analyzer_instance = obj()

                    # name属性を持つかチェック
                    if hasattr(analyzer_instance, "name") and analyzer_instance.name:
                        analyzer_id = analyzer_instance.name
                        analyzers[analyzer_id] = obj
                        log_info(f"分析モジュール {analyzer_id} ({obj.__name__}) を検出しました")
        except Exception as e:
            log_error(f"モジュール {module_name} のロード中にエラーが発生しました: {str(e)}")

    if not analyzers:
        log_warning("分析モジュールが見つかりませんでした")
    else:
        log_info(f"検出された分析モジュール数: {len(analyzers)}")

    return analyzers

def run_tests(test_cases: Dict[str, Type[BaseTest]] = None, verbose: bool = False) -> List[Dict[str, Dict[str, Any]]]:
    """
    テストケースを実行する

    Args:
        test_cases: テストケースのディクショナリ（テストID -> テストクラス）。Noneの場合は自動検出する
        verbose: 詳細なログ出力を行うかどうか

    Returns:
        全テスト実行結果のリスト（各要素は {"iteration": 回数, "results": テスト結果辞書} の形式）
    """
    # テストケースが指定されていない場合は自動検出
    if test_cases is None:
        test_cases = discover_test_cases()

    # テスト繰り返し回数を取得（設定ファイルから）
    config = load_config()
    repeat_count = 1  # デフォルト値

    if config and 'reporting' in config and 'test_repeat_count' in config['reporting']:
        repeat_count = int(config['reporting']['test_repeat_count'])
        # 最大10回までに制限
        if repeat_count > 10:
            log_warning(f"テスト繰り返し回数が多すぎます（{repeat_count}）。最大10回に制限します。")
            repeat_count = 10
        elif repeat_count < 1:
            log_warning(f"テスト繰り返し回数が少なすぎます（{repeat_count}）。最小1回に設定します。")
            repeat_count = 1

    log_info(f"テストを{repeat_count}回繰り返し実行します...")

    all_test_results = []

    for iteration in range(repeat_count):
        log_info(f"テスト実行 #{iteration+1}/{repeat_count} を開始します...")
        test_results = {}

        for test_id, test_class in test_cases.items():
            # テストが有効かどうかをチェック
            if not is_test_enabled(test_id):
                log_info(f"テスト {test_id} は設定で無効化されているためスキップします")
                continue

            try:
                # テストインスタンス生成
                test_instance = test_class()

                # テスト実行
                log_info(f"テスト {test_id} ({test_class.__name__}) を実行しています...")
                result = test_instance.run()

                # テスト結果をログに出力
                if "cli_args" in result:
                    logger.info(f"テスト {test_id} の CLI引数: {result['cli_args']}")

                # パスワード情報を確認
                if "password_a" in result:
                    logger.info(f"DEBUG: テスト {test_id} のA用パスワード: {result['password_a']}")
                if "password_b" in result:
                    logger.info(f"DEBUG: テスト {test_id} のB用パスワード: {result['password_b']}")

                # 結果をログ出力
                success = result.get("success", False)
                status = "成功" if success else "失敗"
                log_info(f"テスト {test_id} の実行結果: {status}")

                # 結果を記録
                test_results[test_id] = result

                # テスト結果をログに記録
                log_test_result(test_id, result)
            except Exception as e:
                log_error(f"テスト {test_id} の実行中にエラーが発生しました: {str(e)}")
                test_results[test_id] = {
                    "test_id": test_id,
                    "success": False,
                    "error": str(e)
                }

        log_info(f"テスト実行 #{iteration+1}/{repeat_count} 完了: 実行されたテスト数: {len(test_results)}")

        # イテレーション番号を追加（レポート生成で重要）
        iteration_results = {
            "iteration": iteration + 1,
            "results": test_results
        }
        all_test_results.append(iteration_results)

    log_info(f"全{repeat_count}回のテスト実行が完了しました")
    return all_test_results

def run_analysis(analyzers: Dict[str, Any], all_test_results: List[Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """
    分析処理を実行する

    Args:
        analyzers: 分析モジュールのディクショナリ（分析ID -> 分析クラス）
        all_test_results: 全テスト実行結果のリスト（各要素は {"iteration": 回数, "results": テスト結果辞書} の形式）

    Returns:
        分析結果のディクショナリ（分析ID -> 分析結果）
    """
    log_info("分析処理を実行しています...")
    analysis_results = {}

    # 最新のテスト結果を取得
    latest_test_results = {}
    if all_test_results:
        latest_test_results = all_test_results[-1]["results"]

    for analyzer_id, analyzer_class in analyzers.items():
        # 分析が有効かどうかをチェック
        if not is_analysis_enabled(analyzer_id):
            log_info(f"分析 {analyzer_id} は設定で無効化されているためスキップします")
            continue

        try:
            # 分析インスタンス生成
            analyzer_instance = analyzer_class()

            # 分析実行
            log_info(f"分析 {analyzer_id} ({analyzer_class.__name__}) を実行しています...")

            # 特定のアナライザーには all_test_results を渡す
            if analyzer_id == "map_intersection" and all_test_results:
                result = analyzer_instance.analyze(latest_test_results, all_test_results)
                log_info(f"パーティションMAP交差分析にall_test_resultsを渡しました（テスト実行数: {len(all_test_results)}）")
                # パーティションマップキー評価は合否判定を行わず、データのみ記録
                log_info(f"分析 {analyzer_id} の実行完了: パーセンテージデータを記録しました")
            else:
                result = analyzer_instance.analyze(latest_test_results)
                # 結果をログ出力（map_intersection以外のアナライザーのみ）
                success = result.get("pass", False)
                status = "合格" if success else "不合格"
                log_info(f"分析 {analyzer_id} の実行結果: {status}")

            # 結果を記録
            analysis_results[analyzer_id] = result
        except Exception as e:
            log_error(f"分析 {analyzer_id} の実行中にエラーが発生しました: {str(e)}")
            analysis_results[analyzer_id] = {
                "name": analyzer_id,
                "pass": False,
                "error": str(e)
            }

    log_info(f"実行された分析数: {len(analysis_results)}")
    return analysis_results

def main():
    """メイン処理"""
    log_info("テスト実行を開始します")

    # 設定ファイル読み込み
    config = load_config()
    if not config:
        log_error("設定ファイルの読み込みに失敗しました")
        sys.exit(1)

    # テストケース検出
    test_cases = discover_test_cases()
    if not test_cases:
        log_error("テストケースが見つかりませんでした")
        sys.exit(1)

    # 分析モジュール検出
    analyzers = discover_analyzers()
    if not analyzers:
        log_warning("分析モジュールが見つかりませんでした")

    # テスト実行
    all_test_results = run_tests(test_cases)

    # 分析実行
    analysis_results = run_analysis(analyzers, all_test_results)

    # レポート生成
    log_info("テストレポートを生成しています...")
    # 最新のテスト結果を取得
    latest_test_results = {}
    if all_test_results:
        latest_test_results = all_test_results[-1]["results"]

    report = generate_report(latest_test_results, analysis_results, all_test_results)
    if report:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"test_report_{timestamp}.md"
        if save_report(report, report_filename):
            log_info(f"テストレポートを保存しました: {report_filename}")
        else:
            log_error("テストレポートの保存に失敗しました")
    else:
        log_error("テストレポートの生成に失敗しました")

    log_info("テスト実行が完了しました")

    # 成功数と失敗数をカウント
    success_count = sum(1 for result in all_test_results[-1]["results"].values() if result.get("success", False))
    failure_count = len(all_test_results[-1]["results"]) - success_count

    log_info(f"テスト結果: 合計={len(all_test_results[-1]['results'])}, 成功={success_count}, 失敗={failure_count}")

    # すべてのテストが成功した場合は0、そうでない場合は1を返す
    return 0 if failure_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
