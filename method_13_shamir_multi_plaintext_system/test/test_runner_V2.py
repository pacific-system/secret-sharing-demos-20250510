#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
シャミア秘密分散法による複数平文復号システムのテストランナーV2

【責務】
このスクリプトは、テスト設定ファイルに基づいてテストを実行し、
結果をJSONファイルに永続化してレポートを生成します。

【主な変更点】
- all_test_resultsをメモリではなくJSONファイルに永続化
- 高頻度でのファイル書き込みによるデバッグ性向上
- UUID+TIMESTAMPによるファイル命名
- results/ディレクトリでの結果管理

【依存関係】
- os: ファイル操作に使用
- sys: プログラム終了に使用
- datetime: タイムスタンプ生成に使用
- logging: ログ出力に使用
- utils.config_loader: 設定ファイル読み込みに使用
- utils.report_generator: レポート生成に使用
- utils.test_logger: テストログ出力に使用

【使用方法】
python -m method_13_shamir_multi_plaintext_system.test.test_runner_V2
"""

import os
import sys
import datetime
import logging
from typing import Dict, Any, List, Type, Optional, Tuple

# プロセス冒頭で実行環境を確定
# test_runner_V2.pyの絶対パスを取得
TEST_RUNNER_V2_FILE_PATH = os.path.abspath(__file__)
TEST_RUNNER_V2_DIR = os.path.dirname(TEST_RUNNER_V2_FILE_PATH)

# 実行環境をカレントディレクトリに設定
os.chdir(TEST_RUNNER_V2_DIR)

from utils.config_loader import load_config
from utils.report_generator import generate_report, save_report
from utils.test_logger import setup_logger, log_info, log_error, log_warning

# V2コンポーネント
from test_runner_V2_file_manager import TestResultFileManager
from test_runner_V2_test_executor import TestCaseDiscoverer, TestExecutor
from test_runner_V2_analysis_executor import AnalyzerDiscoverer, AnalysisExecutor

# ログ設定（実行環境確定後に実行）
logger = setup_logger()


def generate_report_from_json_file(json_file_path: str) -> Optional[str]:
    """
    JSONファイルからレポートを生成する

    Args:
        json_file_path: JSONファイルのパス

    Returns:
        生成されたレポート文字列、失敗した場合はNone
    """
    try:
        import json

        # JSONファイルを読み込み
        with open(json_file_path, 'r', encoding='utf-8') as f:
            execution_data = json.load(f)

        log_info(f"JSONファイルからデータを読み込みました: {json_file_path}")

        # JSONデータを既存のgenerate_report関数で使用できる形式に変換
        latest_test_results = {}
        all_test_results = []
        analysis_results = {}

        # テスト実行データの変換
        if "test_execution" in execution_data and "iterations" in execution_data["test_execution"]:
            iterations = execution_data["test_execution"]["iterations"]

            # 最新のイテレーション結果を取得
            if iterations:
                latest_iteration = iterations[-1]
                if "test_results" in latest_iteration:
                    for test_id, test_result in latest_iteration["test_results"].items():
                        latest_test_results[test_id] = {
                            "test_id": test_result.get("test_id", test_id),
                            "success": test_result.get("success", False),
                            "storage_filename": test_result.get("storage_filepath", ""),
                            "password_a_random": test_result.get("password_a_random", ""),
                            "password_b_random": test_result.get("password_b_random", ""),
                            "password_a_cli": test_result.get("password_a_cli", ""),
                            "password_b_cli": test_result.get("password_b_cli", ""),
                            "cli_args": test_result.get("cli_args", ""),
                            "stdout": test_result.get("stdout", ""),
                            "stderr": test_result.get("stderr", ""),
                            "exit_code": test_result.get("exit_code", 0),
                            "partition_map_a": test_result.get("partition_map_a", ""),
                            "partition_map_b": test_result.get("partition_map_b", ""),
                            "execution_time": test_result.get("execution_time", 0.0),
                            "performance_data": test_result.get("performance_data", {}),
                            "error": test_result.get("error", "")
                        }

            # 全イテレーション結果の変換
            for i, iteration in enumerate(iterations):
                iteration_results = {}
                if "test_results" in iteration:
                    for test_id, test_result in iteration["test_results"].items():
                        iteration_results[test_id] = {
                            "test_id": test_result.get("test_id", test_id),
                            "success": test_result.get("success", False),
                            "storage_filename": test_result.get("storage_filepath", ""),
                            "password_a_random": test_result.get("password_a_random", ""),
                            "password_b_random": test_result.get("password_b_random", ""),
                            "password_a_cli": test_result.get("password_a_cli", ""),
                            "password_b_cli": test_result.get("password_b_cli", ""),
                            "cli_args": test_result.get("cli_args", ""),
                            "stdout": test_result.get("stdout", ""),
                            "stderr": test_result.get("stderr", ""),
                            "exit_code": test_result.get("exit_code", 0),
                            "partition_map_a": test_result.get("partition_map_a", ""),
                            "partition_map_b": test_result.get("partition_map_b", ""),
                            "execution_time": test_result.get("execution_time", 0.0),
                            "performance_data": test_result.get("performance_data", {}),
                            "error": test_result.get("error", "")
                        }

                all_test_results.append({
                    "iteration": iteration.get("iteration", i + 1),
                    "results": iteration_results
                })

        # 分析実行データの変換
        if "analysis_execution" in execution_data:
            analysis_exec = execution_data["analysis_execution"]

            # map_intersection分析結果
            if "map_intersection" in analysis_exec and analysis_exec["map_intersection"]:
                map_data = analysis_exec["map_intersection"]
                if "final_results" in map_data:
                    analysis_results["map_intersection"] = map_data["final_results"]

            # その他の分析結果
            if "other_analyses" in analysis_exec:
                analysis_results.update(analysis_exec["other_analyses"])

        # 既存のgenerate_report関数を呼び出し
        return generate_report(latest_test_results, analysis_results, all_test_results)

    except Exception as e:
        log_error(f"JSONファイルからのレポート生成中にエラーが発生しました: {str(e)}")
        return None


class TestRunnerV2:
    """テストランナーV2 メインクラス"""

    def __init__(self):
        """初期化"""
        self.file_manager = TestResultFileManager()
        self.test_executor = TestExecutor(self.file_manager)
        self.analysis_executor = AnalysisExecutor(self.file_manager)
        self.logger = logging.getLogger(__name__)

    def run(self) -> int:
        """
        メイン実行処理

        Returns:
            終了コード (0=成功, 1=失敗)
        """
        try:
            # 実行開始（実行環境情報をログ出力）
            log_info("テスト実行を開始します")
            log_info(f"実行環境: {TEST_RUNNER_V2_DIR}")
            log_info(f"test_runner_V2.py絶対パス: {TEST_RUNNER_V2_FILE_PATH}")

            # ファイル永続化の初期化
            result_file_path = self.file_manager.initialize_new_execution()
            log_info(f"結果ファイルを初期化しました: {result_file_path}")

            # 設定ファイル読み込み
            config = load_config()
            if not config:
                error_msg = "設定ファイルの読み込みに失敗しました"
                log_error(error_msg)
                self.file_manager.mark_error(error_msg)
                sys.exit(1)

            # 設定データをファイルに保存
            self.file_manager.update_config_data(config)
            log_info("設定ファイルをファイルに記録しました")

            # テストケース検出
            discoverer = TestCaseDiscoverer()
            test_cases = discoverer.discover_test_cases()
            if not test_cases:
                error_msg = "テストケースが見つかりませんでした"
                log_error(error_msg)
                self.file_manager.mark_error(error_msg)
                sys.exit(1)

            # メタデータ更新
            self.file_manager.update_metadata(test_cases_discovered=len(test_cases))
            log_info(f"検出されたテストケース: {list(test_cases.keys())}")

            # 分析モジュール検出
            analyzer_discoverer = AnalyzerDiscoverer()
            analyzers = analyzer_discoverer.discover_analyzers()
            if not analyzers:
                # 分析モジュール未発見時の継続処理
                log_warning("分析モジュールが見つかりませんでした。分析なしでテスト実行を継続します。")
            else:
                log_info(f"検出された分析モジュール: {list(analyzers.keys())}")

            # メタデータ更新
            self.file_manager.update_metadata(analyzers_discovered=len(analyzers))

            # テスト実行（メモリ上のデータは使用せず、JSONファイルに直接保存）
            self.test_executor.run_tests(test_cases)
            log_info("テスト実行が完了し、結果をJSONファイルに保存しました")

            # 分析実行（JSONファイルからデータを読み込んで実行）
            self.analysis_executor.run_analysis_from_json_file(analyzers)
            log_info("分析実行が完了し、結果をJSONファイルに保存しました")

            # レポート生成（JSONファイルからデータを読み込んで生成）
            self._generate_and_save_report_from_json()

            # 完了処理
            log_info("テスト実行が完了しました")

            # 成功数と失敗数をカウント（JSONファイルから読み込み）
            success_count, failure_count = self._count_results_from_json()

            log_info(f"テスト結果: 合計={success_count + failure_count}, 成功={success_count}, 失敗={failure_count}")

            # すべてのテストが成功した場合は0、そうでない場合は1を返す
            return 0 if failure_count == 0 else 1

        except Exception as e:
            # メイン例外時の終了コード1返却
            error_msg = f"テスト実行中に予期しないエラーが発生しました: {str(e)}"
            log_error(error_msg)
            try:
                self.file_manager.mark_error(error_msg)
            except Exception as inner_e:
                log_error(f"エラー記録中にさらにエラーが発生しました: {str(inner_e)}")
            return 1

    def _generate_and_save_report_from_json(self) -> None:
        """
        JSONファイルからデータを読み込んでレポート生成と保存

        JSONファイルを唯一のデータ源泉として使用
        """
        try:
            # レポート生成開始をファイルに記録
            self.file_manager.start_report_generation()
            log_info("JSONファイルからデータを読み込んでテストレポートを生成しています...")

            # JSONファイルからデータを読み込み
            result_file_path = self.file_manager.get_current_file_path()

            # レポート生成（JSONファイルパスを渡す）
            report = generate_report_from_json_file(result_file_path)

            if report:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                report_filename = f"test_report_{timestamp}.md"
                if save_report(report, report_filename):
                    log_info(f"テストレポートを保存しました: {report_filename}")
                    # レポート生成完了をファイルに記録
                    self.file_manager.complete_report_generation(report_filename)
                else:
                    # レポート保存失敗時の継続処理
                    log_error("テストレポートの保存に失敗しました")
                    self.file_manager.complete_report_generation(None)
            else:
                # レポート生成失敗時の継続処理
                log_error("テストレポートの生成に失敗しました")
                self.file_manager.complete_report_generation(None)

        except Exception as e:
            # レポート生成例外時の継続処理
            log_error(f"レポート生成中にエラーが発生しました: {str(e)}")
            try:
                self.file_manager.complete_report_generation(None)
            except Exception as inner_e:
                log_error(f"レポート生成エラー記録中にさらにエラーが発生しました: {str(inner_e)}")

    def _count_results_from_json(self) -> Tuple[int, int]:
        """
        JSONファイルから結果を読み込んで成功数と失敗数をカウント

        Returns:
            (成功数, 失敗数) のタプル
        """
        try:
            execution_data = self.file_manager.get_execution_data()
            if not execution_data or not execution_data.test_execution["iterations"]:
                log_warning("JSONファイルからテスト結果を取得できませんでした")
                return 0, 0

            # 最新のイテレーション結果を取得
            latest_iteration = execution_data.test_execution["iterations"][-1]

            success_count = 0
            failure_count = 0

            for test_result in latest_iteration.test_results.values():
                if test_result.success:
                    success_count += 1
                else:
                    failure_count += 1

            return success_count, failure_count

        except Exception as e:
            log_error(f"JSONファイルからの結果カウント中にエラーが発生しました: {str(e)}")
            return 0, 0


def main():
    """メイン処理"""
    runner = TestRunnerV2()
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())