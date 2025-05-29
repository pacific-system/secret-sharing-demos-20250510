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
from typing import Dict, Any, List, Type, Optional

from utils.config_loader import load_config
from utils.report_generator import generate_report, save_report
from utils.test_logger import setup_logger, log_info, log_error, log_warning

# V2コンポーネント
from test_runner_V2_file_manager import TestResultFileManager
from test_runner_V2_test_executor import TestCaseDiscoverer, TestExecutor
from test_runner_V2_analysis_executor import AnalyzerDiscoverer, AnalysisExecutor

# ログ設定
logger = setup_logger()


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
            # 実行開始
            log_info("テスト実行を開始します")

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

            # 分析モジュール検出
            analyzer_discoverer = AnalyzerDiscoverer()
            analyzers = analyzer_discoverer.discover_analyzers()
            if not analyzers:
                log_warning("分析モジュールが見つかりませんでした")

            # メタデータ更新
            self.file_manager.update_metadata(analyzers_discovered=len(analyzers))

            # テスト実行
            all_test_results = self.test_executor.run_tests(test_cases)

            # 分析実行
            latest_test_results = self.test_executor.get_latest_test_results()
            analysis_results = self.analysis_executor.run_analysis(
                analyzers, latest_test_results, all_test_results
            )

            # レポート生成
            self._generate_and_save_report(latest_test_results, analysis_results, all_test_results)

            # 完了処理
            log_info("テスト実行が完了しました")

            # 成功数と失敗数をカウント
            success_count = sum(1 for result in latest_test_results.values() if result.get("success", False))
            failure_count = len(latest_test_results) - success_count

            log_info(f"テスト結果: 合計={len(latest_test_results)}, 成功={success_count}, 失敗={failure_count}")

            # すべてのテストが成功した場合は0、そうでない場合は1を返す
            return 0 if failure_count == 0 else 1

        except Exception as e:
            error_msg = f"テスト実行中に予期しないエラーが発生しました: {str(e)}"
            log_error(error_msg)
            self.file_manager.mark_error(error_msg)
            return 1

    def _generate_and_save_report(self, latest_test_results: Dict[str, Any], analysis_results: Dict[str, Dict[str, Any]], all_test_results: List[Dict[str, Dict[str, Any]]]) -> None:
        """
        レポート生成と保存

        Args:
            latest_test_results: 最新のテスト結果
            analysis_results: 分析結果
            all_test_results: 全テスト結果
        """
        try:
            # レポート生成開始をファイルに記録
            self.file_manager.start_report_generation()
            log_info("テストレポートを生成しています...")

            # レポート生成（ファイルパスを渡す）
            result_file_path = self.file_manager.get_current_file_path()
            report = generate_report(latest_test_results, analysis_results, result_file_path)

            if report:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                report_filename = f"test_report_{timestamp}.md"
                if save_report(report, report_filename):
                    log_info(f"テストレポートを保存しました: {report_filename}")
                    # レポート生成完了をファイルに記録
                    self.file_manager.complete_report_generation(report_filename)
                else:
                    log_error("テストレポートの保存に失敗しました")
            else:
                log_error("テストレポートの生成に失敗しました")

        except Exception as e:
            log_error(f"レポート生成中にエラーが発生しました: {str(e)}")


def main():
    """メイン処理"""
    runner = TestRunnerV2()
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())