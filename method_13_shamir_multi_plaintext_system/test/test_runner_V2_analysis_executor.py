#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
テストランナーV2 - 分析実行処理

【責務】
- 分析モジュールの検出と実行
- map_intersection分析の特別処理
- ファイルマネージャーとの連携
"""

import os
import importlib
import inspect
import glob
import logging
from typing import Dict, Any, List, Optional

from utils.config_loader import is_analysis_enabled
from utils.test_logger import log_info, log_error, log_warning
from test_runner_V2_file_manager import TestResultFileManager


class AnalyzerDiscoverer:
    """分析モジュール検出クラス"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # test_runner_V2.pyの絶対パスを基準にベースディレクトリを取得
        self.base_dir = self._get_analysis_base_directory()

    def _get_analysis_base_directory(self) -> str:
        """
        テストランナーV2の絶対パスを基準に分析ベースディレクトリを取得

        Returns:
            分析ディレクトリのベースパス
        """
        # 現在のファイル（test_runner_V2_analysis_executor.py）の絶対パス
        current_file = os.path.abspath(__file__)
        # testディレクトリ（test_runner_V2.pyがある場所）
        test_dir = os.path.dirname(current_file)

        self.logger.info(f"分析ベースディレクトリを設定しました: {test_dir}")
        return test_dir

    def discover_analyzers(self) -> Dict[str, Any]:
        """
        分析モジュールを動的に検出する

        Returns:
            分析モジュールのディクショナリ（分析ID -> 分析クラス）
        """
        log_info("分析モジュールを検出しています...")
        analyzers = {}

        # 分析モジュールのディレクトリパス（絶対パスで構築）
        analyze_dir_name = "analysis"
        analyze_dir = os.path.join(self.base_dir, analyze_dir_name)

        # ディレクトリが存在するか確認
        if not os.path.exists(analyze_dir):
            log_warning(f"分析モジュールディレクトリが見つかりません: {analyze_dir}")
            log_warning(f"  ベースディレクトリ: {self.base_dir}")
            log_warning(f"  相対パス: {analyze_dir_name}")
            return analyzers

        log_info(f"分析モジュールディレクトリを検索中: {analyze_dir}")

        # Pythonファイルを検索
        search_pattern = os.path.join(analyze_dir, "*_analyzer.py")
        for analyzer_file in glob.glob(search_pattern):
            # ファイル名からモジュール名を作成
            rel_path = os.path.relpath(analyzer_file, self.base_dir)
            module_name = rel_path.replace(".py", "").replace(os.sep, ".")

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
            log_warning(f"検索対象ベースディレクトリ: {self.base_dir}")
        else:
            log_info(f"検出された分析モジュール数: {len(analyzers)}")

        return analyzers


class MapIntersectionAnalyzer:
    """マップ交差分析の特別処理クラス"""

    def __init__(self, file_manager: TestResultFileManager):
        """
        初期化

        Args:
            file_manager: ファイル管理インスタンス
        """
        self.file_manager = file_manager
        self.logger = logging.getLogger(__name__)

    def analyze_with_file_tracking(self, analyzer_instance, latest_test_results: Dict[str, Any], all_test_results: List[Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
        """
        マップ交差分析を実行し、比較ごとにファイルに記録

        Args:
            analyzer_instance: 分析インスタンス
            latest_test_results: 最新のテスト結果
            all_test_results: 全テスト結果

        Returns:
            分析結果
        """
        # 元の analyze メソッドをラップして、比較ごとにファイルに記録
        original_analyze = analyzer_instance.analyze

        def wrapped_analyze(latest_results, all_results):
            # 分析開始をファイルに記録
            log_info("パーティションMAP交差分析を開始します...")

            # 元の分析を実行
            result = original_analyze(latest_results, all_results)

            # 結果から比較データを抽出してファイルに記録
            self._record_comparison_results(result)

            return result

        # ラップした関数で分析実行
        return wrapped_analyze(latest_test_results, all_test_results)

    def _record_comparison_results(self, result: Dict[str, Any]) -> None:
        """
        比較結果をファイルに記録

        Args:
            result: 分析結果
        """
        try:
            # A用マップ比較結果を記録
            if "a_map_intersection" in result:
                for comparison_key, rate in result["a_map_intersection"].items():
                    if isinstance(comparison_key, tuple) and len(comparison_key) == 2:
                        comparison_str = f"{comparison_key[0]}-{comparison_key[1]}"
                        self.file_manager.add_map_comparison("a_map", comparison_str, rate)

            # B用マップ比較結果を記録
            if "b_map_intersection" in result:
                for comparison_key, rate in result["b_map_intersection"].items():
                    if isinstance(comparison_key, tuple) and len(comparison_key) == 2:
                        comparison_str = f"{comparison_key[0]}-{comparison_key[1]}"
                        self.file_manager.add_map_comparison("b_map", comparison_str, rate)

            # A-B間マップ比較結果を記録
            if "a_b_map_intersection" in result:
                for comparison_key, rate in result["a_b_map_intersection"].items():
                    if isinstance(comparison_key, tuple) and len(comparison_key) == 2:
                        comparison_str = f"{comparison_key[0]}-{comparison_key[1]}"
                        self.file_manager.add_map_comparison("ab_map", comparison_str, rate)

            # 最終結果をファイルに記録
            self.file_manager.complete_map_intersection_analysis(result)

        except Exception as e:
            self.logger.warning(f"比較結果の記録に失敗しました: {e}")


class AnalysisExecutor:
    """分析実行クラス"""

    def __init__(self, file_manager: TestResultFileManager):
        """
        初期化

        Args:
            file_manager: ファイル管理インスタンス
        """
        self.file_manager = file_manager
        self.map_analyzer = MapIntersectionAnalyzer(file_manager)
        self.logger = logging.getLogger(__name__)

    def run_analysis_from_json_file(self, analyzers: Dict[str, Any]) -> None:
        """
        JSONファイルからデータを読み込んで分析処理を実行する（メモリ上のデータは使用しない）

        Args:
            analyzers: 分析モジュールのディクショナリ（分析ID -> 分析クラス）
        """
        log_info("JSONファイルからデータを読み込んで分析処理を実行しています...")

        try:
            # JSONファイルから実行データを取得
            execution_data = self.file_manager.get_execution_data()
            if not execution_data or not execution_data.test_execution["iterations"]:
                log_warning("JSONファイルからテスト実行データを取得できませんでした。分析をスキップします。")
                return

            # JSONデータから分析用データを構築
            latest_test_results = {}
            all_test_results = []

            # 最新のイテレーション結果を取得
            latest_iteration = execution_data.test_execution["iterations"][-1]
            for test_id, test_result in latest_iteration.test_results.items():
                latest_test_results[test_id] = {
                    "test_id": test_result.test_id,
                    "success": test_result.success,
                    "storage_filename": test_result.storage_filepath,
                    "password_a": test_result.password_a,
                    "password_b": test_result.password_b,
                    "cli_args": test_result.cli_args,
                    "stdout": test_result.stdout,
                    "stderr": test_result.stderr,
                    "exit_code": test_result.exit_code,
                    "partition_map_a": test_result.partition_map_a,
                    "partition_map_b": test_result.partition_map_b,
                    "execution_time": test_result.execution_time,
                    "performance_data": test_result.performance_data,
                    "error": test_result.error
                }

            # 全イテレーション結果を構築
            for iteration_result in execution_data.test_execution["iterations"]:
                results_dict = {}
                for test_id, test_result in iteration_result.test_results.items():
                    results_dict[test_id] = {
                        "test_id": test_result.test_id,
                        "success": test_result.success,
                        "storage_filename": test_result.storage_filepath,
                        "password_a": test_result.password_a,
                        "password_b": test_result.password_b,
                        "cli_args": test_result.cli_args,
                        "stdout": test_result.stdout,
                        "stderr": test_result.stderr,
                        "exit_code": test_result.exit_code,
                        "partition_map_a": test_result.partition_map_a,
                        "partition_map_b": test_result.partition_map_b,
                        "execution_time": test_result.execution_time,
                        "performance_data": test_result.performance_data,
                        "error": test_result.error
                    }

                all_test_results.append({
                    "iteration": iteration_result.iteration,
                    "results": results_dict
                })

            log_info(f"JSONファイルから読み込み完了: 最新結果={len(latest_test_results)}件, 全結果={len(all_test_results)}イテレーション")

            # 分析実行（JSONから読み込んだデータを使用）
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
                        # マップ交差分析の特別処理
                        result = self.map_analyzer.analyze_with_file_tracking(
                            analyzer_instance, latest_test_results, all_test_results
                        )
                        log_info(f"パーティションMAP交差分析にall_test_resultsを渡しました（テスト実行数: {len(all_test_results)}）")
                        # パーティションマップキー評価は合否判定を行わず、データのみ記録
                        log_info(f"分析 {analyzer_id} の実行完了: パーセンテージデータを記録しました")
                    else:
                        result = analyzer_instance.analyze(latest_test_results)
                        # 結果をログ出力（map_intersection以外のアナライザーのみ）
                        success = result.get("pass", False)
                        status = "合格" if success else "不合格"
                        log_info(f"分析 {analyzer_id} の実行結果: {status}")

                        # その他の分析結果をファイルに記録
                        self.file_manager.add_other_analysis_result(analyzer_id, result)

                except Exception as e:
                    log_error(f"分析 {analyzer_id} の実行中にエラーが発生しました: {str(e)}")
                    error_result = {
                        "name": analyzer_id,
                        "pass": False,
                        "error": str(e)
                    }

                    # エラー結果もファイルに記録
                    self.file_manager.add_other_analysis_result(analyzer_id, error_result)

            log_info(f"JSONファイルベースの分析処理が完了しました")

        except Exception as e:
            log_error(f"JSONファイルからの分析実行中にエラーが発生しました: {str(e)}")

    def run_analysis(self, analyzers: Dict[str, Any], latest_test_results: Dict[str, Any], all_test_results: List[Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
        """
        分析処理を実行する（旧メソッド - 非推奨）

        Args:
            analyzers: 分析モジュールのディクショナリ（分析ID -> 分析クラス）
            latest_test_results: 最新のテスト結果
            all_test_results: 全テスト実行結果のリスト

        Returns:
            分析結果のディクショナリ（分析ID -> 分析結果）
        """
        # このメソッドは互換性のために残すが、使用は非推奨
        log_warning("run_analysis()は非推奨です。run_analysis_from_json_file()を使用してください")

        # JSONファイルベースの分析を実行
        self.run_analysis_from_json_file(analyzers)

        # 互換性のために分析結果を返す
        return self.get_analysis_results_for_compatibility()

    def get_analysis_results_for_compatibility(self) -> Dict[str, Dict[str, Any]]:
        """
        互換性のための分析結果を取得

        Returns:
            分析結果辞書
        """
        execution_data = self.file_manager.get_execution_data()
        if not execution_data:
            return {}

        analysis_results = {}

        # map_intersection 分析結果
        if execution_data.analysis_execution.map_intersection and execution_data.analysis_execution.map_intersection.final_results:
            analysis_results["map_intersection"] = execution_data.analysis_execution.map_intersection.final_results

        # その他の分析結果
        analysis_results.update(execution_data.analysis_execution.other_analyses)

        return analysis_results