#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
テストランナーV2 - ファイル永続化管理

【責務】
- テスト結果のJSONファイル永続化
- 高頻度書き込み対応
- results/ディレクトリ管理
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from test_runner_V2_data_structures import (
    TestExecutionData,
    TimestampGenerator,
    UUIDGenerator
)


class TestResultFileManager:
    """テスト結果ファイル管理クラス"""

    def __init__(self, base_dir: str = "results"):
        """
        初期化

        Args:
            base_dir: 結果ファイル保存ディレクトリ
        """
        self.base_dir = Path(base_dir)
        self.current_file_path: Optional[Path] = None
        self.execution_data: Optional[TestExecutionData] = None
        self.logger = logging.getLogger(__name__)

        # resultsディレクトリを作成
        self._ensure_results_directory()

    def _ensure_results_directory(self) -> None:
        """resultsディレクトリの存在確認・作成"""
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"結果保存ディレクトリを確認/作成しました: {self.base_dir}")
        except Exception as e:
            self.logger.error(f"結果保存ディレクトリの作成に失敗しました: {e}")
            raise

    def initialize_new_execution(self) -> str:
        """
        新しいテスト実行の初期化

        Returns:
            作成されたファイルパス
        """
        # 新しい実行データを作成
        self.execution_data = TestExecutionData()

        # ファイル名生成
        uuid_str = self.execution_data.metadata.uuid
        timestamp = TimestampGenerator.filename_timestamp()
        filename = f"test_results_{uuid_str}_{timestamp}.json"
        self.current_file_path = self.base_dir / filename

        # 初期ファイル書き込み
        self._write_to_file("実行開始時の初期化")

        self.logger.info(f"新しいテスト実行を初期化しました: {self.current_file_path}")
        return str(self.current_file_path)

    def update_metadata(self, **kwargs) -> None:
        """
        メタデータを更新

        Args:
            **kwargs: 更新するメタデータのキーワード引数
        """
        if not self.execution_data:
            raise RuntimeError("実行データが初期化されていません")

        for key, value in kwargs.items():
            if hasattr(self.execution_data.metadata, key):
                setattr(self.execution_data.metadata, key, value)

        self.execution_data.metadata.last_updated = TimestampGenerator.now()
        self._write_to_file(f"メタデータ更新: {list(kwargs.keys())}")

    def update_config_data(self, config: Dict[str, Any]) -> None:
        """
        設定データを更新

        Args:
            config: 設定データ辞書
        """
        if not self.execution_data:
            raise RuntimeError("実行データが初期化されていません")

        from test_runner_V2_data_structures import ConfigData

        # 設定データを構造化
        config_data = ConfigData(
            test_repeat_count=config.get('reporting', {}).get('test_repeat_count', 1),
            partition_size=config.get('system', {}).get('partition_size'),
            active_shares=config.get('system', {}).get('active_shares'),
            garbage_shares=config.get('system', {}).get('garbage_shares'),
            unassigned_shares=config.get('system', {}).get('unassigned_shares'),
            chunk_size=config.get('system', {}).get('chunk_size'),
            hash_algorithm=config.get('system', {}).get('hash_algorithm'),
            encryption_algorithm=config.get('system', {}).get('encryption_algorithm'),
            raw_config=config
        )

        self.execution_data.config_data = config_data
        self.execution_data.metadata.config_loaded = True
        self.execution_data.metadata.last_updated = TimestampGenerator.now()

        self._write_to_file("設定ファイル読み込み完了")

    def add_iteration_result(self, iteration: int, test_results: Dict[str, Any]) -> None:
        """
        イテレーション結果を追加

        Args:
            iteration: イテレーション番号
            test_results: テスト結果辞書
        """
        if not self.execution_data:
            raise RuntimeError("実行データが初期化されていません")

        from test_runner_V2_data_structures import IterationResult, TestResult

        # TestResult オブジェクトに変換
        structured_results = {}
        for test_id, result in test_results.items():
            test_result = TestResult(
                test_id=test_id,
                success=result.get("success", False),
                storage_filepath=result.get("storage_filename"),  # storage_filename -> storage_filepath
                password_a=result.get("password_a"),
                password_b=result.get("password_b"),
                cli_args=result.get("cli_args"),
                stdout=result.get("stdout"),
                stderr=result.get("stderr"),
                exit_code=result.get("exit_code"),
                partition_map_a=result.get("partition_map_a"),
                partition_map_b=result.get("partition_map_b"),
                execution_time=result.get("execution_time", 0.0),
                performance_data=result.get("performance_data"),
                error=result.get("error")
            )
            structured_results[test_id] = test_result

        # イテレーション結果を作成
        iter_result = IterationResult(
            iteration=iteration,
            test_results=structured_results,
            completed_time=TimestampGenerator.now()
        )

        self.execution_data.test_execution["iterations"].append(iter_result)
        self.execution_data.metadata.last_updated = TimestampGenerator.now()

        self._write_to_file(f"イテレーション {iteration} 完了")

    def update_cli_response_received(self, test_id: str, iteration: int) -> None:
        """
        CLI レスポンス受信時刻を更新

        Args:
            test_id: テストID
            iteration: イテレーション番号
        """
        if not self.execution_data:
            return

        # 該当するイテレーションとテスト結果を検索
        for iter_result in self.execution_data.test_execution["iterations"]:
            if iter_result.iteration == iteration and test_id in iter_result.test_results:
                iter_result.test_results[test_id].cli_response_received = TimestampGenerator.now()
                self.execution_data.metadata.last_updated = TimestampGenerator.now()
                self._write_to_file(f"CLI レスポンス受信: {test_id}")
                break

    def update_password_loaded(self, test_id: str, iteration: int) -> None:
        """
        パスワード読み込み時刻を更新

        Args:
            test_id: テストID
            iteration: イテレーション番号
        """
        if not self.execution_data:
            return

        # 該当するイテレーションとテスト結果を検索
        for iter_result in self.execution_data.test_execution["iterations"]:
            if iter_result.iteration == iteration and test_id in iter_result.test_results:
                iter_result.test_results[test_id].password_loaded = TimestampGenerator.now()
                self.execution_data.metadata.last_updated = TimestampGenerator.now()
                self._write_to_file(f"パスワード読み込み: {test_id}")
                break

    def add_map_comparison(self, comparison_type: str, comparison: str, rate: float) -> None:
        """
        マップ比較結果を追加

        Args:
            comparison_type: 比較タイプ ("a_map", "b_map", "ab_map")
            comparison: 比較ペア ("1-1", "1-2", etc.)
            rate: 一致率
        """
        if not self.execution_data:
            return

        from test_runner_V2_data_structures import MapComparison, MapIntersectionAnalysis

        # map_intersection 分析が未初期化の場合は初期化
        if not self.execution_data.analysis_execution.map_intersection:
            self.execution_data.analysis_execution.map_intersection = MapIntersectionAnalysis(
                start_time=TimestampGenerator.now()
            )

        # 比較結果を追加
        map_comp = MapComparison(comparison=comparison, rate=rate)

        if comparison_type == "a_map":
            self.execution_data.analysis_execution.map_intersection.a_map_comparisons.append(map_comp)
        elif comparison_type == "b_map":
            self.execution_data.analysis_execution.map_intersection.b_map_comparisons.append(map_comp)
        elif comparison_type == "ab_map":
            self.execution_data.analysis_execution.map_intersection.ab_map_comparisons.append(map_comp)

        self.execution_data.metadata.last_updated = TimestampGenerator.now()
        self._write_to_file(f"マップ比較追加: {comparison_type} {comparison} = {rate}%")

    def complete_map_intersection_analysis(self, final_results: Dict[str, Any]) -> None:
        """
        マップ交差分析完了

        Args:
            final_results: 最終分析結果
        """
        if not self.execution_data or not self.execution_data.analysis_execution.map_intersection:
            return

        self.execution_data.analysis_execution.map_intersection.final_results = final_results
        self.execution_data.analysis_execution.map_intersection.completed_time = TimestampGenerator.now()
        self.execution_data.metadata.last_updated = TimestampGenerator.now()

        self._write_to_file("マップ交差分析完了")

    def add_other_analysis_result(self, analyzer_id: str, result: Dict[str, Any]) -> None:
        """
        その他の分析結果を追加

        Args:
            analyzer_id: アナライザーID
            result: 分析結果
        """
        if not self.execution_data:
            return

        self.execution_data.analysis_execution.other_analyses[analyzer_id] = result
        self.execution_data.metadata.last_updated = TimestampGenerator.now()

        self._write_to_file(f"分析完了: {analyzer_id}")

    def start_report_generation(self) -> None:
        """レポート生成開始"""
        if not self.execution_data:
            return

        self.execution_data.report_generation.start_time = TimestampGenerator.now()
        self.execution_data.metadata.last_updated = TimestampGenerator.now()

        self._write_to_file("レポート生成開始")

    def complete_report_generation(self, report_filename: str) -> None:
        """
        レポート生成完了

        Args:
            report_filename: 生成されたレポートファイル名
        """
        if not self.execution_data:
            return

        self.execution_data.report_generation.completed_time = TimestampGenerator.now()
        self.execution_data.report_generation.report_filename = report_filename
        self.execution_data.metadata.status = "completed"
        self.execution_data.metadata.last_updated = TimestampGenerator.now()

        self._write_to_file("レポート生成完了")

    def mark_error(self, error_message: str) -> None:
        """
        エラー状態をマーク

        Args:
            error_message: エラーメッセージ
        """
        if not self.execution_data:
            return

        self.execution_data.metadata.status = "error"
        self.execution_data.metadata.last_updated = TimestampGenerator.now()

        self._write_to_file(f"エラー発生: {error_message}")

    def _write_to_file(self, operation: str) -> None:
        """
        ファイルに書き込み

        Args:
            operation: 実行された操作の説明
        """
        if not self.current_file_path or not self.execution_data:
            return

        try:
            # データを辞書形式に変換
            data = self.execution_data.to_dict()

            # JSONファイルに書き込み
            with open(self.current_file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            self.logger.debug(f"ファイル更新完了: {operation}")

        except Exception as e:
            self.logger.warning(f"ファイル書き込みに失敗しました ({operation}): {e}")

    def get_current_file_path(self) -> Optional[str]:
        """現在のファイルパスを取得"""
        return str(self.current_file_path) if self.current_file_path else None

    def get_execution_data(self) -> Optional[TestExecutionData]:
        """実行データを取得"""
        return self.execution_data