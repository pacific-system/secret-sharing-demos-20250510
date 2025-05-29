#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
テストランナーV2 - データ構造定義

【責務】
- テスト結果の永続化用データ構造定義
- タイムスタンプ生成ユーティリティ
- UUID生成ユーティリティ
"""

import uuid
import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


class TimestampGenerator:
    """タイムスタンプ生成ユーティリティ"""

    @staticmethod
    def now() -> str:
        """現在時刻のISO形式文字列を生成"""
        return datetime.datetime.now().isoformat()

    @staticmethod
    def filename_timestamp() -> str:
        """ファイル名用タイムスタンプを生成"""
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


class UUIDGenerator:
    """UUID生成ユーティリティ"""

    @staticmethod
    def generate() -> str:
        """36文字のUUIDを生成"""
        return str(uuid.uuid4())


@dataclass
class TestResultMetadata:
    """テスト結果メタデータ"""
    uuid: str = field(default_factory=UUIDGenerator.generate)
    execution_start_time: str = field(default_factory=TimestampGenerator.now)
    last_updated: str = field(default_factory=TimestampGenerator.now)
    status: str = "running"  # running|completed|error
    config_loaded: bool = False
    test_cases_discovered: int = 0
    analyzers_discovered: int = 0


@dataclass
class ConfigData:
    """設定データ"""
    test_repeat_count: int = 1
    partition_size: Optional[int] = None
    active_shares: Optional[int] = None
    garbage_shares: Optional[int] = None
    unassigned_shares: Optional[int] = None
    chunk_size: Optional[int] = None
    hash_algorithm: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    raw_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """個別テスト結果"""
    test_id: str
    success: bool = False
    storage_filepath: Optional[str] = None
    # ランダムに決定したパスワード（テスト開始時）
    password_a_random: Optional[str] = None
    password_b_random: Optional[str] = None
    # CLIレスポンスから取得したパスワード（実際の復号用）
    password_a_cli: Optional[str] = None
    password_b_cli: Optional[str] = None
    cli_args: Optional[Dict[str, Any]] = None
    cli_response_received: Optional[str] = None
    password_loaded: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    partition_map_a: Optional[Dict[str, Any]] = None
    partition_map_b: Optional[Dict[str, Any]] = None
    execution_time: float = 0.0
    performance_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class IterationResult:
    """イテレーション結果"""
    iteration: int
    start_time: str = field(default_factory=TimestampGenerator.now)
    test_results: Dict[str, TestResult] = field(default_factory=dict)
    completed_time: Optional[str] = None


@dataclass
class MapComparison:
    """マップ比較結果"""
    comparison: str  # "1-1", "1-2", etc.
    timestamp: str = field(default_factory=TimestampGenerator.now)
    rate: float = 0.0


@dataclass
class MapIntersectionAnalysis:
    """マップ交差分析結果"""
    start_time: Optional[str] = None
    a_map_comparisons: List[MapComparison] = field(default_factory=list)
    b_map_comparisons: List[MapComparison] = field(default_factory=list)
    ab_map_comparisons: List[MapComparison] = field(default_factory=list)
    final_results: Optional[Dict[str, Any]] = None
    completed_time: Optional[str] = None


@dataclass
class AnalysisExecution:
    """分析実行結果"""
    map_intersection: Optional[MapIntersectionAnalysis] = None
    other_analyses: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class ReportGeneration:
    """レポート生成情報"""
    start_time: Optional[str] = None
    completed_time: Optional[str] = None
    report_filename: Optional[str] = None


@dataclass
class TestExecutionData:
    """テスト実行データ全体"""
    metadata: TestResultMetadata = field(default_factory=TestResultMetadata)
    config_data: Optional[ConfigData] = None
    test_execution: Dict[str, List[IterationResult]] = field(default_factory=lambda: {"iterations": []})
    analysis_execution: AnalysisExecution = field(default_factory=AnalysisExecution)
    report_generation: ReportGeneration = field(default_factory=ReportGeneration)

    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "metadata": {
                "uuid": self.metadata.uuid,
                "execution_start_time": self.metadata.execution_start_time,
                "last_updated": self.metadata.last_updated,
                "status": self.metadata.status,
                "config_loaded": self.metadata.config_loaded,
                "test_cases_discovered": self.metadata.test_cases_discovered,
                "analyzers_discovered": self.metadata.analyzers_discovered
            },
            "config_data": {
                "test_repeat_count": self.config_data.test_repeat_count if self.config_data else 1,
                "partition_size": self.config_data.partition_size if self.config_data else None,
                "active_shares": self.config_data.active_shares if self.config_data else None,
                "garbage_shares": self.config_data.garbage_shares if self.config_data else None,
                "unassigned_shares": self.config_data.unassigned_shares if self.config_data else None,
                "chunk_size": self.config_data.chunk_size if self.config_data else None,
                "hash_algorithm": self.config_data.hash_algorithm if self.config_data else None,
                "encryption_algorithm": self.config_data.encryption_algorithm if self.config_data else None,
                "raw_config": self.config_data.raw_config if self.config_data else {}
            },
            "test_execution": {
                "iterations": [
                    {
                        "iteration": iter_result.iteration,
                        "start_time": iter_result.start_time,
                        "test_results": {
                            test_id: {
                                "test_id": test_result.test_id,
                                "success": test_result.success,
                                "storage_filepath": test_result.storage_filepath,
                                "password_a_random": test_result.password_a_random,
                                "password_b_random": test_result.password_b_random,
                                "password_a_cli": test_result.password_a_cli,
                                "password_b_cli": test_result.password_b_cli,
                                "cli_args": test_result.cli_args,
                                "cli_response_received": test_result.cli_response_received,
                                "password_loaded": test_result.password_loaded,
                                "stdout": test_result.stdout,
                                "stderr": test_result.stderr,
                                "exit_code": test_result.exit_code,
                                "partition_map_a": test_result.partition_map_a,
                                "partition_map_b": test_result.partition_map_b,
                                "execution_time": test_result.execution_time,
                                "performance_data": test_result.performance_data,
                                "error": test_result.error
                            }
                            for test_id, test_result in iter_result.test_results.items()
                        },
                        "completed_time": iter_result.completed_time
                    }
                    for iter_result in self.test_execution["iterations"]
                ]
            },
            "analysis_execution": {
                "map_intersection": {
                    "start_time": self.analysis_execution.map_intersection.start_time if self.analysis_execution.map_intersection else None,
                    "a_map_comparisons": [
                        {
                            "comparison": comp.comparison,
                            "timestamp": comp.timestamp,
                            "rate": comp.rate
                        }
                        for comp in (self.analysis_execution.map_intersection.a_map_comparisons if self.analysis_execution.map_intersection else [])
                    ],
                    "b_map_comparisons": [
                        {
                            "comparison": comp.comparison,
                            "timestamp": comp.timestamp,
                            "rate": comp.rate
                        }
                        for comp in (self.analysis_execution.map_intersection.b_map_comparisons if self.analysis_execution.map_intersection else [])
                    ],
                    "ab_map_comparisons": [
                        {
                            "comparison": comp.comparison,
                            "timestamp": comp.timestamp,
                            "rate": comp.rate
                        }
                        for comp in (self.analysis_execution.map_intersection.ab_map_comparisons if self.analysis_execution.map_intersection else [])
                    ],
                    "final_results": self.analysis_execution.map_intersection.final_results if self.analysis_execution.map_intersection else None,
                    "completed_time": self.analysis_execution.map_intersection.completed_time if self.analysis_execution.map_intersection else None
                } if self.analysis_execution.map_intersection else None,
                "other_analyses": self.analysis_execution.other_analyses
            },
            "report_generation": {
                "start_time": self.report_generation.start_time,
                "completed_time": self.report_generation.completed_time,
                "report_filename": self.report_generation.report_filename
            }
        }