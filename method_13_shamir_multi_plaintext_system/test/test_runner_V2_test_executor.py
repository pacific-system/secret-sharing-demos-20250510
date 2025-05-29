#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
テストランナーV2 - テスト実行処理

【責務】
- テストケースの検出と実行
- イテレーション管理
- ファイルマネージャーとの連携
"""

import os
import sys
import importlib
import inspect
import glob
import logging
from typing import Dict, Any, List, Type, Optional

from utils.config_loader import load_config, is_test_enabled
from utils.test_logger import log_info, log_error, log_test_result, log_warning
from test_cases.base_test import BaseTest
from test_runner_V2_file_manager import TestResultFileManager


class TestCaseDiscoverer:
    """テストケース検出クラス"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def discover_test_cases(self) -> Dict[str, Type[BaseTest]]:
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


class TestExecutor:
    """テスト実行クラス"""

    def __init__(self, file_manager: TestResultFileManager):
        """
        初期化

        Args:
            file_manager: ファイル管理インスタンス
        """
        self.file_manager = file_manager
        self.logger = logging.getLogger(__name__)

    def run_tests(self, test_cases: Dict[str, Type[BaseTest]] = None, verbose: bool = False) -> List[Dict[str, Dict[str, Any]]]:
        """
        テストケースを実行する

        Args:
            test_cases: テストケースのディクショナリ（テストID -> テストクラス）。Noneの場合は自動検出する
            verbose: 詳細なログ出力を行うかどうか

        Returns:
            全テスト実行結果のリスト（互換性のため）
        """
        # テストケースが指定されていない場合は自動検出
        if test_cases is None:
            discoverer = TestCaseDiscoverer()
            test_cases = discoverer.discover_test_cases()

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

        # 互換性のための戻り値用リスト
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

                    # CLI レスポンス受信をファイルに記録
                    if "cli_args" in result:
                        self.file_manager.update_cli_response_received(test_id, iteration + 1)
                        self.logger.info(f"テスト {test_id} の CLI引数: {result['cli_args']}")

                    # パスワード読み込みをファイルに記録
                    if "password_a" in result or "password_b" in result:
                        self.file_manager.update_password_loaded(test_id, iteration + 1)
                        if "password_a" in result:
                            self.logger.info(f"DEBUG: テスト {test_id} のA用パスワード: {result['password_a']}")
                        if "password_b" in result:
                            self.logger.info(f"DEBUG: テスト {test_id} のB用パスワード: {result['password_b']}")

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

            # ファイルマネージャーにイテレーション結果を保存
            self.file_manager.add_iteration_result(iteration + 1, test_results)

            # 互換性のための戻り値用データ構造
            iteration_results = {
                "iteration": iteration + 1,
                "results": test_results
            }
            all_test_results.append(iteration_results)

        log_info(f"全{repeat_count}回のテスト実行が完了しました")
        return all_test_results

    def get_latest_test_results(self) -> Dict[str, Any]:
        """
        最新のテスト結果を取得（互換性のため）

        Returns:
            最新のテスト結果辞書
        """
        execution_data = self.file_manager.get_execution_data()
        if not execution_data or not execution_data.test_execution["iterations"]:
            return {}

        # 最新のイテレーション結果を取得
        latest_iteration = execution_data.test_execution["iterations"][-1]

        # TestResult オブジェクトを辞書形式に変換
        latest_results = {}
        for test_id, test_result in latest_iteration.test_results.items():
            latest_results[test_id] = {
                "test_id": test_result.test_id,
                "success": test_result.success,
                "storage_filename": test_result.storage_filepath,  # 互換性のため
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

        return latest_results

    def get_all_test_results_for_compatibility(self) -> List[Dict[str, Dict[str, Any]]]:
        """
        互換性のための全テスト結果を取得

        Returns:
            全テスト実行結果のリスト
        """
        execution_data = self.file_manager.get_execution_data()
        if not execution_data:
            return []

        all_results = []
        for iteration_result in execution_data.test_execution["iterations"]:
            # TestResult オブジェクトを辞書形式に変換
            results_dict = {}
            for test_id, test_result in iteration_result.test_results.items():
                results_dict[test_id] = {
                    "test_id": test_result.test_id,
                    "success": test_result.success,
                    "storage_filename": test_result.storage_filepath,  # 互換性のため
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

            all_results.append({
                "iteration": iteration_result.iteration,
                "results": results_dict
            })

        return all_results