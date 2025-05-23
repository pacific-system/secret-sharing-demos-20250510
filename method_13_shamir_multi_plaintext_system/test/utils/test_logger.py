#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
テストログ出力ユーティリティ

【責務】
このモジュールは、テスト実行中のログ出力機能を提供します。
情報、警告、エラーなどの各種ログレベルでのログ出力と、
テスト結果の記録を行います。

【依存関係】
- logging: ログ出力に使用
- os: ディレクトリ作成に使用
- datetime: タイムスタンプ生成に使用

【使用方法】
from utils.test_logger import setup_logger, log_info, log_warning, log_error, log_test_result

setup_logger()
log_info("テスト開始")
log_test_result("CC-001", {"success": True, "message": "テスト成功"})
"""

import logging
import os
import sys
import datetime
from typing import Dict, Any, Optional

# デフォルトのログレベル
DEFAULT_LOG_LEVEL = logging.INFO

# ロガーの初期化フラグ
_logger_initialized = False

def get_log_dir() -> str:
    """ログディレクトリのパスを取得する"""
    # カレントディレクトリからの相対パス
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_dir = os.path.join(base_dir, "method_13_shamir_multi_plaintext_system", "test", "logs")

    # ディレクトリが存在しない場合は作成
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    return log_dir

def get_log_file_path() -> str:
    """ログファイルのパスを取得する"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = get_log_dir()
    log_file_path = os.path.join(log_dir, f"test_log_{timestamp}.log")

    return log_file_path

def setup_logger(log_level: int = DEFAULT_LOG_LEVEL) -> logging.Logger:
    """
    ロガーを設定する

    Args:
        log_level: ログレベル（logging.DEBUG, logging.INFO など）

    Returns:
        設定されたロガー
    """
    global _logger_initialized

    # ルートロガーを取得
    logger = logging.getLogger()

    # 既に初期化済みの場合は何もしない
    if _logger_initialized:
        return logger

    # ログレベルを設定
    logger.setLevel(log_level)

    # コンソールハンドラを設定
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # ファイルハンドラを設定
    log_file_path = get_log_file_path()
    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setLevel(log_level)

    # フォーマッタを設定
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # ハンドラをロガーに追加
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # 初期化完了
    _logger_initialized = True

    logger.info(f"ロガーを設定しました: {log_file_path}")
    return logger

def log_info(message: str) -> None:
    """
    情報レベルのログを出力する

    Args:
        message: ログメッセージ
    """
    logger = logging.getLogger("test")

    # ロガーが初期化されていない場合は初期化
    if not _logger_initialized:
        setup_logger()

    logger.info(message)

def log_warning(message: str) -> None:
    """
    警告レベルのログを出力する

    Args:
        message: ログメッセージ
    """
    logger = logging.getLogger("test")

    # ロガーが初期化されていない場合は初期化
    if not _logger_initialized:
        setup_logger()

    logger.warning(message)

def log_error(message: str) -> None:
    """
    エラーレベルのログを出力する

    Args:
        message: ログメッセージ
    """
    logger = logging.getLogger("test")

    # ロガーが初期化されていない場合は初期化
    if not _logger_initialized:
        setup_logger()

    logger.error(message)

def log_debug(message: str) -> None:
    """
    デバッグレベルのログを出力する

    Args:
        message: ログメッセージ
    """
    logger = logging.getLogger("test")

    # ロガーが初期化されていない場合は初期化
    if not _logger_initialized:
        setup_logger()

    logger.debug(message)

def log_test_result(test_id: str, result: Dict[str, Any]) -> None:
    """
    テスト結果をログに出力する

    Args:
        test_id: テストケースID（例: "CC-001"）
        result: テスト結果の辞書
    """
    logger = logging.getLogger("test.result")

    # ロガーが初期化されていない場合は初期化
    if not _logger_initialized:
        setup_logger()

    success = result.get("success", False)
    status = "成功" if success else "失敗"

    logger.info(f"テスト {test_id} の結果: {status}")

    # 結果の詳細をデバッグレベルでログ出力
    for key, value in result.items():
        if key != "success":
            logger.debug(f"  {key}: {value}")

def log_analysis_result(analysis_id: str, result: Dict[str, Any]) -> None:
    """
    分析結果をログに出力する

    Args:
        analysis_id: 分析処理ID（例: "key_length"）
        result: 分析結果の辞書
    """
    logger = logging.getLogger("test.analysis")

    # ロガーが初期化されていない場合は初期化
    if not _logger_initialized:
        setup_logger()

    pass_result = result.get("pass", False)
    status = "合格" if pass_result else "不合格"

    logger.info(f"分析 {analysis_id} の結果: {status}")

    # 結果の詳細をデバッグレベルでログ出力
    for key, value in result.items():
        if key != "pass" and key != "name" and key != "description":
            logger.debug(f"  {key}: {value}")