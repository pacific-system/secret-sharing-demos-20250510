#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
設定ファイル読み込みユーティリティ

【責務】
このモジュールは、テスト設定ファイル（test_config.json）を読み込み、
テストケースや分析処理の有効/無効を管理する機能を提供します。

【依存関係】
- json: JSONファイルの読み込みに使用
- logging: ログ出力に使用
- os.path: ファイルパス操作に使用

【使用方法】
from utils.config_loader import load_config, is_test_enabled, is_analysis_enabled

config = load_config()
if is_test_enabled("CC-001"):
    # テストケースCC-001を実行
"""

import json
import logging
import os
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# モジュールレベルのキャッシュ変数
_config_cache = None

def get_config_path() -> str:
    """設定ファイルのパスを取得する"""
    # まずは現在のディレクトリからの相対パスを試す
    current_test_config = "test_config.json"
    if os.path.exists(current_test_config):
        return os.path.abspath(current_test_config)

    # 親ディレクトリを探す
    current_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.dirname(current_dir)
    config_path = os.path.join(test_dir, "test_config.json")

    # 絶対パスを返す
    return config_path

def load_config(force_reload: bool = False) -> Optional[Dict[str, Any]]:
    """
    設定ファイル（test_config.json）を読み込む

    Args:
        force_reload: キャッシュを無視して強制的に再読み込みするフラグ

    Returns:
        設定データの辞書、読み込みに失敗した場合はNone
    """
    global _config_cache

    # キャッシュされたデータがあり、強制再読み込みでない場合はキャッシュを返す
    if _config_cache is not None and not force_reload:
        return _config_cache

    config_path = get_config_path()

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        logger.info(f"設定ファイルを読み込みました: {config_path}")

        # キャッシュに保存
        _config_cache = config
        return config

    except FileNotFoundError:
        logger.error(f"設定ファイルが見つかりません: {config_path}")
        return None

    except json.JSONDecodeError as e:
        logger.error(f"設定ファイルのJSON形式が不正です: {str(e)}")
        return None

    except Exception as e:
        logger.error(f"設定ファイルの読み込み中にエラーが発生しました: {str(e)}")
        return None

def is_test_enabled(test_id: str) -> bool:
    """
    指定されたテストケースが有効かどうかを確認する

    Args:
        test_id: テストケースID（例: "CC-001"）

    Returns:
        有効の場合はTrue、無効またはIDが存在しない場合はFalse
    """
    config = load_config()
    if not config:
        logger.warning(f"設定が読み込めないため、テスト {test_id} は実行されません")
        return False

    return config.get("test_cases", {}).get(test_id, False)

def is_analysis_enabled(analysis_id: str) -> bool:
    """
    指定された分析処理が有効かどうかを確認する

    Args:
        analysis_id: 分析処理ID（例: "key_length"）

    Returns:
        有効の場合はTrue、無効またはIDが存在しない場合はFalse
    """
    config = load_config()
    if not config:
        logger.warning(f"設定が読み込めないため、分析 {analysis_id} は実行されません")
        return False

    return config.get("analytics", {}).get(analysis_id, False)

def get_reporting_option(option: str, default: Any = None) -> Any:
    """
    レポート設定オプションを取得する

    Args:
        option: オプション名（例: "include_raw_data"）
        default: オプションが存在しない場合のデフォルト値

    Returns:
        オプション値、存在しない場合はデフォルト値
    """
    config = load_config()
    if not config:
        logger.warning(f"設定が読み込めないため、レポートオプション {option} はデフォルト値を使用します")
        return default

    return config.get("reporting", {}).get(option, default)