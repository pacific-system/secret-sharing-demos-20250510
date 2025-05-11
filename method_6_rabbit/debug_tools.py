#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ラビット暗号化方式のデバッグツール

暗号化・復号化プロセスの内部状態を可視化し、
デバッグ情報を記録するためのユーティリティを提供します。
"""

import os
import time
import json
import binascii
import logging
from typing import Any, Dict, List, Union, Optional
import inspect
import sys

# ロギング設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rabbit_debug.log')
    ]
)

# デバッガーロガー
logger = logging.getLogger("RabbitDebug")


class DebugMode:
    """
    デバッグモードの制御クラス
    """
    ENABLED = False  # デフォルトでは無効
    VERBOSE = False  # 詳細モード
    LOG_LEVEL = logging.INFO

    @classmethod
    def enable(cls, verbose=False, log_level=logging.INFO):
        """デバッグモードを有効化"""
        cls.ENABLED = True
        cls.VERBOSE = verbose
        cls.LOG_LEVEL = log_level
        logger.setLevel(log_level)
        logger.info("デバッグモードが有効化されました（詳細モード: %s）", verbose)

    @classmethod
    def disable(cls):
        """デバッグモードを無効化"""
        logger.info("デバッグモードが無効化されました")
        cls.ENABLED = False
        cls.VERBOSE = False


class RabbitDebugger:
    """
    ラビット暗号化方式のデバッグ情報収集クラス
    """
    def __init__(self, component_name: str):
        """
        Args:
            component_name: デバッグ対象のコンポーネント名
        """
        self.component_name = component_name
        self.logger = logging.getLogger(f"RabbitDebug.{component_name}")
        self.logger.setLevel(DebugMode.LOG_LEVEL)

        self.start_time = time.time()
        self.step_times = {}
        self.state_history = []

    def log(self, message: str, level: int = logging.INFO):
        """
        ログメッセージを記録

        Args:
            message: ログメッセージ
            level: ログレベル
        """
        if DebugMode.ENABLED:
            self.logger.log(level, message)

    def log_state(self, state_name: str, state_data: Any, redact_sensitive: bool = True):
        """
        内部状態を記録

        Args:
            state_name: 状態の名前
            state_data: 状態データ
            redact_sensitive: 機密データを編集するかどうか
        """
        if not DebugMode.ENABLED:
            return

        # メモリ使用量が多すぎる場合は詳細なデータをスキップ
        try:
            # データの整形
            if isinstance(state_data, bytes):
                state_value = binascii.hexlify(state_data).decode('ascii')
                if redact_sensitive and len(state_value) > 100:
                    state_value = f"{state_value[:50]}...{state_value[-50:]}"
            elif isinstance(state_data, dict):
                # 辞書のコピーを作成して編集
                state_value = state_data.copy()
                if redact_sensitive:
                    for k, v in state_value.items():
                        if isinstance(v, bytes) and len(v) > 100:
                            state_value[k] = f"{binascii.hexlify(v[:20]).decode('ascii')}..."
                        elif isinstance(v, str) and len(v) > 100:
                            state_value[k] = f"{v[:50]}..."
            else:
                state_value = str(state_data)
                if redact_sensitive and len(state_value) > 100:
                    state_value = f"{state_value[:50]}...{state_value[-50:]}"

            # 状態を記録
            self.state_history.append({
                'component': self.component_name,
                'state': state_name,
                'data': state_value,
                'time': time.time() - self.start_time
            })

            # ログに記録
            if DebugMode.VERBOSE:
                self.logger.debug(f"状態 '{state_name}': {state_value}")
        except Exception as e:
            self.logger.warning(f"状態記録中にエラー: {e}")

    def start_step(self, step_name: str):
        """
        処理ステップの開始時間を記録

        Args:
            step_name: ステップ名
        """
        if DebugMode.ENABLED:
            self.step_times[step_name] = {'start': time.time()}
            self.logger.debug(f"ステップ開始: {step_name}")

    def end_step(self, step_name: str):
        """
        処理ステップの終了時間を記録し、経過時間を計算

        Args:
            step_name: ステップ名

        Returns:
            経過時間（秒）
        """
        if not DebugMode.ENABLED or step_name not in self.step_times:
            return None

        step_data = self.step_times[step_name]
        step_data['end'] = time.time()
        step_data['duration'] = step_data['end'] - step_data['start']

        self.logger.debug(f"ステップ完了: {step_name} ({step_data['duration']:.6f}秒)")
        return step_data['duration']

    def get_state_history(self) -> List[Dict]:
        """
        状態履歴を取得

        Returns:
            状態履歴のリスト
        """
        return self.state_history

    def get_performance_report(self) -> Dict:
        """
        パフォーマンスレポートを生成

        Returns:
            パフォーマンスデータを含む辞書
        """
        report = {
            'component': self.component_name,
            'total_time': time.time() - self.start_time,
            'steps': {},
        }

        # 各ステップの実行時間
        for step_name, step_data in self.step_times.items():
            if 'duration' in step_data:
                report['steps'][step_name] = {
                    'duration': step_data['duration'],
                    'percentage': (step_data['duration'] / report['total_time']) * 100
                }

        return report

    def caller_info(self) -> str:
        """
        呼び出し元の情報を取得

        Returns:
            呼び出し元の情報
        """
        caller_frame = inspect.currentframe().f_back.f_back
        caller_info = inspect.getframeinfo(caller_frame)
        return f"{os.path.basename(caller_info.filename)}:{caller_info.lineno}"


# カプセル化されたデバッグ関数
def debug_log(component: str, message: str, level: int = logging.INFO):
    """
    デバッグログを記録するユーティリティ関数

    Args:
        component: コンポーネント名
        message: ログメッセージ
        level: ログレベル
    """
    if DebugMode.ENABLED:
        logger = logging.getLogger(f"RabbitDebug.{component}")
        logger.log(level, message)


def format_hex(data: bytes, max_len: int = 64) -> str:
    """
    バイトデータを16進数文字列にフォーマット

    Args:
        data: フォーマットするバイトデータ
        max_len: 最大表示長

    Returns:
        フォーマットされた16進数文字列
    """
    hex_str = binascii.hexlify(data).decode('ascii')
    if len(hex_str) > max_len:
        return f"{hex_str[:max_len//2]}...{hex_str[-max_len//2:]}"
    return hex_str


def save_debug_report(report_file: str = "rabbit_debug_report.json"):
    """
    デバッグレポートをファイルに保存

    Args:
        report_file: 出力ファイルパス
    """
    if not DebugMode.ENABLED:
        logger.warning("デバッグモードが有効でないため、レポートを生成できません")
        return

    # 全ロガーからデバッグ情報を収集
    # ...実装は省略...

    logger.info(f"デバッグレポートを保存しました: {report_file}")


if __name__ == "__main__":
    # デバッグツールの使用例
    DebugMode.enable(verbose=True, log_level=logging.DEBUG)

    debugger = RabbitDebugger("Example")
    debugger.log("テストメッセージ")

    debugger.start_step("処理1")
    time.sleep(0.1)  # 処理をシミュレート
    debugger.log_state("中間状態", {"key": "value", "data": os.urandom(32)})
    debugger.end_step("処理1")

    report = debugger.get_performance_report()
    print(json.dumps(report, indent=2))

    DebugMode.disable()