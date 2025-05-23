#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLIコマンド実行ユーティリティ

【責務】
このモジュールは、CLIコマンドを実行し、結果を取得する機能を提供します。
テストケースからCLIコマンドを実行する際に使用されます。

【依存関係】
- subprocess: コマンド実行のために使用
- logging: ログ出力のために使用

【使用方法】
from utils.cli_runner import run_cli_command

exit_code, stdout, stderr = run_cli_command(
    'create_storage.py',
    {
        '--output': 'test_storage.bin',
        '--password-a': 'password1',
        '--password-b': 'password2'
    }
)
"""

import subprocess
import logging
import shlex
import os
from typing import Dict, Tuple, Optional, List, Union

logger = logging.getLogger(__name__)

def run_cli_command(
    command: str,
    args: Dict[str, Union[str, bool]] = None,
    input_data: str = None,
    cwd: str = None
) -> Tuple[int, str, str]:
    """
    CLIコマンドを実行し、結果を取得する

    Args:
        command: 実行するCLIコマンド（例: 'create_storage.py'）
        args: コマンドライン引数の辞書
            キーは引数名（例: '--output'）、値は引数値（例: 'test_storage.bin'）
            引数値がbool型の場合、Trueならフラグとして追加、Falseなら無視
        input_data: 標準入力に送るデータ（オプション）
        cwd: コマンドを実行するディレクトリ（オプション）

    Returns:
        (exit_code, stdout, stderr): 終了コード、標準出力、標準エラー出力
    """
    # コマンドを構築
    cmd = [command]

    if args:
        for key, value in args.items():
            if isinstance(value, bool):
                if value:
                    # boolean引数はフラグとして追加
                    cmd.append(key)
            else:
                # 通常の引数はキーと値のペアとして追加
                cmd.append(key)
                cmd.append(str(value))

    # コマンドの文字列表現（ログ用）
    cmd_str = ' '.join(shlex.quote(arg) for arg in cmd)
    logger.info(f"実行するコマンド: {cmd_str}")

    # 実行時のディレクトリ
    if cwd:
        logger.info(f"実行ディレクトリ: {cwd}")
    else:
        logger.info(f"実行ディレクトリ: {os.getcwd()}")

    # 引数をシェルエスケープしない形式で実行
    try:
        # inputを指定した場合、テキストモードでエンコード
        stdin_data = None
        if input_data:
            stdin_data = input_data.encode('utf-8')

        # コマンド実行
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_data else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd
        )

        # 入出力の処理
        stdout_bytes, stderr_bytes = process.communicate(stdin_data)

        # バイナリデータをテキストに変換
        stdout = stdout_bytes.decode('utf-8')
        stderr = stderr_bytes.decode('utf-8')

        exit_code = process.returncode

        # 結果をログに出力
        logger.debug(f"コマンド終了コード: {exit_code}")
        if stdout:
            logger.debug(f"標準出力: {stdout[:200]}...")
        if stderr:
            logger.warning(f"標準エラー: {stderr}")

        return exit_code, stdout, stderr

    except Exception as e:
        error_msg = f"コマンド実行中にエラーが発生しました: {e}"
        logger.error(error_msg)
        return 1, "", error_msg