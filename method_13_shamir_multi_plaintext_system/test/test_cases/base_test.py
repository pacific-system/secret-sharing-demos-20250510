#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
テストケースの基底クラス

【責務】
このモジュールは、すべてのテストケースの基底クラスを定義します。
各テストケースはこのクラスを継承して実装します。

【依存関係】
- os.path: ファイルパスの確認に使用
- re: 正規表現による文字列解析に使用
- logging: ログ出力に使用
- utils.cli_runner: CLIコマンド実行に使用
- utils.password_manager: パスワード管理に使用

【使用方法】
from test_cases.base_test import BaseTest

class TestCase(BaseTest):
    def __init__(self):
        super().__init__()
        self.test_id = "TC-001"
        self.test_name = "テストケース名"

    def run(self):
        # テスト実行コード
        return self.results
"""

import os
import re
import logging
from typing import Dict, Any, Optional, List

from utils.cli_runner import run_cli_command
from utils.password_manager import get_password_for_partition, get_two_random_passwords

logger = logging.getLogger(__name__)

class BaseTest:
    """テストケースの基底クラス

    すべてのテストケースはこのクラスを継承します。
    """

    def __init__(self):
        """初期化処理"""
        self.test_id = ""
        self.test_name = ""
        self.results = {}
        self.logger = logger  # クラスレベルのロガーを設定
        # ランダムパスワードを事前に取得
        self._initialize_random_passwords()
        logger.info(f"テストケース {self.__class__.__name__} を初期化しました")

    def _initialize_random_passwords(self):
        """ランダムパスワードを初期化する"""
        password_a, password_b = get_two_random_passwords()
        if password_a and password_b:
            self.results["password_a_random"] = password_a
            self.results["password_b_random"] = password_b
            logger.info(f"ランダムパスワードを初期化しました（A: {len(password_a)}文字, B: {len(password_b)}文字）")
        else:
            logger.error("ランダムパスワードの初期化に失敗しました")
            self.results["password_a_random"] = None
            self.results["password_b_random"] = None

    def get_random_password(self, partition: str) -> str:
        """
        事前に決定されたランダムパスワードを取得する

        Args:
            partition: パーティション識別子（'A' または 'B'）

        Returns:
            ランダムパスワード文字列
        """
        partition_lower = partition.lower()
        password_key = f"password_{partition_lower}_random"

        if password_key in self.results and self.results[password_key]:
            password = self.results[password_key]
            logger.info(f"パーティション {partition} のランダムパスワードを取得しました（長さ: {len(password)}）")
            return password
        else:
            logger.error(f"パーティション {partition} のランダムパスワードが見つかりません")
            raise ValueError(f"パーティション {partition} のランダムパスワードが見つかりません")

    def set_cli_password(self, partition: str, password: str):
        """
        CLIレスポンスから取得したパスワードを設定する

        Args:
            partition: パーティション識別子（'A' または 'B'）
            password: CLIから取得したパスワード
        """
        partition_lower = partition.lower()
        password_key = f"password_{partition_lower}_cli"
        self.results[password_key] = password
        logger.info(f"パーティション {partition} のCLIパスワードを設定しました（長さ: {len(password)}）")

    def get_cli_password(self, partition: str) -> Optional[str]:
        """
        CLIレスポンスから取得したパスワードを取得する

        Args:
            partition: パーティション識別子（'A' または 'B'）

        Returns:
            CLIパスワード文字列、設定されていない場合はNone
        """
        partition_lower = partition.lower()
        password_key = f"password_{partition_lower}_cli"

        if password_key in self.results:
            password = self.results[password_key]
            if password:
                logger.info(f"パーティション {partition} のCLIパスワードを取得しました（長さ: {len(password)}）")
                return password

        logger.warning(f"パーティション {partition} のCLIパスワードが設定されていません")
        return None

    def get_password(self, partition: str) -> str:
        """
        指定されたパーティション用のパスワードを取得する（互換性のため残存）

        Args:
            partition: パーティション識別子（'A' または 'B'）

        Returns:
            パスワード文字列
        """
        # 新しい実装では、ランダムパスワードを返す
        return self.get_random_password(partition)

    def run(self):
        """
        テストケースを実行する

        Returns:
            テスト結果を含む辞書

        Note:
            サブクラスでオーバーライドする必要があります
        """
        raise NotImplementedError("サブクラスで実装する必要があります")

    def check_file_exists(self, filepath: str) -> bool:
        """
        ファイルが存在するかどうかを確認する

        Args:
            filepath: 確認するファイルのパス

        Returns:
            ファイルが存在する場合はTrue、存在しない場合はFalse
        """
        exists = os.path.exists(filepath)
        logger.debug(f"ファイル存在確認: {filepath} -> {'存在します' if exists else '存在しません'}")
        return exists

    def extract_map_key(self, output: str, partition: str) -> Optional[str]:
        """
        CLIの出力からパーティションマップキーを抽出する

        Args:
            output: CLIの出力文字列
            partition: パーティション識別子（'A' または 'B'）

        Returns:
            抽出されたパーティションマップキー、抽出に失敗した場合はNone
        """
        # 複数行からなる標準出力を1行に結合（マップキーは複数行にまたがる可能性があるため）
        output_oneline = output.replace('\n', ' ')

        # メインパターン: "{パーティション}領域用パーティションマップキー: " で始まる部分を検索
        pattern = rf"{partition}領域用パーティションマップキー: ([A-Za-z0-9+/=-]+(?:[-][A-Za-z0-9+/=]+)*(?:AAAAAA)?)"
        match = re.search(pattern, output_oneline)

        if match:
            # マップキー文字列の抽出
            key_raw = match.group(1).strip()

            # 出力を確認（セキュリティのためキーの先頭部分のみ表示）
            logger.info(f"パーティション {partition} 用マップキーを抽出しました（長さ: {len(key_raw)}）")

            # 結果を成功させるため、辞書に追加
            self.results[f'partition_map_key_{partition.lower()}'] = key_raw

            return key_raw

        # 別の試行: 行ごとにチェック
        lines = output.split("\n")
        for i, line in enumerate(lines):
            if f"{partition}領域用パーティションマップキー:" in line:
                # キーが始まる位置
                start_pos = line.find(f"{partition}領域用パーティションマップキー:") + len(f"{partition}領域用パーティションマップキー:")
                # 現在の行から始まるキー部分
                key_part = line[start_pos:].strip()

                # 次の行がある場合は連結する可能性を検討
                full_key = key_part
                j = i + 1
                while j < len(lines) and not lines[j].strip().startswith(("パーティションマップキー", "B領域用")) and len(lines[j].strip()) > 0:
                    full_key += " " + lines[j].strip()
                    j += 1

                logger.info(f"パーティション {partition} 用マップキーを行ベースで抽出しました（長さ: {len(full_key)}）")

                # 結果を成功させるため、辞書に追加
                self.results[f'partition_map_key_{partition.lower()}'] = full_key

                return full_key

        logger.warning(f"パーティション {partition} のマップキーを抽出できませんでした")
        return None

    def parse_partition_map(self, output: str, partition: str) -> Optional[Dict[str, Any]]:
        """
        CLIの出力からパーティションマップ情報を抽出する

        Args:
            output: CLIの出力文字列
            partition: パーティション識別子（'A' または 'B'）

        Returns:
            抽出されたパーティションマップ情報の辞書、抽出に失敗した場合はNone
        """
        # 実際の出力形式に合わせて実装
        # 現時点では単純にNoneを返す
        logger.warning("パーティションマップ情報の抽出機能は未実装です")
        return None

    def extract_storage_filename(self, output: str) -> Optional[str]:
        """
        CLIの出力から暗号化ファイル名を抽出する

        Args:
            output: CLIの出力文字列

        Returns:
            抽出された暗号化ファイル名、抽出に失敗した場合はNone
        """
        # 「暗号書庫を生成しました: {ファイル名}」のパターンを検索
        pattern = r'暗号書庫を生成しました: (.+?)(?:\n|$)'
        match = re.search(pattern, output)

        if match:
            filename = match.group(1).strip()
            logger.info(f"暗号化ファイル名を抽出しました: {filename}")

            # テスト結果にファイル名を保存
            self.results['storage_filename'] = filename
            return filename

        logger.warning("暗号化ファイル名を抽出できませんでした")
        return None

    def extract_partition_map(self, stdout: str, partition_type: str) -> List[int]:
        """
        標準出力からパーティションマップを抽出する

        Args:
            stdout: CLIコマンドの標準出力
            partition_type: パーティションタイプ ('A' または 'B')

        Returns:
            パーティションマップの整数リスト、抽出に失敗した場合は空リスト
        """
        import re
        import json

        # パーティションマップの抽出パターン
        pattern = rf"{partition_type}領域パーティションMAP: (.+?)(?:\n|$)"
        match = re.search(pattern, stdout)

        if match:
            map_str = match.group(1).strip()
            try:
                # JSON形式であるかチェック
                if map_str.startswith('[') and map_str.endswith(']'):
                    map_indices = json.loads(map_str)
                    self.logger.info(f"{partition_type}領域パーティションMAPを抽出しました: {map_str[:30]}...")
                    return map_indices
                # カンマ区切りの数値リストの場合
                else:
                    # 角括弧を除去し、カンマで分割
                    map_str = map_str.strip('[]')
                    map_indices = [int(idx.strip()) for idx in map_str.split(',') if idx.strip().isdigit()]
                    self.logger.info(f"{partition_type}領域パーティションMAPを抽出しました: {map_indices[:5]}...")
                    return map_indices
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.error(f"{partition_type}領域パーティションMAPの解析に失敗しました: {e}")
                return []

        self.logger.warning(f"{partition_type}領域パーティションMAPが見つかりませんでした")
        return []

    def run_cli_command(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        CLIコマンドを実行し、結果を取得する

        Args:
            command: 実行するCLIコマンド
            args: コマンドライン引数（キー: 引数名、値: 引数値）

        Returns:
            実行結果のディクショナリ（stdout, stderr, exit_code, success, command, args）
        """
        import subprocess
        import time

        start_time = time.time()

        # コマンドラインを構築
        cmd_parts = [command]
        cli_args = {}

        for arg_name, arg_value in args.items():
            if arg_name.startswith('-'):
                if arg_value is True:
                    # フラグオプション（値なし）
                    cmd_parts.append(arg_name)
                elif arg_value is not None:
                    # 値を持つオプション
                    cmd_parts.append(arg_name)

                    # スペースを含む値は引用符で囲む
                    if isinstance(arg_value, str) and (' ' in arg_value or '\t' in arg_value):
                        cmd_parts.append(f"'{arg_value}'")
                    else:
                        cmd_parts.append(str(arg_value))

                    # CLIの引数を記録
                    cli_args[arg_name] = arg_value

        cmd_line = ' '.join(cmd_parts)
        self.logger.info(f"実行するコマンド: {cmd_line}")

        # コマンド実行
        try:
            process = subprocess.Popen(
                cmd_line,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )

            stdout, stderr = process.communicate()
            exit_code = process.returncode

            end_time = time.time()
            execution_time = end_time - start_time

            # 標準出力と標準エラー出力をログに記録
            if stdout:
                self.logger.debug(f"標準出力:\n{stdout}")

            if stderr:
                self.logger.warning(f"標準エラー出力:\n{stderr}")

            # 結果をディクショナリにまとめる
            result = {
                "command": command,
                "args": args,
                "cli_args": cli_args,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "success": exit_code == 0,
                "execution_time": execution_time
            }

            # パーティションマップを抽出
            a_partition_map = self.extract_partition_map(stdout, "A")
            b_partition_map = self.extract_partition_map(stdout, "B")

            # テスト結果に保存
            if a_partition_map:
                result["partition_map_a"] = a_partition_map
                self.results["partition_map_a"] = a_partition_map

            if b_partition_map:
                result["partition_map_b"] = b_partition_map
                self.results["partition_map_b"] = b_partition_map

            # 暗号化ファイル名を抽出
            storage_filename = self.extract_storage_filename(stdout)
            if storage_filename:
                result["storage_filename"] = storage_filename

            return result

        except Exception as e:
            self.logger.error(f"コマンド実行中にエラーが発生しました: {str(e)}")

            return {
                "command": command,
                "args": args,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time
            }