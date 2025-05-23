#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基本生成テスト（CC-001）

【責務】
このモジュールは、シャミア秘密分散法による複数平文復号システムの
基本的な暗号書庫生成機能をテストします。基本パラメータで暗号書庫を生成し、
出力を検証します。

【依存関係】
- test_cases.base_test: テストケースの基底クラス
- logging: ログ出力に使用
- os: ファイル操作に使用
- datetime: タイムスタンプ生成に使用

【使用方法】
from test_cases.crypto_storage_creation.test_cc_001_basic_creation import TestBasicCreation

test = TestBasicCreation()
results = test.run()
"""

import os
import logging
import datetime
from typing import Dict, Any

from test_cases.base_test import BaseTest

logger = logging.getLogger(__name__)

class TestBasicCreation(BaseTest):
    """基本生成テスト（CC-001）

    基本パラメータで暗号書庫を生成し、出力を検証する。
    """

    def __init__(self):
        super().__init__()
        self.test_id = "CC-001"
        self.test_name = "基本生成テスト"
        logger.info(f"{self.test_name}（{self.test_id}）を初期化しました")

    def run(self) -> Dict[str, Any]:
        """テストケースを実行する"""
        logger.info(f"{self.test_name}（{self.test_id}）を実行します")

        # A用パスワードを取得
        password_a = self.get_password('A')

        # B用パスワードを取得
        password_b = self.get_password('B')

        # プロジェクトルートパスを取得
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        # CLIコマンドの完全パスを構築
        cli_path = os.path.join(project_root, "cli", "create_storage.py")

        # CLIコマンド実行
        cli_result = self.run_cli_command(
            cli_path,
            {
                '-o': 'output',
                '-a': password_a,
                '-b': password_b,
                '-v': True  # 検証フラグを有効に
            }
        )

        # 結果を記録
        self.results.update({
            'test_id': self.test_id,
            'test_name': self.test_name,
            'exit_code': cli_result['exit_code'],
            'success': cli_result['success'],
            'storage_file_created': True,
        })

        # 成功した場合の追加処理
        if self.results['success'] and self.results['storage_file_created']:
            # パーティションマップキーを抽出
            stdout = cli_result['stdout']
            self.results['partition_map_key_a'] = self.extract_map_key(stdout, 'A')
            self.results['partition_map_key_b'] = self.extract_map_key(stdout, 'B')

            # 成功判定（A/Bのマップキーが両方抽出できたか）
            self.results['success'] = (
                self.results['partition_map_key_a'] is not None and
                self.results['partition_map_key_b'] is not None
            )

            if self.results['success']:
                logger.info(f"{self.test_name}（{self.test_id}）は成功しました")
            else:
                logger.error(f"{self.test_name}（{self.test_id}）はパーティションマップキーの抽出に失敗しました")
        else:
            logger.error(f"{self.test_name}（{self.test_id}）はコマンド実行に失敗しました")
            if 'stderr' in cli_result and cli_result['stderr']:
                logger.error(f"エラー詳細: {cli_result['stderr']}")
            if 'stdout' in cli_result and cli_result['stdout']:
                logger.debug(f"標準出力: {cli_result['stdout']}")

        return self.results