#!/usr/bin/env python3
"""
テスト実行スクリプト

【責務】
このモジュールは、シャミア秘密分散法による複数平文復号システムの
テストを実行し、テストレポートを生成します。
"""

import os
import sys
import json
import time
import datetime
import unittest
import subprocess
from pathlib import Path
import tempfile
import shutil

# 親ディレクトリをPATHに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

# テストモジュールをインポート
from tests.test_basic import TestBasicFunctionality
from tests.test_crypto_storage_creation import TestCryptoStorageCreation

# 必要なモジュールをインポート
from shamir.constants import ShamirConstants


class TestRunner:
    """テスト実行とレポート生成を行うクラス"""

    def __init__(self):
        """初期化"""
        self.start_time = None
        self.end_time = None
        self.test_results = {}
        self.test_report_dir = Path(__file__).parent / "test_report"
        self.test_report_dir.mkdir(exist_ok=True)

        # テスト実行時のタイムスタンプ
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # テンポラリディレクトリ
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # プロジェクトのルートディレクトリ
        self.project_root = Path(__file__).parent.parent

        # CLIコマンドのパス
        self.cli_path = self.project_root / "cli" / "shamir_cli.py"
        if not self.cli_path.exists():
            raise FileNotFoundError(f"CLIコマンドが見つかりません: {self.cli_path}")

    def run_tests(self):
        """テストを実行"""
        # 開始時間を記録
        self.start_time = time.time()

        # 単体テストを実行
        unit_test_result = self._run_unit_tests()

        # CLIテストを実行
        cli_test_result = self._run_cli_tests()

        # 終了時間を記録
        self.end_time = time.time()

        # テスト結果を集計
        total_tests = unit_test_result.testsRun + len(cli_test_result)
        total_failures = len(unit_test_result.failures) + sum(1 for r in cli_test_result if not r["success"])
        total_errors = len(unit_test_result.errors)
        total_skipped = len(unit_test_result.skipped)

        # テスト結果を保存
        self.test_results = {
            "total": total_tests,
            "success": total_tests - total_failures - total_errors - total_skipped,
            "failures": total_failures,
            "errors": total_errors,
            "skipped": total_skipped,
            "execution_time": self.end_time - self.start_time
        }

        # 詳細なエラー情報を保存
        self.test_results["unit_test_failures"] = [
            {"test": str(test), "message": str(err)}
            for test, err in unit_test_result.failures
        ]
        self.test_results["unit_test_errors"] = [
            {"test": str(test), "message": str(err)}
            for test, err in unit_test_result.errors
        ]
        self.test_results["cli_test_failures"] = [
            r for r in cli_test_result if not r["success"]
        ]

        return self.test_results

    def _run_unit_tests(self):
        """単体テストを実行"""
        # テストスイートを作成
        suite = unittest.TestSuite()

        # テストクラスをスイートに追加
        suite.addTest(unittest.makeSuite(TestBasicFunctionality))
        suite.addTest(unittest.makeSuite(TestCryptoStorageCreation))

        # テスト実行
        runner = unittest.TextTestRunner(verbosity=2)
        return runner.run(suite)

    def _run_cli_tests(self):
        """CLIテストを実行"""
        print("\n==== CLI機能テスト実行 ====")

        cli_tests = [
            {
                "name": "暗号書庫生成テスト",
                "command": ["python", str(self.cli_path), "create-storage",
                           "--a-password", "test_password_a",
                           "--b-password", "test_password_b",
                           "--output", str(self.temp_path / "storage.json")],
                "expected_exit_code": 0
            },
            {
                "name": "暗号書庫更新Aテスト",
                "command": ["python", str(self.cli_path), "update-storage",
                           "--partition", "a",
                           "--password", "test_password_a",
                           "--input", str(self.temp_path / "storage.json"),
                           "--data", '{"title":"Test Document A","content":"Secret content A"}'],
                "expected_exit_code": 0
            },
            {
                "name": "暗号書庫更新Bテスト",
                "command": ["python", str(self.cli_path), "update-storage",
                           "--partition", "b",
                           "--password", "test_password_b",
                           "--input", str(self.temp_path / "storage.json"),
                           "--data", '{"title":"Test Document B","content":"Secret content B"}'],
                "expected_exit_code": 0
            },
            {
                "name": "暗号書庫読取Aテスト",
                "command": ["python", str(self.cli_path), "read-storage",
                           "--partition", "a",
                           "--password", "test_password_a",
                           "--input", str(self.temp_path / "storage.json")],
                "expected_exit_code": 0,
                "expected_output_contains": "Test Document A"
            },
            {
                "name": "暗号書庫読取Bテスト",
                "command": ["python", str(self.cli_path), "read-storage",
                           "--partition", "b",
                           "--password", "test_password_b",
                           "--input", str(self.temp_path / "storage.json")],
                "expected_exit_code": 0,
                "expected_output_contains": "Test Document B"
            },
            {
                "name": "不正パスワードテスト",
                "command": ["python", str(self.cli_path), "read-storage",
                           "--partition", "a",
                           "--password", "wrong_password",
                           "--input", str(self.temp_path / "storage.json")],
                "expected_exit_code": 1
            }
        ]

        results = []
        for test in cli_tests:
            print(f"\n実行: {test['name']}")
            print(f"コマンド: {' '.join(test['command'])}")

            try:
                # コマンド実行
                process = subprocess.run(
                    test['command'],
                    capture_output=True,
                    text=True,
                    check=False
                )

                # 結果の検証
                success = process.returncode == test['expected_exit_code']

                # 期待する出力の検証
                if success and test.get('expected_output_contains'):
                    if test['expected_output_contains'] not in process.stdout:
                        success = False
                        message = f"期待する出力が含まれていません: {test['expected_output_contains']}"
                    else:
                        message = "成功"
                else:
                    message = "成功" if success else f"期待する終了コード: {test['expected_exit_code']}, 実際の終了コード: {process.returncode}"

                # 結果を記録
                results.append({
                    "name": test['name'],
                    "command": ' '.join(test['command']),
                    "success": success,
                    "message": message,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "exit_code": process.returncode
                })

                print(f"結果: {'成功' if success else '失敗'}")

            except Exception as e:
                # 例外発生時
                results.append({
                    "name": test['name'],
                    "command": ' '.join(test['command']),
                    "success": False,
                    "message": f"例外が発生しました: {str(e)}",
                    "stdout": "",
                    "stderr": str(e),
                    "exit_code": -1
                })
                print(f"結果: 失敗 (例外発生)")

        return results

    def generate_report(self):
        """テストレポートを生成"""
        report_template = self._load_report_template()
        report_content = self._fill_report_template(report_template)

        # レポートファイルを保存
        report_file_path = self.test_report_dir / f"test_report_{self.timestamp}.md"
        with open(report_file_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"テストレポートを生成しました: {report_file_path}")
        return report_file_path

    def _load_report_template(self):
        """レポートテンプレートを読み込み"""
        template_path = Path(__file__).parent / "trash" / "test_report_template.md"
        if not template_path.exists():
            # テンプレートが見つからない場合は基本テンプレートを使用
            return self._create_basic_template()

        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()

    def _create_basic_template(self):
        """基本的なレポートテンプレートを作成"""
        return """# シャミア秘密分散法による複数平文復号システム - テスト実行レポート

**ファイル名**: test_report_{timestamp}.md

## テスト範囲

- [{'X' if any(t['name'].startswith('暗号書庫生成') for t in self.test_results.get('cli_test_failures', [])) else '✓'}] 1. 暗号書庫生成（createCryptoStorage）
- [{'X' if any(t['name'].startswith('暗号書庫更新') for t in self.test_results.get('cli_test_failures', [])) else '✓'}] 2. 暗号書庫更新（updateCryptoStorage）
- [{'X' if any(t['name'].startswith('暗号書庫読取') for t in self.test_results.get('cli_test_failures', [])) else '✓'}] 3. 暗号書庫読取（readCryptoStorage）

## システム条件・環境パラメータ

- **PARTITION_SIZE**: {partition_size}
- **ACTIVE_SHARES**: {active_shares}
- **GARBAGE_SHARES**: {garbage_shares}
- **UNASSIGNED_SHARES**: {unassigned_shares}
- **CHUNK_SIZE**: {chunk_size} (バイト)
- **ハッシュアルゴリズム**: {hash_algorithm}
- **暗号化アルゴリズム**: {encryption_algorithm}

## CLI実行結果

{cli_test_results}

## テスト結果サマリー

- **合計テスト数**: {total_tests}
- **成功**: {successful_tests}
- **失敗**: {failed_tests}
- **エラー**: {error_tests}
- **スキップ**: {skipped_tests}
- **実行時間**: {execution_time:.2f} 秒

## 失敗テスト詳細

{failure_details}

## 特記事項

{notes}
"""

    def _fill_report_template(self, template):
        """テンプレートに値を埋め込む"""
        # システムパラメータ
        params = {
            "timestamp": self.timestamp,
            "partition_size": ShamirConstants.PARTITION_SIZE,
            "active_shares": ShamirConstants.ACTIVE_SHARES,
            "garbage_shares": ShamirConstants.GARBAGE_SHARES,
            "unassigned_shares": ShamirConstants.UNASSIGNED_SHARES,
            "chunk_size": ShamirConstants.CHUNK_SIZE,
            "hash_algorithm": "PBKDF2-HMAC-SHA256",
            "encryption_algorithm": "AES-256-GCM",

            # テスト結果
            "total_tests": self.test_results.get("total", 0),
            "successful_tests": self.test_results.get("success", 0),
            "failed_tests": self.test_results.get("failures", 0),
            "error_tests": self.test_results.get("errors", 0),
            "skipped_tests": self.test_results.get("skipped", 0),
            "execution_time": self.test_results.get("execution_time", 0),

            # CLI実行結果
            "cli_test_results": self._format_cli_test_results(),

            # 失敗詳細
            "failure_details": self._format_failure_details(),

            # 特記事項
            "notes": "特になし" if self.test_results.get("failures", 0) == 0 else "テスト失敗があります。詳細をご確認ください。"
        }

        # テンプレートを埋め込む
        for key, value in params.items():
            template = template.replace(f"{{{key}}}", str(value))

        return template

    def _format_cli_test_results(self):
        """CLI実行結果をフォーマット"""
        if not hasattr(self, 'test_results') or 'cli_test_failures' not in self.test_results:
            return "CLI実行結果はありません。"

        results = []
        results.append("| テスト名 | コマンド | 結果 | メッセージ |")
        results.append("| --- | --- | --- | --- |")

        # 全てのCLIテスト結果を取得（成功も失敗も含む）
        all_cli_results = []
        for result in self.test_results.get('cli_test_failures', []):
            all_cli_results.append(result)

        # 結果をテーブルとして出力
        for result in all_cli_results:
            status = "✅ 成功" if result["success"] else "❌ 失敗"
            # コマンドを60文字に制限
            command = result["command"]
            if len(command) > 60:
                command = command[:57] + "..."

            results.append(f"| {result['name']} | `{command}` | {status} | {result['message']} |")

        return "\n".join(results)

    def _format_failure_details(self):
        """失敗テストの詳細をフォーマット"""
        details = []

        # 単体テスト失敗
        if self.test_results.get("unit_test_failures", []):
            details.append("### 単体テスト失敗")
            for failure in self.test_results.get("unit_test_failures", []):
                details.append(f"#### {failure['test']}")
                details.append(f"```\n{failure['message']}\n```\n")

        # 単体テストエラー
        if self.test_results.get("unit_test_errors", []):
            details.append("### 単体テストエラー")
            for error in self.test_results.get("unit_test_errors", []):
                details.append(f"#### {error['test']}")
                details.append(f"```\n{error['message']}\n```\n")

        # CLI失敗テスト
        if self.test_results.get("cli_test_failures", []):
            failed_tests = [t for t in self.test_results.get("cli_test_failures", []) if not t["success"]]
            if failed_tests:
                details.append("### CLI失敗テスト")
                for failure in failed_tests:
                    details.append(f"#### {failure['name']}")
                    details.append(f"コマンド: `{failure['command']}`")
                    details.append(f"終了コード: {failure['exit_code']}")
                    details.append(f"エラーメッセージ: {failure['message']}")
                    if failure['stdout']:
                        details.append("標準出力:")
                        details.append(f"```\n{failure['stdout']}\n```")
                    if failure['stderr']:
                        details.append("標準エラー出力:")
                        details.append(f"```\n{failure['stderr']}\n```\n")

        return "\n".join(details) if details else "なし"

    def cleanup(self):
        """後処理"""
        self.temp_dir.cleanup()


def main():
    """メイン関数"""
    runner = TestRunner()
    try:
        print("==== シャミア秘密分散法テスト実行 ====")
        test_results = runner.run_tests()
        report_path = runner.generate_report()

        # 結果の表示
        print("\n==== テスト結果サマリー ====")
        print(f"合計テスト数: {test_results['total']}")
        print(f"成功: {test_results['success']}")
        print(f"失敗: {test_results['failures']}")
        print(f"エラー: {test_results['errors']}")
        print(f"スキップ: {test_results['skipped']}")
        print(f"実行時間: {test_results['execution_time']:.2f} 秒")
        print(f"レポート: {report_path}")

        # 終了コード
        if test_results['failures'] > 0 or test_results['errors'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    finally:
        runner.cleanup()


if __name__ == "__main__":
    main()