#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
レポート生成ユーティリティ

【責務】
このモジュールは、テスト結果と分析結果からテストレポートを生成する機能を提供します。
test_report_template.mdに定義されたテンプレートを使用して、プレースホルダーを適切に置換します。

【依存関係】
- os.path: ファイルパス操作に使用
- datetime: 現在時刻の取得に使用
- re: 正規表現によるプレースホルダー検出に使用
- logging: ログ出力に使用

【使用方法】
from utils.report_generator import generate_report, save_report

report = generate_report(test_results, analysis_results)
save_report(report, "test_report_20250510_123045.md")
"""

import os
import sys
import datetime
import re
import logging
import importlib
from typing import Dict, Any, List, Optional

from utils.config_loader import load_config

logger = logging.getLogger(__name__)

# プロジェクトのルートディレクトリをPythonパスに追加
current_dir = os.path.dirname(os.path.abspath(__file__))
test_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(test_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)
    logger.info(f"プロジェクトルートをPythonパスに追加しました: {project_root}")

# ShamirConstantsモジュールを動的にインポートする
try:
    from shamir.constants import ShamirConstants
    CONSTANTS_AVAILABLE = True
    logger.info("shamir.constants モジュールを正常にインポートしました")
except ImportError as e:
    logger.warning(f"shamir.constants モジュールをインポートできませんでした（エラー: {str(e)}）。システムパラメータ値は「値が取得できません」と表示されます。")
    CONSTANTS_AVAILABLE = False

def get_template_path() -> str:
    """レポートテンプレートのパスを取得する"""
    # まずは現在のディレクトリからの相対パスを試す
    current_template = "test_report_template.md"
    if os.path.exists(current_template):
        return os.path.abspath(current_template)

    # 親ディレクトリを探す
    current_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.dirname(current_dir)
    template_path = os.path.join(test_dir, "test_report_template.md")

    # 絶対パスを返す
    return template_path

def load_template() -> Optional[str]:
    """
    レポートテンプレートを読み込む

    Returns:
        テンプレート文字列、読み込みに失敗した場合はNone
    """
    template_path = get_template_path()

    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            template = f.read()

        logger.info(f"レポートテンプレートを読み込みました: {template_path}")
        return template

    except FileNotFoundError:
        logger.error(f"レポートテンプレートが見つかりません: {template_path}")
        # テンプレートがない場合は簡易テンプレートを使用
        logger.info("簡易テンプレートを使用します")
        return """# シャミア秘密分散法による複数平文復号システム テストレポート

## 実行日時
{execution_datetime}

## テスト結果サマリー
- 実行テスト数: {テスト数}
- 成功: {成功数}
- 失敗: {失敗数}

## 分析結果
- キー長分析: {key_length_analysis}
"""

    except Exception as e:
        logger.error(f"レポートテンプレートの読み込み中にエラーが発生しました: {str(e)}")
        return None

def get_report_dir() -> str:
    """レポート保存ディレクトリのパスを取得する"""
    # まずは現在のディレクトリ内に作成
    report_dir = "test_report"

    # ディレクトリが存在しない場合は作成
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    return os.path.abspath(report_dir)

def extract_placeholders(template: str) -> List[str]:
    """
    テンプレートからプレースホルダーを抽出する

    Args:
        template: テンプレート文字列

    Returns:
        プレースホルダーのリスト（例: ['execution_datetime', 'パーティションサイズ値', ...]）
    """
    # 正規表現でプレースホルダーを抽出
    # {プレースホルダー} 形式を検出
    placeholders = re.findall(r'\{([^{}]+)\}', template)

    # 重複を除去
    unique_placeholders = sorted(set(placeholders))

    logger.debug(f"抽出されたプレースホルダー: {unique_placeholders}")
    return unique_placeholders

def get_cli_args_from_stdout(stdout: str) -> Dict[str, str]:
    """
    標準出力からCLIコマンドの引数を抽出する

    Args:
        stdout: CLIコマンドの標準出力

    Returns:
        CLIコマンド引数の辞書 {'-a': 'password_a', '-b': 'password_b', ...}
    """
    cli_args = {}

    # CLIコマンド行を探す
    cmd_pattern = r'実行するコマンド: (.+?)$'
    cmd_matches = re.findall(cmd_pattern, stdout, re.MULTILINE)

    if not cmd_matches:
        return cli_args

    cmd_line = cmd_matches[0]

    # 引数パターンを検出 (-a password など)
    # 引用符付きの引数も対応
    arg_patterns = [
        r'\s-([a-z])\s+([^\s\'-]+)', # スペース区切り、引用符なし
        r'\s-([a-z])\s+\'([^\']+)\'', # シングルクォート
        r'\s-([a-z])\s+\"([^\"]+)\"', # ダブルクォート
    ]

    for pattern in arg_patterns:
        arg_matches = re.findall(pattern, cmd_line)
        for arg_name, arg_value in arg_matches:
            cli_args[f'-{arg_name}'] = arg_value

    return cli_args

def get_partition_map_key_from_stdout(stdout: str, partition: str) -> Optional[str]:
    """
    標準出力からパーティションマップキーを抽出する

    Args:
        stdout: CLIコマンドの標準出力
        partition: パーティション識別子 ('a' または 'b')

    Returns:
        パーティションマップキー、見つからない場合はNone
    """
    # 複数行からなる標準出力を1行に結合 (パーティションマップキーは複数行にまたがる可能性があるため)
    stdout_oneline = stdout.replace('\n', ' ')

    # メインパターン: "{パーティション}領域用パーティションマップキー: " で始まる部分を検索
    pattern = rf"{partition.upper()}領域用パーティションマップキー: ([A-Za-z0-9+/=-]+(?:[-][A-Za-z0-9+/=]+)*(?:AAAAAA)?)"
    match = re.search(pattern, stdout_oneline)

    if match:
        # マップキー文字列の抽出
        key_raw = match.group(1).strip()

        # 出力を確認
        logger.info(f"{partition.upper()}領域用パーティションマップキーを抽出しました: {key_raw[:30]}...")
        return key_raw

    # 別の試行: 行ごとにチェック
    lines = stdout.split("\n")
    for i, line in enumerate(lines):
        if f"{partition.upper()}領域用パーティションマップキー:" in line:
            # キーが始まる位置
            start_pos = line.find(f"{partition.upper()}領域用パーティションマップキー:") + len(f"{partition.upper()}領域用パーティションマップキー:")
            # 現在の行から始まるキー部分
            key_part = line[start_pos:].strip()

            # 次の行がある場合は連結する可能性を検討
            full_key = key_part
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith(("パーティションマップキー", "B領域用")) and len(lines[j].strip()) > 0:
                full_key += " " + lines[j].strip()
                j += 1

            logger.info(f"{partition.upper()}領域用パーティションマップキーを行ベースで抽出しました: {full_key[:30]}...")
            return full_key

    # それでも見つからない場合
    logger.warning(f"{partition.upper()}領域用パーティションマップキーが見つかりませんでした")
    return None

def get_placeholder_value(placeholder: str, test_results: Dict[str, Any], analysis_results: Dict[str, Any], specific_test_result: Dict[str, Any] = None, all_test_results: List[Dict[str, Dict[str, Any]]] = None) -> str:
    """
    プレースホルダーに対応する値を取得する

    Args:
        placeholder: プレースホルダー名
        test_results: テスト結果のディクショナリ
        analysis_results: 分析結果のディクショナリ
        specific_test_result: 特定のテスト実行結果（テストセクション内のプレースホルダー用）
        all_test_results: 全テスト実行結果のリスト（各要素は {"iteration": 回数, "results": テスト結果辞書} の形式）

    Returns:
        プレースホルダーに対応する値（文字列）
    """
    # 現在時刻関連
    if placeholder == "execution_datetime":
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if placeholder == "timestamp":
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if placeholder == "report_generation_datetime":
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # テスト繰り返し回数
    if placeholder == "test_repeat_count":
        config = load_config()
        repeat_count = 1  # デフォルト値
        if config and 'reporting' in config and 'test_repeat_count' in config['reporting']:
            repeat_count = config['reporting']['test_repeat_count']
        return str(repeat_count)

    # パーティションマップの交差率テーブル用の値
    value_pattern = re.match(r'値_([AB]+)_(\d+)_(\d+)', placeholder)
    if value_pattern:
        map_type, row, col = value_pattern.groups()
        row = int(row)
        col = int(col)

        if "map_intersection" in analysis_results:
            map_analysis = analysis_results["map_intersection"]

            # A領域パーティションマップ
            if map_type == 'A' and "a_map_table" in map_analysis:
                table = map_analysis["a_map_table"]
                if row in table and col in table[row]:
                    if row == col:
                        return "-"  # 同一マップの場合はハイフン表示
                    else:
                        return f"{table[row][col]:.1f}"

            # B領域パーティションマップ
            elif map_type == 'B' and "b_map_table" in map_analysis:
                table = map_analysis["b_map_table"]
                if row in table and col in table[row]:
                    if row == col:
                        return "-"  # 同一マップの場合はハイフン表示
                    else:
                        return f"{table[row][col]:.1f}"

            # A-B間パーティションマップ
            elif map_type == 'AB' and "ab_map_table" in map_analysis:
                table = map_analysis["ab_map_table"]
                if row in table and col in table[row]:
                    return f"{table[row][col]:.1f}"

        return "N/A"

    # A-B間パーティションマップの交差率テーブル用の値
    # 「値_AB_1_2」形式で行列位置を特定
    ab_value_match = re.match(r'値_AB_(\d+)_(\d+)', placeholder)
    if ab_value_match:
        row, col = ab_value_match.groups()
        row = int(row)
        col = int(col)

        if "map_intersection" in analysis_results:
            map_analysis = analysis_results["map_intersection"]

            if "a_b_map_intersection" in map_analysis:
                # A-B間パーティションマップ一致率表
                rates = map_analysis["a_b_map_intersection"]
                if rates and (row, col) in rates:
                    return f"{rates[(row, col)]:.1f}"

            # 対応する値が見つからない場合、平均値を返す
            if "a_b_map_avg_rate" in map_analysis:
                return f"{map_analysis['a_b_map_avg_rate']:.1f}"

        return "N/A"

    # テスト数のカウント
    if placeholder == "テスト数":
        # all_test_results が提供されている場合は、実際のテスト実行回数を使用
        if all_test_results:
            return str(len(all_test_results))
        # 後方互換性のため、通常のテスト結果数も維持
        return str(len(test_results))

    # 統計情報
    if placeholder in ["成功数", "失敗数", "スキップ数", "実行時間", "コード網羅率"]:
        if placeholder == "成功数":
            if all_test_results:
                # 全テスト実行での成功数を集計
                success_count = 0
                for iteration_data in all_test_results:
                    results = iteration_data.get("results", {})
                    success_count += sum(1 for result in results.values() if result.get("success", False))
                return str(success_count)
            return str(sum(1 for result in test_results.values() if result.get("success", False)))

        elif placeholder == "失敗数":
            if all_test_results:
                # 全テスト実行での失敗数を集計
                failure_count = 0
                for iteration_data in all_test_results:
                    results = iteration_data.get("results", {})
                    failure_count += sum(1 for result in results.values() if not result.get("success", False))
                return str(failure_count)
            return str(sum(1 for result in test_results.values() if not result.get("success", False)))

        elif placeholder == "スキップ数":
            return "0"  # 現在のところスキップ機能は実装されていない

        elif placeholder == "実行時間":
            # テスト実行時間をまとめる
            total_time = 0.0

            if all_test_results:
                # 全テスト実行の時間を合計
                for iteration_data in all_test_results:
                    results = iteration_data.get("results", {})
                    for result in results.values():
                        if "execution_time" in result:
                            total_time += float(result["execution_time"])
            else:
                for result in test_results.values():
                    if "execution_time" in result:
                        total_time += float(result["execution_time"])

            return f"{total_time:.2f} 秒"

        elif placeholder == "コード網羅率":
            return "N/A"  # カバレッジ測定は未実装

    # パーティションマップの一致率表の値
    if placeholder == "値":
        # テーブルセルの位置を特定するための処理
        if "map_intersection" in analysis_results:
            map_analysis = analysis_results["map_intersection"]

            # テーブル内の位置を特定するための前後の文脈を取得
            # 近い行を探す
            context_lines = []
            for i in range(1, 11):  # 最大10行前後を探索
                context_pattern = rf"\| ([A-B][0-9]+|[A-B]\\[0-9]+) +\|"
                matches = re.findall(context_pattern, context_before(200) + context_after(200))
                if matches:
                    context_lines.extend(matches)

            if context_lines:
                # コンテキスト行からテーブルの行と列を特定
                position = None
                for context in context_lines:
                    # A1, B2, A\B などの形式を解析
                    if re.match(r"A\d+", context):
                        # A行のケース (Aマップ同士の比較)
                        row = int(context[1:])
                        if "a_map_intersection" in map_analysis:
                            # 列を取得 (テーブル内の位置から)
                            col_pattern = r"\| +- +\| +([\d\.]+) +\|"
                            for col in range(1, 11):
                                if (row, col) in map_analysis["a_map_intersection"]:
                                    position = (row, col)
                                    return f"{map_analysis['a_map_intersection'][position]:.1f}"

                    elif re.match(r"B\d+", context):
                        # B行のケース (Bマップ同士の比較)
                        row = int(context[1:])
                        if "b_map_intersection" in map_analysis:
                            for col in range(1, 11):
                                if (row, col) in map_analysis["b_map_intersection"]:
                                    position = (row, col)
                                    return f"{map_analysis['b_map_intersection'][position]:.1f}"

                    elif context.startswith("A\\"):
                        # A-B間比較のケース
                        row = int(context[2:])
                        if "a_b_map_intersection" in map_analysis:
                            for col in range(1, 11):
                                if (row, col) in map_analysis["a_b_map_intersection"]:
                                    position = (row, col)
                                    return f"{map_analysis['a_b_map_intersection'][position]:.1f}"

            # テーブルの種類を判断
            a_map_pattern = r"A 用パーティションマップキーの INDEX 一致率"
            b_map_pattern = r"B 用パーティションマップキーの INDEX 一致率"
            ab_map_pattern = r"A-B 間パーティションマップキーの INDEX 一致率"

            if re.search(a_map_pattern, context_before(500)):
                # A用パーティションマップ一致率表
                if "a_map_intersection" in map_analysis:
                    # すべての一致率データを返す
                    a_map_rates = map_analysis["a_map_intersection"]
                    if a_map_rates:
                        # 現在の行・列を見つけるためにテーブル行を解析
                        row_pattern = r"\| +(\d+) +\|"
                        row_match = re.search(row_pattern, context_before(100))
                        column_pattern = r"\| +- +\| +(?:[\d\.]+ +\| +){0,8}([\d\.]+)"
                        column_match = re.search(column_pattern, context_after(100))

                        if row_match and column_match:
                            row = int(row_match.group(1))
                            # 列位置の推定（難しいが、一般的にテーブルの位置から推測）
                            col = 1  # デフォルト値
                            for key in a_map_rates.keys():
                                if key[0] == row:
                                    # 対応するキーを返す
                                    return f"{a_map_rates[key]:.1f}"

                        # キーがないか見つからない場合はランダムに1つ返す
                        first_key = next(iter(a_map_rates))
                        return f"{a_map_rates[first_key]:.1f}"

            elif re.search(b_map_pattern, context_before(500)):
                # B用パーティションマップ一致率表
                if "b_map_intersection" in map_analysis:
                    b_map_rates = map_analysis["b_map_intersection"]
                    if b_map_rates:
                        # キーがないか見つからない場合はランダムに1つ返す
                        first_key = next(iter(b_map_rates))
                        return f"{b_map_rates[first_key]:.1f}"

            elif re.search(ab_map_pattern, context_before(500)):
                # A-B間パーティションマップ一致率表
                if "a_b_map_intersection" in map_analysis:
                    ab_map_rates = map_analysis["a_b_map_intersection"]
                    if ab_map_rates:
                        # キーがないか見つからない場合はランダムに1つ返す
                        first_key = next(iter(ab_map_rates))
                        return f"{ab_map_rates[first_key]:.1f}"

            # テーブルが特定できない場合はデフォルト値を使用
            # 各分析タイプごとの平均値を表示
            if "a_map_avg_rate" in map_analysis:
                return f"{map_analysis['a_map_avg_rate']:.1f}"
            elif "b_map_avg_rate" in map_analysis:
                return f"{map_analysis['b_map_avg_rate']:.1f}"
            elif "a_b_map_avg_rate" in map_analysis:
                return f"{map_analysis['a_b_map_avg_rate']:.1f}"

        return "N/A"

    # 平均一致率
    if placeholder == "平均%":
        # パーティションマップの分析結果があるか確認
        if "map_intersection" in analysis_results:
            map_analysis = analysis_results["map_intersection"]

            # シンプルに平均値を返す
            if "a_map_avg_rate" in map_analysis:
                return f"{map_analysis['a_map_avg_rate']:.1f}"

        # デフォルト値
        return "N/A"

    # グローバルな平均値
    if placeholder == "a_map_avg_rate":
        # パーティションマップの分析結果があるか確認
        if "map_intersection" in analysis_results:
            map_analysis = analysis_results["map_intersection"]
            if "a_map_avg_rate" in map_analysis:
                return f"{map_analysis['a_map_avg_rate']:.1f}"
        return "N/A"

    if placeholder == "b_map_avg_rate":
        # パーティションマップの分析結果があるか確認
        if "map_intersection" in analysis_results:
            map_analysis = analysis_results["map_intersection"]
            if "b_map_avg_rate" in map_analysis:
                return f"{map_analysis['b_map_avg_rate']:.1f}"
        return "N/A"

    if placeholder == "a_b_map_avg_rate":
        # パーティションマップの分析結果があるか確認
        if "map_intersection" in analysis_results:
            map_analysis = analysis_results["map_intersection"]
            if "a_b_map_avg_rate" in map_analysis:
                return f"{map_analysis['a_b_map_avg_rate']:.1f}"
        return "N/A"

    # システムパラメータ
    if placeholder == "パーティションサイズ値":
        if CONSTANTS_AVAILABLE:
            return str(ShamirConstants.PARTITION_SIZE)
        return "【値が取得できません】"

    if placeholder == "アクティブシェア数":
        if CONSTANTS_AVAILABLE:
            return str(ShamirConstants.ACTIVE_SHARES)
        return "【値が取得できません】"

    if placeholder == "ガベージシェア数":
        if CONSTANTS_AVAILABLE:
            return str(ShamirConstants.GARBAGE_SHARES)
        return "【値が取得できません】"

    if placeholder == "未割当シェア数":
        if CONSTANTS_AVAILABLE:
            return str(ShamirConstants.UNASSIGNED_SHARES)
        return "【値が取得できません】"

    if placeholder == "チャンクサイズ (バイト)":
        if CONSTANTS_AVAILABLE:
            return str(ShamirConstants.CHUNK_SIZE)
        return "【値が取得できません】"

    if placeholder == "BACKUP_RETENTION_DAYS":
        if CONSTANTS_AVAILABLE:
            return str(ShamirConstants.BACKUP_RETENTION_DAYS)
        return "【値が取得できません】"

    # 暗号化ファイル名
    if placeholder == "ファイル名（拡張子含む）":
        # 特定のテスト結果が指定されている場合はそれを使用
        result_to_use = specific_test_result if specific_test_result else next(iter(test_results.values()), {})

        # テスト結果から直接抽出されたファイル名を最優先で使用
        if result_to_use and 'storage_filename' in result_to_use:
            filename = result_to_use['storage_filename']
            logger.info(f"テスト結果から直接暗号化ファイル名を取得しました: {filename}")
            return filename

        if result_to_use and result_to_use.get("success", False) and "stdout" in result_to_use:
            stdout = result_to_use["stdout"]

            # 「暗号書庫を生成しました: {ファイル名}」のパターンから直接抽出
            pattern = r'暗号書庫を生成しました: (.+?)(?:\n|$)'
            match = re.search(pattern, stdout)
            if match:
                filename = match.group(1).strip()
                logger.info(f"標準出力から暗号化ファイル名を抽出しました: {filename}")
                return filename

            # CLIコマンドから出力ディレクトリパスを抽出
            cmd_pattern = r'実行するコマンド:.+-o\s+([^\s]+)'
            match = re.search(cmd_pattern, stdout, re.DOTALL)
            if match:
                output_path = match.group(1)
                # ここでは、実際のJSONファイルを探す
                storage_dir = os.path.join(test_dir, output_path)
                if os.path.exists(storage_dir) and os.path.isdir(storage_dir):
                    # ディレクトリ内のJSONファイルを探す
                    json_files = [f for f in os.listdir(storage_dir) if f.endswith('.json')]
                    if json_files:
                        # 最初のJSONファイルを返す（通常は1つしかない）
                        logger.info(f"実際の暗号化ファイル名を抽出しました: {json_files[0]}")
                        return json_files[0]
                else:
                    # ディレクトリでない場合はそのままファイル名を返す
                    filename = os.path.basename(output_path)
                    logger.info(f"暗号化ファイル名を抽出しました: {filename}")
                    return filename

            # 別の方法: 実行コマンド行を探す
            cmd_lines = re.findall(r'実行するコマンド: (.+)$', stdout, re.MULTILINE)
            for cmd_line in cmd_lines:
                output_pattern = r'-o\s+([^\s]+)'
                match = re.search(output_pattern, cmd_line)
                if match:
                    output_path = match.group(1)
                    storage_dir = os.path.join(test_dir, output_path)
                    if os.path.exists(storage_dir) and os.path.isdir(storage_dir):
                        # ディレクトリ内のJSONファイルを探す
                        json_files = [f for f in os.listdir(storage_dir) if f.endswith('.json')]
                        if json_files:
                            logger.info(f"実際の暗号化ファイル名を抽出しました: {json_files[0]}")
                            return json_files[0]

                    # ディレクトリでない場合はそのままファイル名を返す
                    filename = os.path.basename(output_path)
                    logger.info(f"暗号化ファイル名を抽出しました: {filename}")
                    return filename

        # 出力ディレクトリを確認
        output_dir = os.path.join(test_dir, "output")
        if os.path.exists(output_dir):
            # 最新のディレクトリを検索
            test_dirs = [d for d in os.listdir(output_dir) if d.startswith("test_storage_")]
            if test_dirs:
                # タイムスタンプで並べ替えて最新のものを取得
                test_dirs.sort(reverse=True)
                latest_dir = os.path.join(output_dir, test_dirs[0])
                if os.path.isdir(latest_dir):
                    # ディレクトリ内のJSONファイルを探す
                    json_files = [f for f in os.listdir(latest_dir) if f.endswith('.json')]
                    if json_files:
                        logger.info(f"最新ディレクトリから実際の暗号化ファイル名を抽出しました: {json_files[0]}")
                        return json_files[0]
                return test_dirs[0]

        return "暗号化ファイル名を取得できませんでした"  # デフォルト値

    # テスト結果関連
    if placeholder.startswith("test_") or placeholder == "success" or placeholder == "failure":
        # テスト結果から値を取得するロジックを実装
        return "未実装"

    # 分析結果関連
    for analysis_id, analysis_result in analysis_results.items():
        if placeholder == f"{analysis_id}_analysis":
            return str(analysis_result)

    # パーティションマップキー関連
    if placeholder.endswith("用パーティションマップキー"):
        partition = placeholder[0].lower()  # 'A'用 または 'B'用の先頭文字を取得し小文字に変換

        # 特定のテスト結果が指定されている場合はそれを使用
        if specific_test_result and specific_test_result.get("success", False):
            # テスト結果から直接マップキーを取得（テスト実行時に保存されたもの）
            key = specific_test_result.get(f"partition_map_key_{partition}")
            if key:
                logger.info(f"{partition.upper()}用パーティションマップキーをテスト結果から取得しました（長さ: {len(key)}）")
                return key

            # 標準出力から抽出
            if "stdout" in specific_test_result:
                stdout = specific_test_result["stdout"]
                map_key = get_partition_map_key_from_stdout(stdout, partition)
                if map_key:
                    return map_key

            # 見つからない場合は未取得として返す
            return "（パーティションマップキーが取得できませんでした）"

        # 特定のテスト結果がない場合は全テスト結果を検索
        for test_id, result in test_results.items():
            if result.get("success", False):
                # テスト結果から直接マップキーを取得
                key = result.get(f"partition_map_key_{partition}")
                if key:
                    logger.info(f"{partition.upper()}用パーティションマップキーをテスト結果から取得しました（長さ: {len(key)}）")
                    return key

                # 標準出力から抽出を試みる
                if "stdout" in result:
                    stdout = result["stdout"]
                    map_key = get_partition_map_key_from_stdout(stdout, partition)
                    if map_key:
                        return map_key

        return "（パーティションマップキーが取得できませんでした）"

    # パスワード関連
    if placeholder.endswith("用パスワード"):
        partition = placeholder[0].lower()  # 'A'用 または 'B'用の先頭文字を取得し小文字に変換

        # 特定のテスト結果が指定されている場合はそれを使用
        if specific_test_result:
            # テスト結果から直接パスワードを取得
            direct_password_key = f"password_{partition}"
            if direct_password_key in specific_test_result:
                password = specific_test_result[direct_password_key]
                if password:
                    logger.info(f"テストの{partition.upper()}用パスワードを取得しました: {password}")
                    return password

            # パスワードが見つからない場合
            logger.warning(f"{partition.upper()}用パスワードが特定テスト結果に保存されていません - テスト異常")
            return f"（{partition.upper()}用パスワードが取得できません - テスト失敗）"

        # 特定のテスト結果がない場合、最初の成功したテストからパスワードを取得
        for test_id, result in test_results.items():
            if result.get("success", False):
                direct_password_key = f"password_{partition}"
                if direct_password_key in result:
                    password = result[direct_password_key]
                    if password:
                        logger.info(f"テスト全体の{partition.upper()}用パスワードを取得しました: {password}")
                        return password

        # パスワードが見つからない場合
        logger.warning(f"{partition.upper()}用パスワードがテスト結果全体で見つかりません - テスト異常")
        return f"（{partition.upper()}用パスワードが取得できません - テスト失敗）"

    # テーブル用の値
    if placeholder == "✅/❌":
        return "❌"  # デフォルトは失敗とする

    # 未知のプレースホルダー
    logger.warning(f"未知のプレースホルダー: {placeholder}")
    return f"{{{placeholder}}}"  # そのまま返す

def extract_password_from_test_result(test_result: Dict[str, Any], partition: str) -> str:
    """
    テスト結果からパスワードを抽出する

    Args:
        test_result: テスト結果
        partition: パーティション識別子 ('a' または 'b')

    Returns:
        パスワード文字列、取得できない場合はエラーメッセージ
    """
    # テスト結果から直接パスワードを取得（明示的に保存されている場合）
    direct_password_key = f"password_{partition.lower()}"
    if direct_password_key in test_result and test_result[direct_password_key]:
        password = test_result[direct_password_key]
        logger.info(f"{partition.upper()}領域用パスワードをテスト結果から直接取得しました: {password}")
        return password

    # パスワードが見つからない場合は異常として扱う
    logger.warning(f"{partition.upper()}領域用パスワードが保存されていません - テスト異常")
    return f"（{partition.upper()}用パスワードが取得できません - テスト失敗）"

def generate_report(test_results: Dict[str, Dict[str, Any]], analysis_results: Dict[str, Dict[str, Any]], all_test_results: List[Dict[str, Dict[str, Any]]] = None) -> Optional[str]:
    """
    テスト結果と分析結果からレポートを生成する

    Args:
        test_results: テスト結果のディクショナリ（テストID -> テスト結果）
        analysis_results: 分析結果のディクショナリ（分析ID -> 分析結果）
        all_test_results: 全テスト実行結果のリスト（各要素は {"iteration": 回数, "results": テスト結果辞書} の形式）

    Returns:
        生成されたレポート文字列、失敗した場合はNone
    """
    try:
        logger.info("テストレポートの生成を開始します")

        # テンプレートファイルのパスを設定
        template_path = os.path.join(test_dir, "test_report_template.md")
        logger.info(f"テンプレートパス: {template_path}")

        # テンプレートファイルが存在するか確認
        if not os.path.exists(template_path):
            logger.error(f"テンプレートファイルが見つかりません: {template_path}")
            return None

        # テンプレートファイルを読み込む
        with open(template_path, 'r', encoding='utf-8') as f:
            template = f.read()

        # テスト繰り返し回数を取得
        repeat_count = 1  # デフォルト値
        if all_test_results:
            repeat_count = len(all_test_results)

        logger.info(f"テスト繰り返し回数: {repeat_count}")

        # グローバルなプレースホルダー（全体で使うもの）を置換
        # パーティションサイズ値、アクティブシェア数など
        global_pattern = r'\{([^{}]+)\}'
        global_placeholders = re.findall(global_pattern, template)

        for placeholder in global_placeholders:
            # 特定のセクションに属するものは除外
            if placeholder.startswith("A 用") or placeholder.startswith("B 用") or \
               placeholder == "ファイル名（拡張子含む）" or placeholder.endswith("用パスワード"):
                continue

            # プレースホルダーに対応する値を取得
            value = get_placeholder_value(placeholder, test_results, analysis_results, all_test_results=all_test_results)
            # プレースホルダーを値で置換
            template = template.replace(f'{{{placeholder}}}', value)

        # テストセクションの基本テンプレートを抽出
        # 最初のテストセクションをテンプレートとして使用
        test_section_template_match = re.search(r'(### テスト #1\s*\n.*?)(?=## パーティションマップキー評価|\Z)', template, re.DOTALL)
        if not test_section_template_match:
            logger.error("テストセクションテンプレートを抽出できませんでした")
            return None

        test_section_template = test_section_template_match.group(1)

        # テスト暗号書庫情報セクション全体を取得
        test_info_section_match = re.search(r'(## テスト暗号書庫情報\s*\n)(.*?)(?=## パーティションマップキー評価)', template, re.DOTALL)
        if not test_info_section_match:
            logger.error("テスト暗号書庫情報セクションを抽出できませんでした")
            return None

        section_header = test_info_section_match.group(1)

        # 再構築されたテストセクション
        reconstructed_sections = [section_header]

        # 各テスト実行に対応するセクションを生成
        for i in range(1, repeat_count + 1):
            # テスト実行結果を取得
            if all_test_results and i <= len(all_test_results):
                # 新しい構造: {"iteration": 回数, "results": テスト結果辞書}
                current_iteration_data = all_test_results[i - 1]
                current_test_result = current_iteration_data.get("results", {})

                # 最初のテスト結果を取得（通常は1つのみ）
                if current_test_result:
                    first_test_id = next(iter(current_test_result))
                    first_test_data = current_test_result[first_test_id]

                    # セクション内のプレースホルダーを置換
                    section_content = test_section_template

                    # セクション番号を更新
                    section_content = section_content.replace("### テスト #1", f"### テスト #{i}")

                    # テスト統計セクションを削除（重複を避けるため）
                    section_content = re.sub(r'### テスト統計\s*\n.*?(?=##|\Z)', '', section_content, flags=re.DOTALL)

                    # セクション内のプレースホルダーを特定し、現在のテスト結果で置換
                    section_placeholders = re.findall(global_pattern, section_content)
                    for ph in section_placeholders:
                        ph_value = get_placeholder_value(ph, current_test_result, analysis_results, first_test_data, all_test_results)
                        section_content = section_content.replace(f'{{{ph}}}', ph_value)

                    reconstructed_sections.append(section_content)
                else:
                    # テスト結果がない場合も、空のセクションを追加
                    empty_section = test_section_template.replace("### テスト #1", f"### テスト #{i}")
                    # テスト統計セクションを削除
                    empty_section = re.sub(r'### テスト統計\s*\n.*?(?=##|\Z)', '', empty_section, flags=re.DOTALL)
                    reconstructed_sections.append(empty_section)
            else:
                # テスト結果がない場合も、空のセクションを追加
                empty_section = test_section_template.replace("### テスト #1", f"### テスト #{i}")
                # テスト統計セクションを削除
                empty_section = re.sub(r'### テスト統計\s*\n.*?(?=##|\Z)', '', empty_section, flags=re.DOTALL)
                reconstructed_sections.append(empty_section)

        # テンプレートからオリジナルのテストセクションを削除
        cleaned_template = re.sub(
            r'## テスト暗号書庫情報\s*\n(.*?)(?=## パーティションマップキー評価|\Z)',
            '',
            template,
            flags=re.DOTALL
        )

        # 生成したテストセクションを挿入する位置を見つける
        partition_map_section_pos = cleaned_template.find('## パーティションマップキー評価')
        if partition_map_section_pos == -1:
            partition_map_section_pos = len(cleaned_template)

        # 動的に生成したテストセクションを挿入
        final_template = cleaned_template[:partition_map_section_pos] + ''.join(reconstructed_sections) + cleaned_template[partition_map_section_pos:]

        # レポートディレクトリを作成（存在しない場合）
        report_dir = os.path.join(test_dir, "test_report")
        os.makedirs(report_dir, exist_ok=True)

        logger.info("テストレポートの生成が完了しました")
        return final_template

    except Exception as e:
        logger.error(f"テストレポートの生成中にエラーが発生しました: {str(e)}")
        logger.exception(e)
        return None

def save_report(report: str, filename: str) -> bool:
    """
    生成されたレポートをファイルに保存する

    Args:
        report: レポート文字列
        filename: 保存するファイル名

    Returns:
        保存に成功した場合はTrue、失敗した場合はFalse
    """
    if not report:
        logger.error("レポートが空のため保存できません")
        return False

    # レポート保存ディレクトリ取得
    report_dir = get_report_dir()
    report_path = os.path.join(report_dir, filename)

    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)

        logger.info(f"レポートを保存しました: {report_path}")
        return True

    except Exception as e:
        logger.error(f"レポートの保存中にエラーが発生しました: {str(e)}")
        return False

def create_test_result_table(test_results: Dict[str, Any], test_type: str) -> str:
    """
    テスト結果の表を生成する

    Args:
        test_results: テスト結果のディクショナリ
        test_type: テストタイプ（"functional" または "security"）

    Returns:
        生成された表のマークダウン文字列
    """
    # テスト結果の表を生成するロジックを実装
    # （現時点では未実装だが、実際のテスト結果を整形して表示するロジックを追加予定）
    return "テスト結果表は実際のテスト実行時に生成されます。"

def get_check_mark(success: bool) -> str:
    """
    成功/失敗のチェックマークを取得する

    Args:
        success: 成功フラグ

    Returns:
        成功の場合は✅、失敗の場合は❌
    """
    return "✅" if success else "❌"