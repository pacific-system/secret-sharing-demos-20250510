#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式のデバッグユーティリティ

このモジュールは、準同型暗号マスキング方式のデバッグに必要な様々なユーティリティを提供します。
暗号化・復号プロセスのログ出力、可視化、エラートレース、状態チェックなどの機能を含みます。
"""

import os
import sys
import time
import json
import logging
import traceback
import binascii
import hashlib
import inspect
import random
import base64
from typing import Dict, Any, List, Tuple, Union, Optional, Callable
import matplotlib.pyplot as plt
import numpy as np

# ロガーの設定
logger = logging.getLogger("homomorphic_debug")
logger.setLevel(logging.DEBUG)

# 出力ディレクトリの作成
os.makedirs("test_output", exist_ok=True)

# ファイルハンドラーの追加
log_file = os.path.join("test_output", f"debug_{int(time.time())}.log")
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# コンソールハンドラーの追加
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# フォーマッターの設定
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# ハンドラーをロガーに追加
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class DebugInfo:
    """デバッグ情報を収集・保持するクラス"""

    def __init__(self, enabled: bool = True):
        """
        デバッグ情報クラスの初期化

        Args:
            enabled: デバッグモードが有効かどうか
        """
        self.enabled = enabled
        self.start_time = time.time()
        self.events = []
        self.measurements = {}
        self.errors = []
        self.states = {}

    def log_event(self, event_name: str, details: Dict[str, Any] = None) -> None:
        """
        イベントをログに記録

        Args:
            event_name: イベント名
            details: イベントの詳細情報
        """
        if not self.enabled:
            return

        timestamp = time.time()
        elapsed = timestamp - self.start_time

        event = {
            "timestamp": timestamp,
            "elapsed": elapsed,
            "event": event_name,
            "details": details or {}
        }

        self.events.append(event)
        logger.info(f"Event: {event_name} - Elapsed: {elapsed:.4f}s")

        if details:
            logger.debug(f"Details: {json.dumps(details, indent=2, default=str)}")

    def measure_time(self, operation_name: str) -> Callable:
        """
        処理時間計測用のデコレータ

        Args:
            operation_name: 計測する処理の名前

        Returns:
            デコレータ関数
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)

                start_time = time.time()
                logger.debug(f"Starting {operation_name}...")

                try:
                    result = func(*args, **kwargs)

                    end_time = time.time()
                    elapsed = end_time - start_time

                    if operation_name not in self.measurements:
                        self.measurements[operation_name] = []

                    self.measurements[operation_name].append(elapsed)
                    logger.debug(f"Completed {operation_name} in {elapsed:.4f}s")

                    return result

                except Exception as e:
                    end_time = time.time()
                    elapsed = end_time - start_time

                    error_info = {
                        "operation": operation_name,
                        "elapsed": elapsed,
                        "exception": str(e),
                        "traceback": traceback.format_exc()
                    }

                    self.errors.append(error_info)
                    logger.error(f"Error in {operation_name}: {str(e)}")
                    logger.debug(traceback.format_exc())

                    raise

            return wrapper

        return decorator

    def save_state(self, state_name: str, state_data: Any) -> None:
        """
        状態を保存

        Args:
            state_name: 状態の名前
            state_data: 状態データ
        """
        if not self.enabled:
            return

        self.states[state_name] = state_data
        logger.debug(f"Saved state: {state_name}")

    def dump_to_file(self, output_file: Optional[str] = None) -> str:
        """
        デバッグ情報をファイルに出力

        Args:
            output_file: 出力ファイルパス（指定がなければタイムスタンプ付きの名前を生成）

        Returns:
            出力されたファイルパス
        """
        if not output_file:
            timestamp = int(time.time())
            output_file = os.path.join("test_output", f"debug_info_{timestamp}.json")

        # JSONシリアライズ可能な形式に変換
        debug_data = {
            "start_time": self.start_time,
            "end_time": time.time(),
            "total_elapsed": time.time() - self.start_time,
            "events": self.events,
            "measurements": {k: [float(v) for v in vals] for k, vals in self.measurements.items()},
            "errors": self.errors,
            "states": {k: str(v) if not isinstance(v, (dict, list, str, int, float, bool, type(None))) else v
                      for k, v in self.states.items()}
        }

        with open(output_file, 'w') as f:
            json.dump(debug_data, f, indent=2, default=str)

        logger.info(f"Debug information saved to {output_file}")
        return output_file

    def visualize(self, output_file: Optional[str] = None) -> str:
        """
        デバッグ情報を可視化

        Args:
            output_file: 出力画像ファイルパス（指定がなければタイムスタンプ付きの名前を生成）

        Returns:
            出力された画像ファイルパス
        """
        if not output_file:
            timestamp = int(time.time())
            output_file = os.path.join("test_output", f"debug_visualization_{timestamp}.png")

        plt.figure(figsize=(15, 12))

        # イベントタイムライン
        plt.subplot(3, 1, 1)
        if self.events:
            events = [(e["elapsed"], e["event"]) for e in self.events]
            times, names = zip(*events)

            # イベントを時間順にプロット
            plt.scatter(times, range(len(times)), marker='o')

            # イベント名を表示
            for i, (t, name) in enumerate(zip(times, names)):
                plt.text(t, i, f" {name}", verticalalignment='center')

            plt.yticks([])
            plt.xlabel('Time (seconds)')
            plt.title('Event Timeline')
            plt.grid(True, axis='x')
        else:
            plt.text(0.5, 0.5, "No events recorded",
                     horizontalalignment='center',
                     verticalalignment='center',
                     transform=plt.gca().transAxes)
            plt.title('Event Timeline')

        # 処理時間の測定
        plt.subplot(3, 1, 2)
        if self.measurements:
            # 処理ごとの平均時間
            operations = list(self.measurements.keys())
            avg_times = [sum(times) / len(times) for times in self.measurements.values()]

            # 横棒グラフでプロット
            y_pos = range(len(operations))
            plt.barh(y_pos, avg_times)
            plt.yticks(y_pos, operations)
            plt.xlabel('Average Time (seconds)')
            plt.title('Operation Times')
            plt.grid(True, axis='x')

            # 最大値・最小値を表示
            for i, op in enumerate(operations):
                times = self.measurements[op]
                min_time = min(times)
                max_time = max(times)
                plt.text(avg_times[i], i, f"  Avg: {avg_times[i]:.4f}s (Min: {min_time:.4f}s, Max: {max_time:.4f}s)",
                         verticalalignment='center')
        else:
            plt.text(0.5, 0.5, "No measurements recorded",
                     horizontalalignment='center',
                     verticalalignment='center',
                     transform=plt.gca().transAxes)
            plt.title('Operation Times')

        # エラー情報
        plt.subplot(3, 1, 3)
        if self.errors:
            error_ops = [e["operation"] for e in self.errors]
            error_times = [e["elapsed"] for e in self.errors]

            plt.bar(range(len(error_ops)), error_times)
            plt.xticks(range(len(error_ops)), error_ops, rotation=45)
            plt.ylabel('Time until Error (seconds)')
            plt.title(f'Errors ({len(self.errors)})')
            plt.grid(True, axis='y')

            # エラーメッセージを表示
            for i, err in enumerate(self.errors):
                plt.text(i, err["elapsed"] / 2, f"{err['exception'][:30]}...",
                         horizontalalignment='center',
                         verticalalignment='center',
                         rotation=90)
        else:
            plt.text(0.5, 0.5, "No errors recorded",
                     horizontalalignment='center',
                     verticalalignment='center',
                     transform=plt.gca().transAxes)
            plt.title('Errors')

        plt.tight_layout()
        plt.savefig(output_file)
        logger.info(f"Debug visualization saved to {output_file}")

        return output_file


class CryptoDebugger:
    """準同型暗号のデバッグを支援するクラス"""

    def __init__(self, debug_level: str = "INFO"):
        """
        準同型暗号デバッガーの初期化

        Args:
            debug_level: デバッグレベル ("DEBUG", "INFO", "WARNING", "ERROR")
        """
        # デバッグレベルの設定
        numeric_level = getattr(logging, debug_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {debug_level}")

        logger.setLevel(numeric_level)

        # デバッグ情報クラスの初期化
        self.debug_info = DebugInfo(enabled=True)
        self.start_time = time.time()

    def inspect_encrypted_data(self, encrypted_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        暗号化データの内部構造を検査

        Args:
            encrypted_data: 暗号化データ

        Returns:
            検査結果
        """
        result = {
            "format": encrypted_data.get("format", "unknown"),
            "version": encrypted_data.get("version", "unknown"),
            "metadata": {},
            "structure": {},
            "stats": {}
        }

        # メタデータの抽出
        if "metadata" in encrypted_data:
            result["metadata"] = encrypted_data["metadata"]

        # データ構造の分析
        if "true_chunks" in encrypted_data and "false_chunks" in encrypted_data:
            result["structure"]["true_chunks_count"] = len(encrypted_data["true_chunks"])
            result["structure"]["false_chunks_count"] = len(encrypted_data["false_chunks"])

            # チャンクのサンプル（最大5つまで）
            if encrypted_data["true_chunks"]:
                result["structure"]["true_chunks_sample"] = encrypted_data["true_chunks"][:5]

            if encrypted_data["false_chunks"]:
                result["structure"]["false_chunks_sample"] = encrypted_data["false_chunks"][:5]

        # 統計情報の収集
        if "true_chunks" in encrypted_data and encrypted_data["true_chunks"]:
            true_chunk_lens = [len(str(c)) for c in encrypted_data["true_chunks"]]
            result["stats"]["true_chunks_min_len"] = min(true_chunk_lens)
            result["stats"]["true_chunks_max_len"] = max(true_chunk_lens)
            result["stats"]["true_chunks_avg_len"] = sum(true_chunk_lens) / len(true_chunk_lens)

        if "false_chunks" in encrypted_data and encrypted_data["false_chunks"]:
            false_chunk_lens = [len(str(c)) for c in encrypted_data["false_chunks"]]
            result["stats"]["false_chunks_min_len"] = min(false_chunk_lens)
            result["stats"]["false_chunks_max_len"] = max(false_chunk_lens)
            result["stats"]["false_chunks_avg_len"] = sum(false_chunk_lens) / len(false_chunk_lens)

        # 暗号化方式の確認
        crypto_type = None
        if "metadata" in encrypted_data and "crypto_type" in encrypted_data["metadata"]:
            crypto_type = encrypted_data["metadata"]["crypto_type"]
        elif "crypto_type" in encrypted_data:
            crypto_type = encrypted_data["crypto_type"]

        result["crypto_type"] = crypto_type

        # デバッグ情報に保存
        self.debug_info.save_state("inspected_data", result)
        self.debug_info.log_event("inspect_encrypted_data", {"result": result})

        return result

    def analyze_key(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        鍵データを分析

        Args:
            key_data: 鍵データ

        Returns:
            分析結果
        """
        result = {
            "format": key_data.get("format", "unknown"),
            "key_type": key_data.get("key_type", "unknown"),
            "metadata": {},
            "structure": {},
            "checksum": None
        }

        # メタデータの抽出
        if "metadata" in key_data:
            result["metadata"] = key_data["metadata"]

        # キータイプの確認
        key_type = None
        if "key_type" in key_data:
            key_type = key_data["key_type"]

        result["key_type"] = key_type

        # 鍵構造の分析
        if "key_data" in key_data:
            if isinstance(key_data["key_data"], dict):
                result["structure"]["fields"] = list(key_data["key_data"].keys())
            elif isinstance(key_data["key_data"], str):
                # Base64エンコードされた鍵の場合
                try:
                    key_bytes = base64.b64decode(key_data["key_data"])
                    result["structure"]["decoded_length"] = len(key_bytes)
                    result["checksum"] = hashlib.sha256(key_bytes).hexdigest()[:16]
                except:
                    result["structure"]["encoded_length"] = len(key_data["key_data"])
            else:
                result["structure"]["key_data_type"] = str(type(key_data["key_data"]))

        # デバッグ情報に保存
        self.debug_info.save_state("analyzed_key", result)
        self.debug_info.log_event("analyze_key", {"result": result})

        return result

    def trace_operation(self, operation_name: str) -> Callable:
        """
        操作をトレースするデコレータ

        Args:
            operation_name: 操作の名前

        Returns:
            デコレータ関数
        """
        return self.debug_info.measure_time(operation_name)

    def checkpoint(self, checkpoint_name: str, data: Any = None) -> None:
        """
        チェックポイントを記録

        Args:
            checkpoint_name: チェックポイント名
            data: 関連データ（オプショナル）
        """
        self.debug_info.log_event("checkpoint", {
            "name": checkpoint_name,
            "data": str(data) if data is not None else None
        })

    def save_debug_state(self, output_prefix: str = "crypto_debug") -> Tuple[str, str]:
        """
        デバッグ状態を保存して可視化

        Args:
            output_prefix: 出力ファイル名のプレフィックス

        Returns:
            (JSONファイルパス, 画像ファイルパス)のタプル
        """
        timestamp = int(time.time())

        # JSONファイルへ保存
        json_file = os.path.join("test_output", f"{output_prefix}_{timestamp}.json")
        self.debug_info.dump_to_file(json_file)

        # 可視化
        image_file = os.path.join("test_output", f"{output_prefix}_{timestamp}.png")
        self.debug_info.visualize(image_file)

        return json_file, image_file

    def log_error(self, error_message: str, exception: Optional[Exception] = None) -> None:
        """
        エラーをログに記録

        Args:
            error_message: エラーメッセージ
            exception: 例外オブジェクト（オプショナル）
        """
        error_info = {
            "message": error_message,
            "exception": str(exception) if exception else None,
            "traceback": traceback.format_exc() if exception else None
        }

        self.debug_info.errors.append(error_info)
        logger.error(error_message)

        if exception:
            logger.error(f"Exception: {str(exception)}")
            logger.debug(traceback.format_exc())


def inspect_call_stack() -> List[Dict[str, Any]]:
    """
    呼び出しスタックを検査

    Returns:
        スタックフレーム情報のリスト
    """
    stack = inspect.stack()[1:]  # 自分自身の呼び出しを除外
    result = []

    for frame_info in stack:
        frame = frame_info.frame
        code = frame.f_code

        frame_data = {
            "function": code.co_name,
            "filename": code.co_filename,
            "lineno": frame_info.lineno,
            "local_vars": {
                k: str(v) if not isinstance(v, (int, float, bool, str, type(None))) else v
                for k, v in frame.f_locals.items()
                if not k.startswith('__')
            }
        }

        result.append(frame_data)

    return result


def dump_object(obj: Any, max_depth: int = 2) -> Dict[str, Any]:
    """
    オブジェクトの状態をダンプ

    Args:
        obj: ダンプするオブジェクト
        max_depth: 再帰の最大深度

    Returns:
        オブジェクト状態を表す辞書
    """
    if max_depth <= 0:
        return str(obj)

    if isinstance(obj, (int, float, bool, str, type(None))):
        return obj

    if isinstance(obj, (list, tuple)):
        if len(obj) > 10:
            # 長いリストの場合は先頭と末尾の要素のみダンプ
            return {
                "type": type(obj).__name__,
                "length": len(obj),
                "sample": [dump_object(item, max_depth - 1) for item in list(obj)[:5]] +
                         ["..."] +
                         [dump_object(item, max_depth - 1) for item in list(obj)[-5:]]
            }
        else:
            return [dump_object(item, max_depth - 1) for item in obj]

    if isinstance(obj, dict):
        if len(obj) > 10:
            # 長い辞書の場合はキーのリストと一部の値のみダンプ
            keys = list(obj.keys())
            return {
                "type": "dict",
                "length": len(obj),
                "keys": keys,
                "sample": {k: dump_object(obj[k], max_depth - 1) for k in keys[:10]}
            }
        else:
            return {k: dump_object(v, max_depth - 1) for k, v in obj.items()}

    # その他のオブジェクト
    try:
        # 辞書形式で保存可能な属性を取得
        attrs = {}
        for attr in dir(obj):
            if not attr.startswith('__') and not callable(getattr(obj, attr)):
                try:
                    attrs[attr] = dump_object(getattr(obj, attr), max_depth - 1)
                except:
                    attrs[attr] = "ERROR: Failed to dump attribute"

        return {
            "type": type(obj).__name__,
            "attributes": attrs
        }
    except:
        return str(obj)


def compare_files(file1_path: str, file2_path: str) -> Dict[str, Any]:
    """
    2つのファイルを比較

    Args:
        file1_path: 1つ目のファイルパス
        file2_path: 2つ目のファイルパス

    Returns:
        比較結果
    """
    if not os.path.exists(file1_path):
        return {"error": f"File not found: {file1_path}"}

    if not os.path.exists(file2_path):
        return {"error": f"File not found: {file2_path}"}

    result = {
        "file1": {"path": file1_path, "size": os.path.getsize(file1_path)},
        "file2": {"path": file2_path, "size": os.path.getsize(file2_path)},
        "size_diff": os.path.getsize(file1_path) - os.path.getsize(file2_path),
        "content_identical": False,
        "content_diff_locations": []
    }

    # ファイルの内容を読み込み
    with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
        content1 = f1.read()
        content2 = f2.read()

    # ハッシュ値の計算
    result["file1"]["hash"] = hashlib.sha256(content1).hexdigest()
    result["file2"]["hash"] = hashlib.sha256(content2).hexdigest()

    # 内容が同じかチェック
    result["content_identical"] = content1 == content2

    # テキストファイルかどうかチェック
    try:
        text1 = content1.decode('utf-8')
        text2 = content2.decode('utf-8')

        result["file1"]["is_text"] = True
        result["file2"]["is_text"] = True

        # テキストファイルの場合、行ごとの違いを確認
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()

        result["file1"]["line_count"] = len(lines1)
        result["file2"]["line_count"] = len(lines2)
        result["line_count_diff"] = len(lines1) - len(lines2)

        # 最初の10個の相違点を記録
        diff_count = 0
        max_diffs = 10

        for i, (line1, line2) in enumerate(zip(lines1, lines2)):
            if line1 != line2:
                result["content_diff_locations"].append({
                    "line": i + 1,
                    "file1_content": line1[:50] + ("..." if len(line1) > 50 else ""),
                    "file2_content": line2[:50] + ("..." if len(line2) > 50 else "")
                })

                diff_count += 1
                if diff_count >= max_diffs:
                    break

        # 行数の違いも相違点として記録
        if len(lines1) != len(lines2):
            result["content_diff_locations"].append({
                "line": min(len(lines1), len(lines2)) + 1,
                "description": f"File1 has {len(lines1)} lines, File2 has {len(lines2)} lines"
            })

    except UnicodeDecodeError:
        # バイナリファイルの場合
        result["file1"]["is_text"] = False
        result["file2"]["is_text"] = False

        # バイナリの違いを確認
        min_len = min(len(content1), len(content2))
        diff_count = 0
        max_diffs = 10

        for i in range(min_len):
            if content1[i] != content2[i]:
                result["content_diff_locations"].append({
                    "position": i,
                    "file1_byte": hex(content1[i]),
                    "file2_byte": hex(content2[i])
                })

                diff_count += 1
                if diff_count >= max_diffs:
                    break

        # サイズの違いも相違点として記録
        if len(content1) != len(content2):
            result["content_diff_locations"].append({
                "position": min_len,
                "description": f"File1 size is {len(content1)} bytes, File2 size is {len(content2)} bytes"
            })

    return result


def visualize_file_comparison(file1_path: str, file2_path: str, output_file: Optional[str] = None) -> str:
    """
    2つのファイルの比較を可視化

    Args:
        file1_path: 1つ目のファイルパス
        file2_path: 2つ目のファイルパス
        output_file: 出力ファイルパス（指定がなければタイムスタンプ付きの名前を生成）

    Returns:
        出力された画像ファイルパス
    """
    if not output_file:
        timestamp = int(time.time())
        output_file = os.path.join("test_output", f"file_comparison_{timestamp}.png")

    # ファイル比較結果を取得
    comparison = compare_files(file1_path, file2_path)

    plt.figure(figsize=(10, 8))

    # ファイルサイズの比較
    plt.subplot(2, 1, 1)
    sizes = [
        comparison["file1"]["size"],
        comparison["file2"]["size"]
    ]
    labels = [
        os.path.basename(file1_path),
        os.path.basename(file2_path)
    ]

    plt.bar(range(len(sizes)), sizes)
    plt.ylabel('Size (bytes)')
    plt.title('File Size Comparison')
    plt.xticks(range(len(sizes)), labels)
    plt.grid(True, axis='y')

    # ファイルのハッシュ値とテキスト情報
    file1_info = f"File: {os.path.basename(file1_path)}\n" \
                f"Size: {comparison['file1']['size']} bytes\n" \
                f"Hash: {comparison['file1']['hash'][:16]}...\n"

    file2_info = f"File: {os.path.basename(file2_path)}\n" \
                f"Size: {comparison['file2']['size']} bytes\n" \
                f"Hash: {comparison['file2']['hash'][:16]}...\n"

    if "is_text" in comparison["file1"] and comparison["file1"]["is_text"]:
        file1_info += f"Type: Text\n" \
                     f"Lines: {comparison['file1']['line_count']}\n"

        file2_info += f"Type: Text\n" \
                     f"Lines: {comparison['file2']['line_count']}\n"
    else:
        file1_info += "Type: Binary\n"
        file2_info += "Type: Binary\n"

    # 相違点の情報
    diff_info = f"Content identical: {comparison['content_identical']}\n"

    if not comparison["content_identical"]:
        diff_info += f"Differences found: {len(comparison['content_diff_locations'])}\n"

        if comparison["content_diff_locations"]:
            first_diff = comparison["content_diff_locations"][0]
            if "line" in first_diff:
                diff_info += f"First difference at line {first_diff['line']}\n"
            elif "position" in first_diff:
                diff_info += f"First difference at byte {first_diff['position']}\n"

    plt.subplot(2, 1, 2)
    plt.axis('off')
    plt.text(0.05, 0.8, file1_info, fontsize=10, verticalalignment='top')
    plt.text(0.5, 0.8, file2_info, fontsize=10, verticalalignment='top')
    plt.text(0.05, 0.4, diff_info, fontsize=10, verticalalignment='top')

    if not comparison["content_identical"] and comparison["content_diff_locations"]:
        diff_table = "Differences:\n"

        for i, diff in enumerate(comparison["content_diff_locations"][:5]):
            if "line" in diff and "file1_content" in diff:
                diff_table += f"{i+1}. Line {diff['line']}:\n" \
                             f"   File1: {diff['file1_content']}\n" \
                             f"   File2: {diff['file2_content']}\n"
            elif "position" in diff and "file1_byte" in diff:
                diff_table += f"{i+1}. Byte {diff['position']}:\n" \
                             f"   File1: {diff['file1_byte']}\n" \
                             f"   File2: {diff['file2_byte']}\n"
            elif "description" in diff:
                diff_table += f"{i+1}. {diff['description']}\n"

        plt.text(0.05, 0.1, diff_table, fontsize=9, verticalalignment='top')

    plt.tight_layout()
    plt.savefig(output_file)
    logger.info(f"File comparison visualization saved to {output_file}")

    return output_file


def setup_debug_environment():
    """デバッグ環境のセットアップ"""
    # 出力ディレクトリの作成
    os.makedirs("test_output", exist_ok=True)


# デバッグ環境のセットアップ
setup_debug_environment()


if __name__ == "__main__":
    # テスト用コード
    debugger = CryptoDebugger()
    debugger.checkpoint("Debug module test started")

    # テスト用のダミーデータ
    dummy_encrypted_data = {
        "format": "homomorphic_masked",
        "version": "1.0",
        "true_chunks": ["chunk1", "chunk2", "chunk3"],
        "false_chunks": ["chunk4", "chunk5", "chunk6"],
        "metadata": {
            "crypto_type": "paillier",
            "timestamp": time.time()
        }
    }

    # 暗号化データの検査
    inspection_result = debugger.inspect_encrypted_data(dummy_encrypted_data)
    print(f"Inspection result: {json.dumps(inspection_result, indent=2)}")

    # デバッグ情報の可視化
    json_file, image_file = debugger.save_debug_state()
    print(f"Debug state saved to {json_file} and {image_file}")

    # スタック検査のテスト
    def test_nested_function():
        var1 = "test"
        var2 = 123
        stack_info = inspect_call_stack()
        return stack_info

    stack_result = test_nested_function()
    print(f"Stack inspection result: {json.dumps(stack_result, indent=2)}")

    # オブジェクトダンプのテスト
    class TestClass:
        def __init__(self):
            self.name = "Test"
            self.value = 42
            self.nested = {"key": "value"}

    test_obj = TestClass()
    dump_result = dump_object(test_obj)
    print(f"Object dump result: {json.dumps(dump_result, indent=2)}")

    # ファイル比較のテスト
    with open("test_output/file1.txt", "w") as f:
        f.write("Line 1\nLine 2\nLine 3\n")

    with open("test_output/file2.txt", "w") as f:
        f.write("Line 1\nLine 2 modified\nLine 3\n")

    comparison_result = compare_files("test_output/file1.txt", "test_output/file2.txt")
    print(f"File comparison result: {json.dumps(comparison_result, indent=2)}")

    # ファイル比較の可視化
    visualization_file = visualize_file_comparison(
        "test_output/file1.txt",
        "test_output/file2.txt"
    )
    print(f"File comparison visualization saved to {visualization_file}")

    debugger.checkpoint("Debug module test completed")

    print("Debug module test completed successfully.")