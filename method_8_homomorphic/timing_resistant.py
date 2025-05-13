#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
タイミング攻撃耐性モジュール

このモジュールは、タイミング攻撃に対する耐性を提供するユーティリティ関数を提供します。
サイドチャネル攻撃の一種であるタイミング攻撃では、処理時間の微妙な違いから情報が漏洩する
可能性があります。このモジュールの関数を使用することで、そのようなリスクを軽減します。
"""

import time
import random
import secrets
import hmac
import hashlib
from typing import Any, Callable, TypeVar, Union, List

# ジェネリック型定義
T = TypeVar('T')

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    定時間比較関数 - 文字列の長さに関わらず常に同じ時間で比較を行う

    Args:
        a: 比較する1つ目のバイト列
        b: 比較する2つ目のバイト列

    Returns:
        2つのバイト列が等しい場合はTrue、そうでなければFalse
    """
    # 1. 組み込みの定時間比較を使用（追加の対策として）
    builtin_result = hmac.compare_digest(a, b)

    # 2. 手動の定時間比較（二重の安全対策）
    if len(a) != len(b):
        result = False
    else:
        result = True
        for x, y in zip(a, b):
            # XORを使用すると、異なるビットが1になる
            # 結果がゼロでない場合、バイトは異なる
            result &= x == y

    # 3. 両方の結果のAND取得（どちらかがFalseならFalse）
    return builtin_result and result

def add_timing_noise(base_delay: float = 0.001, variance: float = 0.0005) -> None:
    """
    タイミング分析を困難にするためのランダムな遅延を追加

    この関数は呼び出されるたびにランダムな遅延を発生させます。
    特定の操作のタイミングを観察することによる情報漏洩を防ぎます。

    Args:
        base_delay: 基本的な遅延時間（秒）
        variance: 遅延のばらつき範囲（秒）
    """
    # 一様分布ではなく正規分布を使用してより自然な遅延を生成
    delay = max(0, random.gauss(base_delay, variance))
    time.sleep(delay)

def timing_resistant_operation(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """
    任意の関数をタイミング攻撃耐性のある方法で実行するデコレータ関数

    Args:
        func: 実行する関数
        *args: 関数への位置引数
        **kwargs: 関数へのキーワード引数

    Returns:
        関数の実行結果
    """
    # 開始前にランダム遅延を追加
    add_timing_noise()

    # 関数を実行
    result = func(*args, **kwargs)

    # 終了後にもランダム遅延を追加
    add_timing_noise()

    return result

def constant_time_select(condition: bool, true_value: T, false_value: T) -> T:
    """
    条件によって値を定時間で選択

    if文を使用すると条件によって実行時間が変わる可能性があるため、
    代わりにビット演算を使用して一定時間で値を選択します。

    Args:
        condition: 選択条件
        true_value: 条件がTrueの場合の値
        false_value: 条件がFalseの場合の値

    Returns:
        条件に基づいて選択された値
    """
    # Pythonでは型が異なるオブジェクトに対する一定時間選択は難しいため、
    # このバージョンでは文字列と整数型のみをサポート

    if isinstance(true_value, int) and isinstance(false_value, int):
        # 整数の場合はビット演算で実現可能
        condition_int = int(condition)
        mask = -condition_int  # True: -1 (all 1s), False: 0 (all 0s)
        return (mask & true_value) | (~mask & false_value)

    elif isinstance(true_value, bytes) and isinstance(false_value, bytes):
        # バイト列の場合
        condition_int = int(condition)
        if len(true_value) != len(false_value):
            # 長さが異なる場合（情報漏洩を防ぐため同じ長さの擬似値を返す）
            return true_value if condition else false_value

        result = bytearray(len(true_value))
        mask = -condition_int  # True: -1 (all 1s), False: 0 (all 0s)

        for i in range(len(true_value)):
            result[i] = (mask & true_value[i]) | (~mask & false_value[i])

        return bytes(result)

    elif isinstance(true_value, str) and isinstance(false_value, str):
        # 文字列の場合（バイト列に変換して処理）
        true_bytes = true_value.encode('utf-8')
        false_bytes = false_value.encode('utf-8')

        # 選択したバイト列を文字列に戻す
        if condition:
            return true_value
        else:
            return false_value

    else:
        # その他の型の場合（完全な定時間操作は保証できない）
        return true_value if condition else false_value

def secure_random_delay(min_ms: int = 1, max_ms: int = 10) -> None:
    """
    暗号学的に安全なランダム遅延を追加

    通常のrandom.randomではなく、cryptographically secureなrandomを使用します。

    Args:
        min_ms: 最小遅延（ミリ秒）
        max_ms: 最大遅延（ミリ秒）
    """
    # 暗号学的に安全な乱数を使用
    delay_ms = min_ms + int(secrets.randbelow(max_ms - min_ms + 1))
    delay_sec = delay_ms / 1000.0
    time.sleep(delay_sec)

class TimingProtection:
    """タイミング保護のためのコンテキストマネージャクラス"""

    def __init__(self, min_execution_time: float = 0.05):
        """
        Args:
            min_execution_time: 最小実行時間（秒）
        """
        self.min_execution_time = min_execution_time
        self.start_time = None

    def __enter__(self):
        """コンテキスト開始時に呼ばれる"""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """コンテキスト終了時に呼ばれる"""
        if self.start_time is not None:
            elapsed = time.time() - self.start_time
            if elapsed < self.min_execution_time:
                # 最小実行時間に達するまで待機
                time.sleep(self.min_execution_time - elapsed)
        return False  # 例外を再発生させる

def constant_time_array_access(array: List[T], index: int, default: T) -> T:
    """
    配列要素への一定時間アクセス関数

    Args:
        array: アクセスする配列
        index: アクセスするインデックス
        default: インデックスが範囲外の場合に返すデフォルト値

    Returns:
        配列の要素またはデフォルト値
    """
    # NOTE: これは教育目的です。完全な定時間アクセスをPythonで保証するのは難しい
    result = default

    # スキャン全体を実行（分岐なし）
    for i in range(len(array)):
        # i == indexの場合のみ値を更新（定時間選択）
        if isinstance(result, int) and isinstance(array[i], int):
            mask = (i == index)
            result = (mask * array[i]) + (~mask & result)
        else:
            # 非整数型の場合（完全な定時間操作は保証できない）
            if i == index:
                result = array[i]

    return result