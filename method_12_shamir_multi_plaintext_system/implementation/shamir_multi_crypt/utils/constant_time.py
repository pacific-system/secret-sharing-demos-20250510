#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
定数時間処理のためのユーティリティ関数モジュール

このモジュールは、条件分岐を避け、タイミング攻撃を防ぐための関数群を提供します。
すべての関数は入力値や条件に関わらず常に同じ処理パスを通ります。
"""

import hmac
import hashlib
import secrets


def constant_time_compare(a, b):
    """
    定数時間で2つのバイト列を比較する

    Args:
        a (bytes): 比較対象のバイト列1
        b (bytes): 比較対象のバイト列2

    Returns:
        bool: 2つのバイト列が等しい場合はTrue、そうでない場合はFalse
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def select_int(condition, true_value, false_value):
    """
    条件に基づいて2つの整数値のいずれかを選択（定数時間）

    Args:
        condition (bool): 選択条件
        true_value (int): conditionがTrueの場合に選択される値
        false_value (int): conditionがFalseの場合に選択される値

    Returns:
        int: 選択された値
    """
    mask = -int(condition)  # True -> -1 (all 1s), False -> 0
    return (true_value & mask) | (false_value & ~mask)


def select_bytes(condition, true_value, false_value):
    """
    条件に基づいて2つのバイト列のいずれかを選択（定数時間）

    Args:
        condition (bool): 選択条件
        true_value (bytes): conditionがTrueの場合に選択されるバイト列
        false_value (bytes): conditionがFalseの場合に選択されるバイト列

    Returns:
        bytes: 選択されたバイト列
    """
    # バイト列を同じ長さに調整（ゼロパディング）
    max_len = max(len(true_value), len(false_value))
    padded_true = true_value.ljust(max_len, b'\x00')
    padded_false = false_value.ljust(max_len, b'\x00')

    # バイト単位で選択
    result = bytearray(max_len)
    mask = -int(condition)  # True -> -1 (all 1s), False -> 0
    mask_bytes = mask.to_bytes(1, 'big') * max_len

    for i in range(max_len):
        result[i] = (padded_true[i] & mask_bytes[i]) | (padded_false[i] & ~mask_bytes[i])

    # 選択されたバイト列の元の長さを復元
    orig_len = select_int(condition, len(true_value), len(false_value))
    return bytes(result[:orig_len])


def constant_time_index_of(item, collection):
    """
    コレクション内でアイテムを検索し、インデックスを返す（定数時間）

    すべての要素をスキャンし、コレクション内にアイテムが見つからない場合は-1を返します。

    Args:
        item: 検索対象のアイテム
        collection (list): 検索対象のコレクション

    Returns:
        int: アイテムのインデックス（見つからない場合は-1）
    """
    found_idx = -1
    for i, element in enumerate(collection):
        is_match = (element == item)
        # 最初に見つかったインデックスのみを記録（複数ある場合は最初のもの）
        found_idx = select_int(is_match and found_idx == -1, i, found_idx)

    return found_idx
