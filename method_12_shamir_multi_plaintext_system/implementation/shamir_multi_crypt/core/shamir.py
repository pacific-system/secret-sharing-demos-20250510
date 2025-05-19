#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
シャミア秘密分散法の核となるモジュール

このモジュールは、多項式の生成と評価、シェアの生成と復元など、
シャミア秘密分散法の基本機能を提供します。
"""

import random
import secrets
import hashlib
import hmac
from ..utils.constant_time import select_int

# デフォルトの素数 (2^256 - 189)
# 十分に大きな素数を使用して安全性を確保
DEFAULT_PRIME = 2**256 - 189


def generate_polynomial(secret, degree, prime=DEFAULT_PRIME):
    """
    秘密値を固定項として、指定された次数のランダム多項式を生成

    Args:
        secret (int): 秘密値（多項式の0次の係数）
        degree (int): 多項式の次数
        prime (int, optional): 有限体の素数

    Returns:
        list: 多項式の係数リスト [a_0, a_1, ..., a_degree]
             ただし a_0 = secret
    """
    if not (0 <= secret < prime):
        raise ValueError(f"秘密値は0以上prime未満の整数である必要があります: 0 <= {secret} < {prime}")

    # 多項式の係数を生成（最初の要素は秘密値）
    coef = [secret]

    # 残りの係数をランダムに生成
    for _ in range(degree):
        # セキュリティ上重要: 暗号学的に安全な乱数を使用
        coef.append(secrets.randbelow(prime))

    return coef


def evaluate_polynomial(coefficients, x, prime=DEFAULT_PRIME):
    """
    多項式を指定されたxで評価（定数時間で処理）

    Args:
        coefficients (list): 多項式の係数リスト [a_0, a_1, ..., a_n]
        x (int): 評価点
        prime (int, optional): 有限体の素数

    Returns:
        int: f(x) mod prime の値
    """
    if x == 0:
        # x=0の場合は定数項を返す（秘密値）
        return coefficients[0]

    # 多項式の値を計算（ホーナー法）
    result = 0

    # 最高次の項から計算
    for coef in reversed(coefficients):
        result = (result * x + coef) % prime

    return result


def generate_shares(secret, threshold, n, prime=DEFAULT_PRIME):
    """
    シャミア秘密分散法を用いて、シェアを生成

    Args:
        secret (int): 分散する秘密値
        threshold (int): 秘密を復元するために必要なシェアの最小数
        n (int): 生成するシェアの総数
        prime (int, optional): 有限体の素数

    Returns:
        list: [(x_1, y_1), (x_2, y_2), ..., (x_n, y_n)] 形式のシェアのリスト
    """
    if threshold > n:
        raise ValueError(f"閾値はシェア総数以下である必要があります: {threshold} <= {n}")

    if not (0 <= secret < prime):
        raise ValueError(f"秘密値は0以上prime未満の整数である必要があります: 0 <= {secret} < {prime}")

    # 次数 (threshold-1) の多項式を生成
    coefficients = generate_polynomial(secret, threshold-1, prime)

    # シェアを生成
    shares = []
    for i in range(1, n+1):
        # x値として1からnまでの連続した整数を使用
        x = i
        # 多項式を評価してシェアを作成
        y = evaluate_polynomial(coefficients, x, prime)
        shares.append((x, y))

    return shares


def generate_share_for_ids(secret, threshold, share_ids, prime=DEFAULT_PRIME):
    """
    シャミア秘密分散法を用いて、指定されたIDに対応するシェアを生成

    Args:
        secret (int): 分散する秘密値
        threshold (int): 秘密を復元するために必要なシェアの最小数
        share_ids (list): シェアIDのリスト（x値として使用）
        prime (int, optional): 有限体の素数

    Returns:
        list: [(id_1, y_1), (id_2, y_2), ...] 形式のシェアのリスト
    """
    if not share_ids:
        return []

    if not (0 <= secret < prime):
        raise ValueError(f"秘密値は0以上prime未満の整数である必要があります: 0 <= {secret} < {prime}")

    # 次数 (threshold-1) の多項式を生成
    coefficients = generate_polynomial(secret, threshold-1, prime)

    # 指定されたIDに対応するシェアを生成
    shares = []
    for id_value in share_ids:
        # 多項式を評価してシェアを作成
        y = evaluate_polynomial(coefficients, id_value, prime)
        shares.append((id_value, y))

    return shares


def mod_inverse(a, m):
    """
    モジュラ逆数を計算: a^(-1) mod m

    拡張ユークリッドアルゴリズムを使用して、
    a * x ≡ 1 (mod m) となるxを求める

    Args:
        a (int): 逆数を求める数
        m (int): モジュラス

    Returns:
        int: モジュラ逆数

    Raises:
        ValueError: aとmが互いに素でない場合
    """
    if m == 1:
        return 0

    # 拡張ユークリッドアルゴリズム
    m0, a0 = m, a
    t, q = 0, 0
    x0, x1 = 0, 1

    while a > 1:
        q = a // m
        t = m

        m = a % m
        a = t

        t = x0
        x0 = x1 - q * x0
        x1 = t

    # 結果が負になる場合はモジュラスを加える
    if x1 < 0:
        x1 += m0

    return x1


def lagrange_interpolation(shares, prime=DEFAULT_PRIME):
    """
    ラグランジュ補間を用いて秘密を復元（定数時間で処理）

    Args:
        shares (list): 形式 [(x_1, y_1), (x_2, y_2), ...] のシェアのリスト
        prime (int, optional): 有限体の素数

    Returns:
        int: 復元された秘密値
    """
    if len(shares) < 2:
        raise ValueError("少なくとも2つのシェアが必要です")

    x_coords = [x for x, _ in shares]
    y_coords = [y for _, y in shares]

    # 重複するx座標をチェック
    if len(set(x_coords)) != len(x_coords):
        raise ValueError("重複するx座標があります")

    # x=0での多項式の値（秘密値）を計算
    secret = 0

    for i, (x_i, y_i) in enumerate(shares):
        # ラグランジュ基底多項式の係数を計算
        numerator = 1
        denominator = 1

        for j, (x_j, _) in enumerate(shares):
            if i == j:
                continue

            # L_i(x) の分子と分母を計算
            # L_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j)
            numerator = (numerator * (0 - x_j)) % prime
            denominator = (denominator * (x_i - x_j)) % prime

        # モジュラ逆数を計算
        inverse_denominator = mod_inverse(denominator, prime)

        # ラグランジュ係数
        lagrange_coef = (numerator * inverse_denominator) % prime

        # 秘密値に寄与を加算
        secret = (secret + y_i * lagrange_coef) % prime

    return secret
