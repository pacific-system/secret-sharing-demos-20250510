#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLIコマンドモジュール

このモジュールは、コマンドラインインターフェースの各サブコマンド（init, decrypt, update, generate）
の処理を実装します。
"""

import os
import sys
import json
import time
import getpass
import random
import secrets
from pathlib import Path

from ..core.encryption import encrypt
from ..core.decryption import decrypt
from ..core.update import update_file
from ..utils.file_utils import safe_read_json, safe_write_json


def prompt_password(prompt_text="パスワードを入力してください: "):
    """
    パスワードを安全にプロンプト

    Args:
        prompt_text (str, optional): プロンプト表示テキスト

    Returns:
        str: 入力されたパスワード
    """
    return getpass.getpass(prompt_text)


def load_share_ids(share_file):
    """
    シェアIDリストファイルを読み込み

    Args:
        share_file (str): シェアIDリストのJSONファイルパス

    Returns:
        list: シェアIDのリスト

    Raises:
        FileNotFoundError: ファイルが存在しない場合
        ValueError: 不正なファイル形式の場合
    """
    try:
        data = safe_read_json(share_file)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and 'share_ids' in data:
            return data['share_ids']
        raise ValueError("不正なシェアIDファイル形式です")
    except FileNotFoundError:
        raise FileNotFoundError(f"シェアIDファイルが見つかりません: {share_file}")
    except json.JSONDecodeError:
        raise ValueError(f"JSONの解析に失敗しました: {share_file}")


def generate_command(args):
    """
    シェアID生成コマンド

    Args:
        args: コマンドライン引数

    Returns:
        int: 終了コード
    """
    # 出力ファイル名の設定
    output_file = args.output
    if output_file is None:
        timestamp = int(time.time())
        output_file = f"shares-{timestamp}.json"

    # 比率解析
    ratio_parts = args.ratio.split(':')
    if len(ratio_parts) != 3:
        print("エラー: 比率は 'A:B:未割当' の形式で指定してください")
        return 1

    try:
        ratio_a, ratio_b, ratio_unassigned = map(int, ratio_parts)
    except ValueError:
        print("エラー: 比率は整数で指定してください")
        return 1

    total_ratio = ratio_a + ratio_b + ratio_unassigned
    if total_ratio <= 0:
        print("エラー: 比率の合計は正の整数である必要があります")
        return 1

    # シェアID数の計算
    total_shares = args.size
    a_shares = int(total_shares * ratio_a / total_ratio)
    b_shares = int(total_shares * ratio_b / total_ratio)
    unassigned_shares = total_shares - a_shares - b_shares

    # 全シェアIDの生成
    all_ids = list(range(1, total_shares + 1))
    # シャッフル
    random.shuffle(all_ids)

    # 各カテゴリに割り当て
    a_ids = all_ids[:a_shares]
    b_ids = all_ids[a_shares:a_shares + b_shares]
    unassigned_ids = all_ids[a_shares + b_shares:]

    # 結果の出力
    result = {
        'timestamp': int(time.time()),
        'total_shares': total_shares,
        'ratio': {
            'a': ratio_a,
            'b': ratio_b,
            'unassigned': ratio_unassigned
        },
        'share_ids': {
            'a': sorted(a_ids),
            'b': sorted(b_ids),
            'unassigned': sorted(unassigned_ids)
        }
    }

    # ファイルに保存
    try:
        safe_write_json(result, output_file)
        print(f"シェアIDを生成しました: {output_file}")
        print(f"A文書用: {len(a_ids)}個")
        print(f"B文書用: {len(b_ids)}個")
        print(f"未割当: {len(unassigned_ids)}個")
        return 0
    except Exception as e:
        print(f"エラー: ファイルの保存に失敗しました: {e}")
        return 1


def init_command(args):
    """
    初期化（暗号化）コマンド

    Args:
        args: コマンドライン引数

    Returns:
        int: 終了コード
    """
    # 入力ファイルのチェック
    if not os.path.exists(args.file_a):
        print(f"エラー: ファイルが見つかりません: {args.file_a}")
        return 1

    if not os.path.exists(args.file_b):
        print(f"エラー: ファイルが見つかりません: {args.file_b}")
        return 1

    # シェアIDファイルの読み込み
    try:
        shares_data = safe_read_json(args.shares)

        # シェアIDの取得
        if 'share_ids' in shares_data:
            a_ids = shares_data['share_ids'].get('a', [])
            b_ids = shares_data['share_ids'].get('b', [])
            unassigned_ids = shares_data['share_ids'].get('unassigned', [])
        else:
            print("エラー: シェアIDファイルの形式が不正です")
            return 1

        if not a_ids or not b_ids:
            print("エラー: A文書用またはB文書用のシェアIDがありません")
            return 1

    except Exception as e:
        print(f"エラー: シェアIDファイルの読み込みに失敗しました: {e}")
        return 1

    # JSON文書の読み込み
    try:
        with open(args.file_a, 'r', encoding='utf-8') as f:
            json_a = json.load(f)

        with open(args.file_b, 'r', encoding='utf-8') as f:
            json_b = json.load(f)

    except json.JSONDecodeError:
        print("エラー: 不正なJSON形式のファイルが含まれています")
        return 1
    except Exception as e:
        print(f"エラー: ファイルの読み込みに失敗しました: {e}")
        return 1

    # パスワードの取得
    password_a = args.password_a
    password_b = args.password_b

    if password_a is None:
        password_a = prompt_password("A文書のパスワードを入力してください: ")

    if password_b is None:
        password_b = prompt_password("B文書のパスワードを入力してください: ")

    if not password_a or not password_b:
        print("エラー: パスワードが空です")
        return 1

    # 暗号化処理
    try:
        json_docs = [json_a, json_b]
        passwords = [password_a, password_b]
        share_id_sets = [a_ids, b_ids]

        encrypted_file = encrypt(
            json_docs,
            passwords,
            share_id_sets,
            unassigned_ids,
            threshold=args.threshold
        )

        # 暗号化ファイルの保存
        safe_write_json(encrypted_file, args.output)

        print(f"暗号化に成功しました: {args.output}")
        return 0

    except Exception as e:
        print(f"エラー: 暗号化処理中にエラーが発生しました: {e}")
        return 1


def decrypt_command(args):
    """
    復号コマンド

    Args:
        args: コマンドライン引数

    Returns:
        int: 終了コード
    """
    # 入力ファイルの確認
    if not os.path.exists(args.input):
        print(f"エラー: ファイルが見つかりません: {args.input}")
        return 1

    # シェアIDリストの読み込み
    try:
        share_ids = load_share_ids(args.shares)
    except Exception as e:
        print(f"エラー: シェアIDリストの読み込みに失敗しました: {e}")
        return 1

    # 暗号化ファイルの読み込み
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            encrypted_file = json.load(f)
    except Exception as e:
        print(f"エラー: 暗号化ファイルの読み込みに失敗しました: {e}")
        return 1

    # パスワードの取得
    password = args.password
    if password is None:
        password = prompt_password("パスワードを入力してください: ")

    if not password:
        print("エラー: パスワードが空です")
        return 1

    # 復号処理
    try:
        json_doc = decrypt(encrypted_file, share_ids, password)

        if json_doc is None:
            print("エラー: 復号に失敗しました。パスワードまたはシェアIDが正しくありません。")
            return 1

        # 出力ファイル名の設定
        output_file = args.output
        if output_file is None:
            timestamp = int(time.time())
            output_file = f"decrypted-{timestamp}.json"

        # 復号データの保存
        safe_write_json(json_doc, output_file)

        print(f"復号に成功しました: {output_file}")
        return 0

    except Exception as e:
        print(f"エラー: 復号処理中にエラーが発生しました: {e}")
        return 1


def update_command(args):
    """
    更新コマンド

    Args:
        args: コマンドライン引数

    Returns:
        int: 終了コード
    """
    # 入力ファイルの確認
    if not os.path.exists(args.input):
        print(f"エラー: ファイルが見つかりません: {args.input}")
        return 1

    if not os.path.exists(args.file):
        print(f"エラー: 新しいJSONファイルが見つかりません: {args.file}")
        return 1

    # シェアIDリストの読み込み
    try:
        share_ids = load_share_ids(args.shares)
    except Exception as e:
        print(f"エラー: シェアIDリストの読み込みに失敗しました: {e}")
        return 1

    # 新しいJSON文書の読み込み
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            new_json_doc = json.load(f)
    except Exception as e:
        print(f"エラー: 新しいJSON文書の読み込みに失敗しました: {e}")
        return 1

    # パスワードの取得
    password = args.password
    if password is None:
        password = prompt_password("パスワードを入力してください: ")

    if not password:
        print("エラー: パスワードが空です")
        return 1

    # 出力ファイルの設定
    output_path = args.output
    if output_path is None:
        output_path = args.input

    # 更新処理
    try:
        success = update_file(
            args.input,
            output_path,
            new_json_doc,
            password,
            share_ids,
            backup=args.backup
        )

        if success:
            print(f"更新に成功しました: {output_path}")
            return 0
        else:
            print("エラー: 更新に失敗しました")
            return 1

    except Exception as e:
        print(f"エラー: 更新処理中にエラーが発生しました: {e}")
        return 1
