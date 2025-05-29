#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
パスワード管理ユーティリティ

【責務】
このモジュールは、テスト用パスワードの管理機能を提供します。
パスワードファイルからの読み込み、ランダムなパスワードの選択、
およびパスワードのハッシュ化を行います。

【依存関係】
- random: ランダムなパスワード選択に使用
- hashlib: パスワードのハッシュ化に使用
- logging: ログ出力に使用
- os.path: ファイルパス操作に使用

【使用方法】
from utils.password_manager import get_random_password, get_password_hash

password = get_random_password()
password_hash = get_password_hash(password)
"""

import random
import hashlib
import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)

# モジュールレベルのキャッシュ変数
_passwords_cache = None

def get_password_file_path() -> str:
    """パスワードファイルのパスを取得する"""
    # まずは現在のディレクトリからの相対パスを試す
    current_password_file = "test_passwords.txt"
    if os.path.exists(current_password_file):
        return os.path.abspath(current_password_file)

    # 親ディレクトリを探す
    current_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.dirname(current_dir)
    password_file_path = os.path.join(test_dir, "test_passwords.txt")

    # 絶対パスを返す
    return password_file_path

def load_passwords(force_reload: bool = False) -> List[str]:
    """
    パスワードファイル（test_passwords.txt）を読み込む

    Args:
        force_reload: キャッシュを無視して強制的に再読み込みするフラグ

    Returns:
        パスワードのリスト、読み込みに失敗した場合は空リスト
    """
    global _passwords_cache

    # キャッシュされたデータがあり、強制再読み込みでない場合はキャッシュを返す
    if _passwords_cache is not None and not force_reload:
        return _passwords_cache

    password_file_path = get_password_file_path()

    try:
        with open(password_file_path, 'r', encoding='utf-8') as f:
            # 各行をトリムしてリストに格納
            passwords = [line.strip() for line in f if line.strip()]

        logger.info(f"パスワードファイルを読み込みました: {password_file_path}")
        logger.debug(f"読み込まれたパスワード数: {len(passwords)}")

        # キャッシュに保存
        _passwords_cache = passwords
        return passwords

    except FileNotFoundError:
        logger.error(f"パスワードファイルが見つかりません: {password_file_path}")
        return []

    except Exception as e:
        logger.error(f"パスワードファイルの読み込み中にエラーが発生しました: {str(e)}")
        return []

def get_random_password() -> Optional[str]:
    """
    ランダムなパスワードを取得する

    Returns:
        ランダムに選択されたパスワード、パスワードが読み込めない場合はNone
    """
    passwords = load_passwords()

    if not passwords:
        logger.error("パスワードが読み込めないため、ランダムなパスワードを返せません")
        return None

    password = random.choice(passwords)
    # ログにはパスワードの長さのみを出力（セキュリティのため）
    logger.debug(f"ランダムなパスワードを選択しました（長さ: {len(password)}）")

    return password

def get_password_for_partition(partition: str) -> Optional[str]:
    """
    指定されたパーティション用のパスワードを取得する

    Args:
        partition: パーティション識別子（'A' または 'B'）

    Returns:
        選択されたパスワード、パスワードが読み込めない場合はNone
    """
    # ランダムなパスワードを選択して返す
    password = get_random_password()
    logger.info(f"パーティション {partition} 用のパスワードをランダムに選択しました")
    return password

def get_password_hash(password: str) -> str:
    """
    パスワードのハッシュ値を取得する

    Args:
        password: ハッシュ化するパスワード

    Returns:
        パスワードのSHA-256ハッシュ値（16進数文字列）
    """
    if not password:
        logger.warning("空のパスワードに対してハッシュを計算しています")

    # SHA-256ハッシュを計算
    hash_obj = hashlib.sha256(password.encode('utf-8'))
    password_hash = hash_obj.hexdigest()

    logger.debug(f"パスワードハッシュを計算しました: {password_hash[:8]}...")

    return password_hash

def get_two_random_passwords() -> tuple[Optional[str], Optional[str]]:
    """
    重複なしで2個のランダムなパスワードを取得する

    Returns:
        (password_a, password_b): 重複なしの2個のパスワードのタプル、
        パスワードが読み込めない場合は(None, None)
    """
    passwords = load_passwords()

    if not passwords:
        logger.error("パスワードが読み込めないため、ランダムなパスワードを返せません")
        return None, None

    if len(passwords) < 2:
        logger.error("パスワードが2個未満のため、重複なしで2個のパスワードを返せません")
        return None, None

    # 重複なしで2個選択
    selected_passwords = random.sample(passwords, 2)
    password_a, password_b = selected_passwords[0], selected_passwords[1]

    # ログにはパスワードの長さのみを出力（セキュリティのため）
    logger.debug(f"重複なしで2個のランダムなパスワードを選択しました（長さ: {len(password_a)}, {len(password_b)}）")
    logger.info(f"A用パスワード（ランダム選択）: {password_a}")
    logger.info(f"B用パスワード（ランダム選択）: {password_b}")

    return password_a, password_b