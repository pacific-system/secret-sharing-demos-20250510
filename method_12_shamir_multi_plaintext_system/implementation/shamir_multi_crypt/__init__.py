#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
シャミア秘密分散法による複数平文復号システム

このパッケージは、単一の暗号化ファイルから
異なるパスワードを用いて異なる平文（JSON文書）を
復号可能にするシステムを提供します。
"""

from .core.encryption import encrypt
from .core.decryption import decrypt
from .core.update import update, update_file

__version__ = '0.1.0'
__author__ = 'Shamir Multi-Crypt Team'
__all__ = ['encrypt', 'decrypt', 'update', 'update_file']
