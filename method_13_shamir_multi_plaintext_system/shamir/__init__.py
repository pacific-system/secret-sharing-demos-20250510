"""
シャミア秘密分散法による複数平文復号システム

このパッケージでは、シャミア秘密分散法を使用して複数の平文をひとつの暗号化ファイルに
格納し、それぞれを独立したパスワードで復号できるシステムを提供します。
"""

from .constants import ShamirConstants
from .crypto import (
    encrypt_json_document, decrypt_json_document, select_shares_for_encryption,
    select_shares_for_decryption, reconstruct_secret, derive_key,
    preprocess_json_document, postprocess_json_document,
    init_encrypted_file, process_with_progress
)
from .core import generate_shares, lagrange_interpolation
from .update import update_encrypted_document, verify_update
from .partition import generate_partition_map_key, initialize_system
# V3形式のインポート
try:
    from .formats.v3 import FileFormatV3
    V3_FORMAT_AVAILABLE = True
except ImportError:
    V3_FORMAT_AVAILABLE = False

__version__ = '1.0.0'