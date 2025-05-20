"""
シャミア秘密分散法による複数平文復号システム

このパッケージは、シャミア秘密分散法を応用した複数平文復号システムを
実装しています。単一の暗号化ファイルから異なるパスワードを使用して
異なる平文（JSON文書）を復号可能にします。
"""

from .crypto import encrypt_json_document, decrypt_json_document
from .update import update_encrypted_document, verify_update
from .formats import load_encrypted_file, save_encrypted_file, convert_file_format, detect_file_format
from .partition import generate_partition_map_key, PartitionManager, initialize_system
from .constants import ShamirConstants
from .key_management import PartitionKeyManager
from .metadata import MetadataManager
from .share_id import MemoryEfficientShareIDGenerator, verify_share_ids

__version__ = '1.0.0'