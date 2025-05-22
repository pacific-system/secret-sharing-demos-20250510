"""
暗号化ファイル形式パッケージ

このパッケージでは、シャミア秘密分散法による複数平文復号システムの
暗号化ファイル形式を定義しています。
"""

# load_encrypted_fileとsave_encrypted_fileをcrypto.pyからインポートして再エクスポート
from ..crypto import load_encrypted_file, save_encrypted_file

# V3形式を有効化
from . import v3

# V1/V2形式関連のクラスをインポート（存在する場合）
try:
    from . import v1
    FileFormatV1 = v1.FileFormatV1
except ImportError:
    # FileFormatV1が存在しない場合は無視
    pass

try:
    from . import v2
    FileFormatV2 = v2.FileFormatV2
except ImportError:
    # FileFormatV2が存在しない場合は無視
    pass

# V3形式をエクスポート
FileFormatV3 = v3.FileFormatV3