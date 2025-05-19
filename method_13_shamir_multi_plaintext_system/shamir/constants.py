"""
シャミア秘密分散法システムの定数

このモジュールでは、シャミア秘密分散法による複数平文復号システムの
グローバル定数を定義します。
"""

from gmpy2 import mpz


class ShamirConstants:
    """システム全体で使用する定数"""
    # 有限体の素数 (2^521 - 1)
    PRIME = mpz(2**521 - 1)

    # 閾値（最小復元シェア数）
    DEFAULT_THRESHOLD = 3

    # チャンクサイズ（バイト単位）
    CHUNK_SIZE = 64

    # KDF設定
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_TIME_COST = 3
    ARGON2_PARALLELISM = 4
    ARGON2_OUTPUT_LENGTH = 32

    # パーティション比率
    RATIO_A = 0.35  # Aユーザー用（35%）
    RATIO_B = 0.35  # Bユーザー用（35%）
    RATIO_UNASSIGNED = 0.30  # 未割当（30%）

    # シェアID空間サイズ
    SHARE_ID_SPACE = 1000  # テスト用に小さな値に変更

    # WALログのタイムアウト（秒）
    WAL_TIMEOUT = 3600  # 1時間

    # テンポラリファイルのプレフィックス
    TEMP_FILE_PREFIX = "shamir_temp_"