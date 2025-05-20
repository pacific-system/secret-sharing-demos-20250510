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



    # ファイルパーティション設計
    PARTITION_SIZE = 3500   # 各ファイル(A/B)用パーティション総サイズ（整数、共通値）
    ACTIVE_SHARES = 2000    # 各ファイル(A/B)用有効シェア数（整数、共通値）
    GARBAGE_SHARES = 1500   # 各ファイル(A/B)用ゴミデータ数（整数、共通値）
    # 検証: ACTIVE_SHARES + GARBAGE_SHARES == PARTITION_SIZE

    # 未割当領域
    UNASSIGNED_SHARES = 3000     # 未割当シェア数（整数）

    # 全体シェア数（自動計算）
    SHARE_ID_SPACE = PARTITION_SIZE * 2 + UNASSIGNED_SHARES

    # チャンクサイズ（バイト単位）
    CHUNK_SIZE = 64

    # KDF設定
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_TIME_COST = 3
    ARGON2_PARALLELISM = 4
    ARGON2_OUTPUT_LENGTH = 32

    # 固定PBKDF2イテレーション数
    PBKDF2_ITERATIONS = 100000

    # パーティション比率
    RATIO_A = 0.35  # Aファイル用（35%）
    RATIO_B = 0.35  # Bファイル用（35%）
    RATIO_UNASSIGNED = 0.30  # 未割当（30%）

    # WALログのタイムアウト（秒）
    WAL_TIMEOUT = 3600  # 1時間

    # テンポラリファイルのプレフィックス
    TEMP_FILE_PREFIX = "shamir_temp_"

    # 暗号化ファイル形式バージョン
    # 1: 元の形式（各シェアに冗長なメタデータ）
    # 2: 最適化形式（シェア値のみ）
    FILE_FORMAT_VERSION = 2

    # ファイルヘッダー識別子
    FILE_HEADER_MAGIC = "SHAMIR_MP"

    # パフォーマンスモニタリング設定
    ENABLE_PERFORMANCE_MONITORING = True
    MEMORY_WARNING_THRESHOLD_MB = 1024  # 1GB以上のメモリ使用で警告