#!/usr/bin/env python3
"""
不確定性転写暗号化方式の設定

状態遷移マトリクスのサイズや確率パラメータなど、
暗号化処理の動作を制御するための設定を定義します。
"""

# ファイルパス設定
TRUE_TEXT_PATH = "common/true-false-text/true.text"
FALSE_TEXT_PATH = "common/true-false-text/false.text"

# 暗号化パラメータ
KEY_SIZE_BYTES = 32  # 256ビット鍵
SALT_SIZE = 16       # ソルトサイズ
NONCE_SIZE = 12      # ノンスサイズ

# 状態マトリクスの設定
STATE_MATRIX_SIZE = 16  # 状態マトリクスのサイズ（状態の数）
STATE_TRANSITIONS = 10  # 状態遷移回数

# 確率設定
MIN_PROBABILITY = 0.05  # 最小遷移確率
MAX_PROBABILITY = 0.95  # 最大遷移確率
PROBABILITY_STEPS = 100  # 確率の量子化ステップ数

# 出力ファイル形式
OUTPUT_FORMAT = "indeterministic"
OUTPUT_EXTENSION = ".indet"

# 長大ファイル分割設定
MAX_CHUNK_SIZE = 10 * 1024 * 1024  # 10MB: ファイル分割の最大チャンクサイズ
FILE_THRESHOLD_SIZE = 50 * 1024 * 1024  # 50MB: この閾値を超えるとファイルを分割
DEFAULT_CHUNK_COUNT = 5  # デフォルトのチャンク数（大きなファイルを何分割するか）

# セキュリティ設定
SECURE_MEMORY_WIPE = True  # メモリからの鍵情報を安全に消去
ANTI_TAMPERING = True  # 改ざん検知を有効にするかどうか
USE_DYNAMIC_THRESHOLD = True  # 動的判定閾値の使用
RUNTIME_VERIFICATION = True  # 実行時検証の有効化
INTEGRITY_CHECK_INTERVAL = 500  # 整合性チェックの間隔（ミリ秒）
MAX_RETRY_COUNT = 3  # 処理失敗時の最大再試行回数

# バックドア・バイパス防止設定
ERROR_ON_SUSPICIOUS_BEHAVIOR = True  # 不審な挙動を検出した場合にエラーを発生させるかどうか
ENFORCE_PATH_ISOLATION = True  # 正規/非正規パス間の分離を強制
PREVENT_OUTPUT_BYPASS = True  # 出力バイパスを防止

# デバッグフラグ（本番では必ずFalseにする）
DEBUG = False