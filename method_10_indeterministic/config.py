"""
不確定性転写暗号化方式の設定ファイル
"""

# ファイルパス設定
TRUE_TEXT_PATH = "common/true-false-text/true.text"
FALSE_TEXT_PATH = "common/true-false-text/false.text"

# 暗号化パラメータ
KEY_SIZE_BYTES = 32  # 256ビット鍵
SALT_SIZE = 16       # ソルトサイズ
NONCE_SIZE = 12      # ノンスサイズ

# 状態遷移パラメータ
STATE_MATRIX_SIZE = 16     # 状態マトリクスサイズ
STATE_TRANSITIONS = 10     # 状態遷移回数
ENTROPY_POOL_SIZE = 4096   # エントロピープールサイズ

# 確率的パラメータ
MIN_PROBABILITY = 0.05     # 最小確率閾値
MAX_PROBABILITY = 0.95     # 最大確率閾値
PROBABILITY_STEPS = 100    # 確率ステップ数

# 出力ファイル形式
OUTPUT_FORMAT = "indeterministic"
OUTPUT_EXTENSION = ".indet"

# デバッグフラグ（本番では必ずFalseにする）
DEBUG = False