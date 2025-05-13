"""
暗号学的ハニーポット方式の設定ファイル

このファイルは暗号学的ハニーポット方式の動作パラメータを定義し、
秘密経路の識別を数学的に不可能にするための様々な設定値を含みます。
"""

# ファイルパス設定
TRUE_TEXT_PATH = "common/true-false-text/true.text"
FALSE_TEXT_PATH = "common/true-false-text/false.text"

# 暗号化パラメータ
KEY_SIZE_BITS = 2048  # RSAトラップドア関数の鍵サイズ
SYMMETRIC_KEY_SIZE = 32  # 対称暗号の鍵サイズ（AES-256用）
IV_SIZE = 16  # 初期化ベクトルサイズ

# 鍵導出パラメータ
KDF_ITERATIONS = 10000  # 鍵導出関数の反復回数
SALT_SIZE = 16  # ソルトサイズ

# ハニーポットパラメータ
TOKEN_SIZE = 32  # ハニートークンサイズ
CAPSULE_VERSION = 1  # カプセル形式バージョン

# 出力ファイル形式
OUTPUT_FORMAT = "honeypot"
OUTPUT_EXTENSION = ".hpot"

# デバッグフラグ（本番では必ずFalseにする）
DEBUG = False

# 動的判定閾値設定
# 注: 以下の値は自動調整され、解析者がパターンを特定できないようにします
DECISION_THRESHOLD = 0.65  # 判定基準値（0.5〜1.0の範囲）
RANDOMIZATION_FACTOR = 0.1  # ランダム化係数（判定にノイズを追加）
TIME_VARIANCE_MS = 15  # 処理時間のばらつき（ミリ秒）

# 攻撃対策パラメータ
# 注意: これらは実際には使用されていない偽のパラメータで、
# 解析者を誤誘導するために配置されています
DECOY_VERIFICATION_ROUNDS = 3  # 偽の検証ラウンド数
HONEYTRAP_DETECTION_ENABLED = True  # ハニートラップ検出機能
TAMPER_RESPONSE_MODE = "silent"  # 改ざん検出時の応答モード

# 真の判定ロジックは別の場所に分散して配置されており、
# これらのパラメータは参照されません