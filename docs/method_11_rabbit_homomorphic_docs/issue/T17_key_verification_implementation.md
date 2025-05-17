# 📝 鍵検証・強度評価実装指示書（T17） - ラビット＋準同型マスキング暗号プロセッサ 🔐

> **ドキュメント種別: 実装指示書**

## 🌟 タスク進捗状況

タスク実装フェーズの進捗:

- 🔄 **フェーズ 0**: 実装準備 [**現在作業中**]
- ⏳ **フェーズ 1**: 基盤ユーティリティ実装 [予定]
- ⏳ **フェーズ 2**: セキュリティ対策基盤実装 [予定]
- ⏳ **フェーズ 3**: 三暗号方式コア実装 [予定]
- ⏳ **フェーズ 4**: 融合機能と変換システム実装 [予定]
- ⏳ **フェーズ 5**: データ形式とインターフェース実装 [予定]
- ⏳ **フェーズ 6**: 検証とパフォーマンス最適化 [予定]

### 📋 現在の実装フェーズ: `フェーズ0: 実装準備`

**現在のタスク**: T17（鍵検証・強度評価実装）
**進捗状況**: T1-T16 完了 → **T17 実装中** → T18-T115 未着手

**注**: 各タスクは独立して実装・完了させてください。

### 🎯 タスク範囲（T17: 鍵検証・強度評価実装）

**実装すべきもの**:

- ✅ `utils/key/key_verification.py`
- ✅ 関連するテスト

**実装してはいけないもの**:

- ❌ `utils/key/key_rotation.py`（次のタスク T18）
- ❌ `utils/key/key_lifecycle.py`（タスク T19）
- ❌ 他の機能（T18 以降のタスク）

**実装がベストプラクティスに反する可能性がある場合**: 作業を即時停止し、問題を報告してください。

## 📝 課題の詳細

### 🎯 タスク概要

本タスク（T17）では鍵検証・強度評価機能を実装します。T15 で実装した鍵管理基本機能および T16 で実装した鍵保存・読込機能と連携し、暗号鍵の品質検証と強度評価を行うための機能を提供します。このコンポーネントは鍵の生成、保存、使用のライフサイクル全体における鍵の安全性を確保する上で重要な役割を果たします。

**本タスク（T17）の作業カウント**:

- 📝 **実装作業**: 10 件

  - 鍵品質検証機能: 3 関数
  - 鍵強度評価機能: 3 関数
  - 鍵脆弱性検出機能: 2 関数
  - 鍵統計分析機能: 2 関数

- 🧪 **テスト作業**: 4 件

  - 鍵品質検証機能テスト
  - 鍵強度評価機能テスト
  - 鍵脆弱性検出機能テスト
  - 鍵統計分析機能テスト

- ✅ **完了条件**: 25 項目
  - 実装完了条件: 5 項目
  - 機能完了条件: 5 項目
  - テスト完了条件: 5 項目
  - ドキュメント完了条件: 5 項目
  - 納品物件検証条件: 5 項目

### 🔍 背景と目的

ラビット＋準同型マスキング暗号プロセッサにおいて、鍵の品質と強度はシステム全体のセキュリティの基盤です。良質な暗号鍵は、第二回暗号解読キャンペーンで発見された脆弱性を含め、あらゆる攻撃に対する耐性の前提条件となります。本タスクでは、生成された暗号鍵の品質を評価し、統計的・暗号学的な欠陥を検出するための機能を実装します。

特に、伝統的なエントロピー評価だけでなく、格子基底の直交性や同型写像の非周期性といった高度な数学的特性も検証し、Tri-Fusion アーキテクチャの核心部分における鍵の適合性を確認します。また、鍵の強度を客観的に評価し、具体的な数値として表すことで、システム管理者やセキュリティ担当者が適切な判断を行うための指標を提供します。

このタスクはフェーズ 0 の最初に位置し、他のすべてのコンポーネントから利用される基盤機能を提供します。安全かつ効率的なロギング機能は、開発、デバッグ、運用の全段階で暗号処理の正確性検証と問題診断に不可欠です。

### 📊 要件仕様

1. T15（鍵管理基本機能）と T16（鍵保存・読込機能）と連携し、鍵の品質と強度を評価できること
2. 最新の暗号学的基準に基づいた鍵品質検証機能を提供すること
3. 鍵長、エントロピー、周期性、相関性など複数の観点から客観的な鍵強度評価を行えること
4. 第二回暗号解読キャンペーンで発見された脆弱性に関連する鍵の欠陥を検出できること
5. 検証結果を数値評価とカテゴリ評価の両方で提供すること
6. 高度な数学的評価（格子基底分析、同型写像評価など）を適用できること
7. 既知の弱い鍵パターンやアルゴリズム固有の脆弱性を検出できること
8. 鍵のライフサイクル管理に必要な情報（強度減衰予測など）を提供すること
9. ロギング基盤（T1）と連携し、セキュリティを考慮した監査ログを出力すること
10. 後続タスクでの鍵ローテーション（T18）や鍵ライフサイクル（T19）と整合的に連携できるインターフェースを提供すること

### 🛠️ 実装内容詳細

#### 1. 鍵品質検証機能（3 つの関数）

```python
def verify_key_quality(key_data: bytes, requirements: dict = None) -> dict:
    """
    暗号鍵の品質を検証し、合格/不合格の判定と詳細評価を提供する

    Args:
        key_data: 検証する鍵データ（バイト列）
        requirements: 検証要件を指定する辞書（省略可）
          例: {
            "min_entropy": 7.5,  # ビット単位のバイトあたり最小エントロピー
            "min_key_length": 32,  # 最小鍵長（バイト数）
            "max_repetition": 0.1,  # 許容される最大繰り返しパターン率
            "required_tests": ["entropy", "distribution", "correlation"]  # 必須検証項目
          }

    Returns:
        検証結果を含む辞書
        {
          "passed": bool,  # 全体的な合格/不合格判定
          "score": float,  # 品質スコア（0.0～10.0）
          "details": {  # 各検証項目の詳細結果
            "entropy": {"passed": bool, "value": float, "threshold": float, "description": str},
            "length": {"passed": bool, "value": int, "threshold": int, "description": str},
            ... 他の検証項目 ...
          },
          "recommendations": [str, ...],  # 改善推奨事項（あれば）
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: requirementsに無効な値が含まれる場合

    実装詳細:
    1. 引数の検証（key_dataが非空、requirementsの構造が有効）
    2. デフォルト要件の設定（requirementsが省略された場合）
    3. 検証項目の実行:
       - エントロピー評価（analyze_key_entropy()を使用）
       - 鍵長評価
       - ランダム性評価
       - 周期性評価
       - バイト分布評価
       - 相関性評価
    4. 結果の集約と全体スコアの計算:
       - 各検証項目の重み付け合計
       - 0.0～10.0の範囲での正規化
    5. 合格/不合格の判定（すべての必須項目が基準を満たすか）
    6. 問題がある場合の改善推奨事項の生成
    7. ログ出力（検証イベント、結果概要、鍵自体は非表示）
    8. 詳細な結果辞書の返却
    """
    pass

def verify_key_suitability(key_data: bytes, algorithm: str, use_case: str = None) -> dict:
    """
    特定のアルゴリズムやユースケースに対する鍵の適合性を検証する

    Args:
        key_data: 検証する鍵データ（バイト列）
        algorithm: 暗号アルゴリズム識別子（"rabbit", "homomorphic", "quantum_resistant", "tri_fusion"など）
        use_case: 用途識別子（"encryption", "signing", "key_derivation"など、省略可）

    Returns:
        適合性検証結果を含む辞書
        {
          "suitable": bool,  # 適合性の判定
          "confidence": float,  # 確信度（0.0～1.0）
          "reasons": [str, ...],  # 判定理由のリスト
          "algorithm_requirements": {  # アルゴリズム要件
            "key_format": str,  # 期待される鍵形式
            "min_length": int,  # 最小バイト長
            ... 他の要件 ...
          },
          "key_properties": {  # 鍵の実際の特性
            "format": str,  # 検出された形式
            "length": int,  # 実際の長さ
            ... 他の特性 ...
          }
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: algorithmが未サポートの場合
        ValueError: use_caseが未サポートの場合

    実装詳細:
    1. 引数の検証（key_data非空、algorithmとuse_caseのサポート確認）
    2. アルゴリズム固有の要件セットの取得:
       - "rabbit": ストリーム暗号鍵要件
       - "homomorphic": 準同型暗号鍵要件
       - "quantum_resistant": 量子耐性暗号鍵要件
       - "tri_fusion": 三方向融合アーキテクチャ要件
    3. 用途固有の追加要件の適用（指定がある場合）
    4. 鍵特性の詳細分析:
       - 形式と構造の検出
       - 鍵長の評価
       - 特殊構造や拡張情報の抽出
    5. アルゴリズム要件と鍵特性の比較
    6. 適合度と確信度の計算
    7. 詳細な理由説明の生成
    8. ログ出力（適合性評価イベント、結果概要、鍵自体は非表示）
    9. 詳細な結果辞書の返却
    """
    pass

def verify_mathematical_properties(key_data: bytes, property_name: str, params: dict = None) -> dict:
    """
    暗号鍵の特定の数学的特性を検証する

    Args:
        key_data: 検証する鍵データ（バイト列）
        property_name: 検証する数学的特性
          サポートされる特性:
          - "orthogonality" - 格子基底の直交性
          - "non_periodicity" - 同型写像の非周期性
          - "lattice_security" - 格子ベースの安全性
          - "correlation_resistance" - 相関分析耐性
          - "collision_resistance" - 衝突耐性
        params: 特性検証用の追加パラメータ（省略可）

    Returns:
        数学的特性検証結果を含む辞書
        {
          "verified": bool,  # 検証結果
          "confidence": float,  # 確信度（0.0～1.0）
          "value": float,  # 測定値または評価値
          "threshold": float,  # 合格基準値
          "details": {  # 特性固有の詳細結果
            ... 特性固有のフィールド ...
          },
          "technical_description": str,  # 技術的な説明
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: property_nameが未サポートの場合
        ValueError: paramsに特性と互換性のない値が含まれる場合

    実装詳細:
    1. 引数の検証（key_data非空、property_nameのサポート確認）
    2. 特性に応じた検証処理:
       - "orthogonality": 格子基底の直交性検証
         - 鍵から格子基底を導出
         - グラム・シュミット過程による直交化
         - 直交度と基底ベクトル間の角度計算
       - "non_periodicity": 同型写像の非周期性検証
         - 周期性検出アルゴリズムの適用
         - 最小周期長の推定
         - 非周期性信頼度の計算
       - "lattice_security": 格子ベースの安全性検証
         - SVP/CVP困難性の推定
         - 量子アルゴリズムに対する耐性評価
       - "correlation_resistance": 相関分析耐性検証
         - 自己相関分析
         - 相補文書相関分析
       - "collision_resistance": 衝突耐性検証
         - バースデーパラドックス理論に基づく衝突確率計算
         - 部分空間分析
    3. 数学的特性の技術的な説明生成
    4. ログ出力（数学的検証イベント、特性名と結果のみ、鍵自体は非表示）
    5. 詳細な結果辞書の返却
    """
    pass
```

#### 2. 鍵強度評価機能（3 つの関数）

```python
def evaluate_key_strength(key_data: bytes, context: dict = None) -> dict:
    """
    暗号鍵の強度を総合的に評価し、数値スコアとカテゴリ評価を提供する

    Args:
        key_data: 評価する鍵データ（バイト列）
        context: 評価コンテキスト情報（省略可）
          例: {
            "algorithm": "rabbit_stream",  # 使用アルゴリズム
            "year": 2023,  # 評価基準年（デフォルト: 現在）
            "adversary": "quantum",  # 想定攻撃者能力（"classical", "quantum"）
            "purpose": "encryption"  # 鍵の用途
          }

    Returns:
        強度評価結果を含む辞書
        {
          "score": float,  # 総合強度スコア（0.0～10.0）
          "category": str,  # 強度カテゴリ（"very_weak", "weak", "moderate", "strong", "very_strong"）
          "effective_bits": int,  # 実効的なセキュリティビット数
          "estimated_lifetime": {  # 推定有効期間
            "years": int,  # 年数
            "confidence": float,  # 推定確信度
            "assumptions": str,  # 前提条件の説明
          },
          "breakdown": {  # 評価内訳
            "entropy": float,  # エントロピー評価（0.0～10.0）
            "length": float,  # 長さ評価（0.0～10.0）
            "algorithm_suitability": float,  # アルゴリズム適合性（0.0～10.0）
            "statistical_strength": float,  # 統計的強度（0.0～10.0）
            "quantum_resistance": float,  # 量子耐性（0.0～10.0）
            ... 他の評価項目 ...
          },
          "mitigations": [str, ...],  # 強度向上策の推奨（あれば）
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: contextに無効な値が含まれる場合

    実装詳細:
    1. 引数の検証（key_data非空、context内容の検証）
    2. デフォルトコンテキストの設定（省略された場合）
    3. 以下の観点での鍵強度評価:
       - エントロピー分析（analyze_key_entropy()を使用）
       - 鍵長評価と実効ビット数計算
       - アルゴリズム適合性評価（verify_key_suitability()を使用）
       - 統計的強度評価（analyze_key_statistics()を使用）
       - 量子耐性評価（quantum_resistant contextの場合）
       - 数学的特性評価（verify_mathematical_properties()を使用）
    4. 時間的側面の評価:
       - 現在と指定された評価基準年に基づく計算能力予測
       - 攻撃者モデル（classical/quantum）に基づく攻撃難易度推定
       - 有効期間の推定
    5. 総合スコアの計算:
       - 各評価項目の重み付け合計
       - 0.0～10.0の範囲での正規化
    6. カテゴリ分類:
       - 0.0～2.0: "very_weak"
       - 2.0～4.0: "weak"
       - 4.0～6.0: "moderate"
       - 6.0～8.0: "strong"
       - 8.0～10.0: "very_strong"
    7. 強度向上策の生成（スコアが8.0未満の場合）
    8. ログ出力（強度評価イベント、スコアとカテゴリのみ、鍵自体は非表示）
    9. 詳細な結果辞書の返却
    """
    pass
```

```python
def estimate_attack_complexity(key_data: bytes, attack_type: str, params: dict = None) -> dict:
    """
    特定の攻撃方法に対する鍵の攻撃複雑性（実効強度）を推定する

    Args:
        key_data: 評価する鍵データ（バイト列）
        attack_type: 攻撃タイプ識別子
          サポートされる攻撃タイプ:
          - "brute_force" - 総当たり攻撃
          - "dictionary" - 辞書攻撃
          - "rainbow_table" - レインボーテーブル攻撃
          - "side_channel" - サイドチャネル攻撃
          - "shor_algorithm" - Shorアルゴリズム（量子）
          - "grover_algorithm" - Groverアルゴリズム（量子）
          - "lattice_reduction" - 格子基底簡約攻撃
          - "correlation" - 相関解析攻撃
          - "complementary_document" - 相補文書攻撃
        params: 攻撃パラメータ（省略可）
          例: {
            "computing_power": 1e12,  # 1秒あたりの演算回数
            "memory_limit": 1e15,  # 利用可能メモリ（バイト）
            "time_limit": 315360000,  # 時間制限（秒、デフォルト：10年）
            "quantum_qubits": 5000,  # 量子ビット数（量子攻撃の場合）
            "budget": 1e6  # 予算（USD）
          }

    Returns:
        攻撃複雑性推定結果を含む辞書
        {
          "feasible": bool,  # 現実的に実行可能かどうか
          "time_estimate": {  # 時間推定
            "seconds": float,  # 秒数
            "human_readable": str,  # 人間可読表現（例: "10.5年"）
          },
          "resources_required": {  # 必要リソース
            "computing_power": float,  # 必要計算能力
            "memory": float,  # 必要メモリ量
            "cost": float,  # 推定コスト
            ... 攻撃固有のリソース要件 ...
          },
          "comparative_difficulty": str,  # 比較難易度説明
          "effective_key_bits": int,  # この攻撃に対する実効鍵ビット数
          "confidence": float,  # 推定確信度（0.0～1.0）
          "mitigations": [str, ...],  # 対策推奨（あれば）
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: attack_typeが未サポートの場合
        ValueError: paramsに無効な値が含まれる場合

    実装詳細:
    1. 引数の検証（key_data非空、attack_typeのサポート確認）
    2. デフォルトパラメータの設定（省略された場合）
    3. 鍵特性の抽出（エントロピー、長さなど）
    4. 攻撃タイプに応じた計算:
       - "brute_force": 総当たり攻撃の計算量計算
       - "dictionary": 辞書攻撃の成功確率と必要辞書サイズ推定
       - "rainbow_table": メモリ・時間トレードオフ分析
       - "side_channel": サイドチャネル漏洩可能性と必要測定回数の推定
       - "shor_algorithm": 量子ビット数と量子ゲート深度の推定
       - "grover_algorithm": 量子探索の平方根高速化を考慮した計算量推定
       - "lattice_reduction": LLL/BKZ計算量の推定
       - "correlation": 相関分析に必要なサンプル数と計算量の推定
       - "complementary_document": 相補文書攻撃の成功確率とサンプル要件
    5. 攻撃の実行可能性判定
    6. 時間・リソース要件の詳細計算
    7. 対策推奨事項の生成（実行可能と判定された場合）
    8. ログ出力（攻撃複雑性評価イベント、攻撃タイプと結果概要のみ）
    9. 詳細な結果辞書の返却
    """
    pass

def rate_key_against_standards(key_data: bytes, standard_name: str, params: dict = None) -> dict:
    """
    特定のセキュリティ標準規格に対する鍵の適合性を評価する

    Args:
        key_data: 評価する鍵データ（バイト列）
        standard_name: セキュリティ標準規格識別子
          サポートされる標準規格:
          - "nist_sp800_57" - NIST SP 800-57鍵管理推奨
          - "nist_sp800_131a" - NIST SP 800-131A暗号アルゴリズム移行推奨
          - "iso_19790" - ISO/IEC 19790暗号モジュール要件
          - "fips_140_3" - FIPS 140-3セキュリティ要件
          - "pci_dss" - PCI DSS暗号要件
          - "project_internal" - プロジェクト内部標準（Tri-Fusionシステム用）
        params: 評価パラメータ（省略可）
          例: {
            "target_date": "2030-01-01",  # 目標適合日
            "classification": "top_secret",  # 情報分類レベル
            "compliance_level": "strict"  # 準拠レベル（"relaxed", "normal", "strict"）
          }

    Returns:
        標準規格適合性評価結果を含む辞書
        {
          "compliant": bool,  # 標準規格に準拠しているか
          "standard_version": str,  # 評価に使用した標準規格のバージョン
          "rating": str,  # 評価カテゴリ（"non_compliant", "minimum", "recommended", "future_proof"）
          "score": float,  # 準拠スコア（0.0～10.0）
          "requirements": [  # 標準規格要件リスト
            {
              "id": str,  # 要件ID
              "description": str,  # 要件説明
              "met": bool,  # 要件を満たしているか
              "importance": str,  # 重要度（"mandatory", "recommended", "optional"）
              "notes": str,  # 詳細注記（該当時）
            },
            ... その他の要件 ...
          ],
          "issues": [str, ...],  # 不適合項目（あれば）
          "remediation": [str, ...],  # 是正措置推奨（あれば）
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: standard_nameが未サポートの場合
        ValueError: paramsに無効な値が含まれる場合

    実装詳細:
    1. 引数の検証（key_data非空、standard_nameのサポート確認）
    2. デフォルトパラメータの設定（省略された場合）
    3. 対象標準規格の要件セットの取得
    4. 鍵特性の評価:
       - アルゴリズム識別と特性抽出
       - 鍵長評価
       - 使用目的の確認
       - 有効期間の評価
       - 鍵導出メカニズムの評価（可能な場合）
    5. 各要件に対する適合性評価
    6. 全体的な準拠判定と評価カテゴリの決定
    7. 準拠スコアの計算（要件の重み付け合計）
    8. 不適合項目の特定と是正措置の推奨
    9. ログ出力（標準規格評価イベント、規格名と結果概要のみ）
    10. 詳細な結果辞書の返却
    """
    pass
```

#### 3. 鍵脆弱性検出機能（2 つの関数）

```python
def scan_for_key_vulnerabilities(key_data: bytes, scan_types: list = None) -> dict:
    """
    暗号鍵の既知の脆弱性パターンを検出する

    Args:
        key_data: 検査する鍵データ（バイト列）
        scan_types: 実行する脆弱性検査タイプのリスト（省略可）
          サポートされる検査タイプ:
          - "weak_patterns" - 弱い鍵パターン検出
          - "bias" - 統計的偏り検出
          - "predictable_structure" - 予測可能な構造検出
          - "entropy_gaps" - エントロピーギャップ検出
          - "algorithm_specific" - アルゴリズム固有の弱点検出
          - "campaign_vulnerabilities" - 第二回暗号解読キャンペーン脆弱性関連検出
          - "all" - すべての検査を実行（デフォルト）

    Returns:
        脆弱性検査結果を含む辞書
        {
          "vulnerabilities_found": bool,  # 脆弱性が見つかったか
          "risk_level": str,  # リスクレベル（"none", "low", "medium", "high", "critical"）
          "scan_summary": {  # 検査概要
            "total_checks": int,  # 実行された検査数
            "passed": int,  # 合格した検査数
            "failed": int,  # 失敗した検査数
            "warnings": int,  # 警告が発生した検査数
          },
          "issues": [  # 検出された問題のリスト
            {
              "type": str,  # 問題タイプ
              "severity": str,  # 深刻度
              "description": str,  # 問題の説明
              "affected_bits": [int, ...],  # 影響を受けるビット位置（該当時）
              "confidence": float,  # 検出確信度（0.0～1.0）
              "recommendations": [str, ...],  # 対策推奨
            },
            ... その他の問題 ...
          ],
          "warnings": [str, ...],  # 警告メッセージ（あれば）
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: scan_typesに未サポートの検査タイプが含まれる場合

    実装詳細:
    1. 引数の検証（key_data非空、scan_typesのサポート確認）
    2. デフォルト検査タイプの設定（省略された場合は"all"）
    3. 検査タイプに応じた脆弱性検出:
       - "weak_patterns": 既知の弱い鍵パターン検出
         - 固定パターン
         - 繰り返しパターン
         - 単調増減パターン
         - 既知の弱い鍵データベースとの比較
       - "bias": 統計的偏り検出
         - ビット分布偏り分析
         - バイト分布偏り分析
         - n-gram分布分析
       - "predictable_structure": 予測可能な構造検出
         - 周期性検出
         - 決定論的構造検出
         - 可逆性解析
       - "entropy_gaps": エントロピーギャップ検出
         - 局所エントロピー解析
         - エントロピー落ち込み検出
         - エントロピー損失推定
       - "algorithm_specific": アルゴリズム固有の弱点検出
         - 鍵形式から推定されるアルゴリズムに基づく分析
         - アルゴリズム固有の既知弱点パターン検出
       - "campaign_vulnerabilities": 暗号解読キャンペーン脆弱性関連検出
         - 固定シード値痕跡の検出
         - 経路情報漏洩パターン検出
         - 予測可能なパディングパターン検出
    4. 各検査の結果集約とリスクレベル判定
    5. 問題の重大度に基づいた推奨対策の生成
    6. ログ出力（脆弱性検査イベント、検出結果概要のみ、鍵自体は非表示）
    7. 詳細な結果辞書の返却
    """
    pass

def validate_key_resilience(key_data: bytes, resilience_types: list = None, params: dict = None) -> dict:
    """
    特定のセキュリティ脅威に対する鍵の耐性を検証する

    Args:
        key_data: 検証する鍵データ（バイト列）
        resilience_types: 検証する耐性タイプのリスト（省略可）
          サポートされる耐性タイプ:
          - "differential_analysis" - 差分解析耐性
          - "linear_analysis" - 線形解析耐性
          - "related_key" - 関連鍵攻撃耐性
          - "quantum_attack" - 量子攻撃耐性
          - "side_channel" - サイドチャネル攻撃耐性
          - "fault_injection" - 故障注入攻撃耐性
          - "complementary_document" - 相補文書攻撃耐性
          - "all" - すべての耐性を検証（デフォルト）
        params: 検証パラメータ（省略可）

    Returns:
        耐性検証結果を含む辞書
        {
          "overall_resilience": str,  # 総合耐性レベル（"very_low", "low", "medium", "high", "very_high"）
          "score": float,  # 総合耐性スコア（0.0～10.0）
          "resilience_breakdown": {  # 各耐性タイプの評価内訳
            "differential_analysis": {
              "level": str,  # 耐性レベル
              "score": float,  # 耐性スコア
              "details": str,  # 詳細説明
            },
            ... その他の耐性タイプ ...
          },
          "weak_points": [str, ...],  # 弱点（あれば）
          "improvement_suggestions": [str, ...],  # 改善提案（あれば）
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: resilience_typesに未サポートの耐性タイプが含まれる場合
        ValueError: paramsに無効な値が含まれる場合

    実装詳細:
    1. 引数の検証（key_data非空、resilience_typesのサポート確認）
    2. デフォルト耐性タイプの設定（省略された場合は"all"）
    3. 基本鍵特性の抽出（エントロピー、長さ、構造など）
    4. 各耐性タイプに対する評価:
       - "differential_analysis": 差分解析耐性評価
         - 差分伝播特性分析
         - S-box特性評価（該当時）
       - "linear_analysis": 線形解析耐性評価
         - 線形マスク相関分析
         - 線形バイアス評価
       - "related_key": 関連鍵攻撃耐性評価
         - 鍵スケジュール特性分析
         - 関連鍵差分評価
       - "quantum_attack": 量子攻撃耐性評価
         - Shorアルゴリズム耐性
         - Groverアルゴリズム耐性
         - 量子計算複雑性評価
       - "side_channel": サイドチャネル攻撃耐性評価
         - 実装独立性評価
         - 時間的一様性評価
         - 電力消費パターン予測
       - "fault_injection": 故障注入攻撃耐性評価
         - 鍵導出構造解析
         - 耐故障設計評価
       - "complementary_document": 相補文書攻撃耐性評価
         - 状態推測困難性評価
         - 統計的独立性検証
         - 格子基底直交性評価
    5. 各耐性スコアの計算と総合評価
    6. 弱点の特定と改善提案の生成
    7. ログ出力（耐性評価イベント、評価結果概要のみ、鍵自体は非表示）
    8. 詳細な結果辞書の返却
    """
    pass
```

#### 4. 鍵統計分析機能（2 つの関数）

```python
def analyze_key_entropy(key_data: bytes, analysis_method: str = "shannon") -> dict:
    """
    暗号鍵のエントロピー特性を詳細に分析する

    Args:
        key_data: 分析する鍵データ（バイト列）
        analysis_method: エントロピー分析手法
          サポートされる分析手法:
          - "shannon" - シャノンエントロピー（デフォルト）
          - "min_entropy" - 最小エントロピー
          - "hartley" - ハートレーエントロピー
          - "renyi" - レニーエントロピー
          - "all" - すべての手法でのエントロピー計算

    Returns:
        エントロピー分析結果を含む辞書
        {
          "entropy": float,  # 主要エントロピー値（ビット/バイト）
          "normalized_entropy": float,  # 正規化エントロピー（0.0～1.0）
          "entropy_per_byte": float,  # バイトあたりエントロピー
          "total_entropy_bits": float,  # 鍵全体のエントロピービット数
          "method": str,  # 使用された分析手法
          "ideal_entropy": float,  # 理想的なエントロピー値
          "entropy_quality": str,  # エントロピー品質評価
          "distribution_analysis": {  # 分布分析
            "most_common_byte": int,  # 最頻出バイト
            "least_common_byte": int,  # 最低頻出バイト
            "histogram": {...},  # バイト出現頻度ヒストグラム
            "uniformity_score": float,  # 一様性スコア（0.0～1.0）
          },
          "local_entropy": [float, ...],  # 局所エントロピー分析結果
          "additional_metrics": {  # 追加メトリクス（分析手法による）
            ... 手法固有のメトリクス ...
          },
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: analysis_methodが未サポートの場合

    実装詳細:
    1. 引数の検証（key_data非空、analysis_methodのサポート確認）
    2. 選択された分析手法に基づくエントロピー計算:
       - "shannon": シャノン情報エントロピー計算
       - "min_entropy": 最悪ケースシナリオのエントロピー計算
       - "hartley": 可能な状態数に基づくハートレーエントロピー計算
       - "renyi": パラメータ化されたレニーエントロピー計算
       - "all": すべての手法での計算と結果統合
    3. バイト出現頻度の詳細分析
    4. 局所エントロピー解析（鍵の異なる部分の変動評価）
    5. 理想値との比較と品質評価
    6. ログ出力（エントロピー分析イベント、結果概要のみ、鍵自体は非表示）
    7. 詳細な結果辞書の返却
    """
    pass

def analyze_key_statistics(key_data: bytes, tests: list = None) -> dict:
    """
    暗号鍵の詳細な統計的特性を分析する

    Args:
        key_data: 分析する鍵データ（バイト列）
        tests: 実行する統計テストのリスト（省略可）
          サポートされるテスト:
          - "frequency" - 頻度テスト
          - "block_frequency" - ブロック頻度テスト
          - "runs" - ランテスト
          - "longest_run" - 最長連続ビットランテスト
          - "binary_matrix_rank" - バイナリ行列ランクテスト
          - "dft" - 離散フーリエ変換テスト
          - "non_overlapping_template" - 非重複テンプレートマッチングテスト
          - "overlapping_template" - 重複テンプレートマッチングテスト
          - "correlation" - 相関テスト
          - "periodicity" - 周期性テスト
          - "all" - すべてのテストを実行（デフォルト）

    Returns:
        統計分析結果を含む辞書
        {
          "randomness_score": float,  # 総合ランダム性スコア（0.0～1.0）
          "overall_assessment": str,  # 総合評価（"random", "likely_random", "questionable", "non_random"）
          "p_value": float,  # 総合P値
          "test_results": {  # 各テストの結果
            "frequency": {
              "passed": bool,  # テスト合格判定
              "p_value": float,  # P値
              "statistic": float,  # テスト統計量
              "details": {...},  # テスト固有の詳細結果
            },
            ... その他のテスト ...
          },
          "patterns_detected": [  # 検出パターン（あれば）
            {
              "type": str,  # パターンタイプ
              "position": int,  # 開始位置
              "length": int,  # 長さ
              "description": str,  # 説明
            },
            ... その他のパターン ...
          ],
          "visualization_data": {...},  # 視覚化用データ
        }

    Raises:
        ValueError: key_dataが空または無効な場合
        ValueError: testsに未サポートのテストが含まれる場合

    実装詳細:
    1. 引数の検証（key_data非空、testsのサポート確認）
    2. デフォルトテストセットの設定（省略された場合は"all"）
    3. 選択されたテストの実行:
       - "frequency": 1と0の出現頻度が均等か検証
       - "block_frequency": ブロック内での1の頻度が均等か検証
       - "runs": 連続する同一ビットの数が期待通りか検証
       - "longest_run": 最長連続ビット列の長さが適切か検証
       - "binary_matrix_rank": バイナリ行列のランク分布特性検証
       - "dft": スペクトル解析による周波数分布の検証
       - "non_overlapping_template": 非重複特定パターンの出現頻度検証
       - "overlapping_template": 重複特定パターンの出現頻度検証
       - "correlation": 自己相関分析
       - "periodicity": 周期性探索と検証
    4. パターン検出アルゴリズムの適用（反復、単調性など）
    5. 各テスト結果の統合と総合評価の決定
    6. ランダム性スコアの計算（テスト結果の加重平均）
    7. 視覚化用データの準備（バイト分布、相関ヒートマップなど）
    8. ログ出力（統計分析イベント、結果概要のみ、鍵自体は非表示）
    9. 詳細な結果辞書の返却
    """
    pass
```

## 🔍 完了の定義

以下の基準をすべて満たすことで、このタスクは「完了」とみなされます：

1. **実装完了の条件**:

   - [ ] `utils/key/key_verification.py`が指定された仕様で実装されていること
   - [ ] ソースコードが単一責務の原則に従い、明確に構造化されていること
   - [ ] 全ての関数に適切なドキュメント（docstring）が付与されていること
   - [ ] コードレビューでの指摘事項がすべて解消されていること
   - [ ] 静的解析ツールによる警告がゼロであること

2. **機能完了の条件**:

   - [ ] 鍵品質検証機能が正確に動作し、鍵の品質を正しく評価できること
   - [ ] 鍵強度評価機能が正確に動作し、鍵の強度を客観的に評価できること
   - [ ] 鍵脆弱性検出機能が既知の脆弱性パターンを正確に検出できること
   - [ ] 鍵統計分析機能が鍵の統計的特性を正確に分析できること
   - [ ] T15（鍵管理基本機能）および T16（鍵保存・読込機能）と正しく連携して動作すること

3. **テスト完了の条件**:

   - [ ] 単体テストのカバレッジが 95%以上であること
   - [ ] 全関数の正常系・異常系のテストケースが実装されていること
   - [ ] エッジケース（極端に弱い鍵や極端に強い鍵など）のテストが実装されていること
   - [ ] 既知の脆弱性パターンに対する検出テストが実装されていること
   - [ ] T15（鍵管理基本機能）および T16（鍵保存・読込機能）との連携テストが実装されていること

4. **ドキュメント完了の条件**:

   - [ ] 実装した機能の詳細な技術ドキュメントが作成されていること
   - [ ] API 仕様とインターフェース説明が完成していること
   - [ ] 使用方法とサンプルコードが提供されていること
   - [ ] 評価メトリクスと解釈ガイドラインが文書化されていること
   - [ ] 後続タスク（T18、T19）との連携方法が説明されていること

5. **納品物件検証条件**:
   - [ ] 鍵品質検証機能の結果が暗号学的に正確であることが検証されていること
   - [ ] 鍵強度評価が現在の暗号理論と整合していることが検証されていること
   - [ ] 脆弱性検出機能が既知の弱い鍵パターンを検出できることが検証されていること
   - [ ] 統計分析機能が業界標準の統計テストと同等の結果を提供することが検証されていること
   - [ ] 第二回暗号解読キャンペーンで発見された脆弱性に関連する鍵の問題を検出できることが検証されていること

## 🧪 テスト対応方針

テスト実装と実行においては以下の方針を厳守してください：

1. **テストの意義**:

   - テストはプロジェクト品質を保証する重要な手段です
   - テストを欺くことは品質の放棄を意味します
   - UNDER NO CIRCUMSTANCES should the test files be modified to make failures pass

2. **テスト実装要件**:

   - 各機能のテストは `tests/utils/key/test_key_verification.py` に実装します
   - ユニットテストはモジュールの公開インターフェースに焦点を当て、内部実装の詳細に依存しないようにします
   - モック（T5 量子乱数など）を適切に使用して依存関係を制御します
   - 肯定的なケース（正常系）と否定的なケース（異常系）の両方をテストします
   - 境界値と極端なケースについても考慮します

3. **鍵品質検証機能のテスト**:

   - 既知の高品質な鍵と低品質な鍵の両方でテストを行います
   - 検証要件のバリエーションをテストします
   - 無効なパラメータでの例外処理をテストします
   - 数学的特性検証の正確性を独立に検証します

4. **鍵強度評価機能のテスト**:

   - 強度スコアの一貫性と再現性をテストします
   - 同じ鍵に対して異なるコンテキストでの評価結果を検証します
   - 異なる攻撃タイプに対する複雑性推定の妥当性をテストします
   - 様々なセキュリティ標準に対する評価の整合性をテストします

5. **鍵脆弱性検出機能のテスト**:

   - 既知の脆弱性パターンを含む鍵が正しく検出されることをテストします
   - 誤検出（false positive）と検出漏れ（false negative）のバランスをテストします
   - 様々な検査タイプとパラメータの組み合わせをテストします
   - 攻撃耐性評価の一貫性をテストします

6. **鍵統計分析機能のテスト**:

   - エントロピー計算の正確性を検証します（既知の値と比較）
   - 統計テストが NIST SP 800-22 などの標準と一致することを検証します
   - 様々な統計的特性を持つ鍵のサンプルで一貫した結果が得られることを検証します
   - 異なる分析手法による結果の整合性をテストします

7. **テスト環境構築**:

   - テスト用の鍵データの生成方法:
     - 高品質鍵サンプル（真の乱数源から生成）
     - 低品質鍵サンプル（エントロピーが低い、パターンが含まれるなど）
     - 既知の脆弱性を持つ鍵サンプル（特定のパターン、統計的偏りなど）
     - 標準的な鍵サンプル（中程度の品質）
   - 環境変数 `TEST_MODE=True` を設定して T5 量子乱数の代わりにテスト用の決定論的乱数を使用するテストモードを導入します
   - テスト実行の高速化のため、処理量が多いテストには適切なタイムアウトを設定します

8. **テスト実行**:
   - テストは自動 CI/CD パイプラインで実行されます
   - すべてのテストが通過するまでタスクは完了とみなされません
   - テストケースには説明的な名前と十分なドキュメントが必要です
   - 異常系テストではエラーメッセージも検証します

## 💎 タスク実装における重要原則

以下の原則を厳守してください。これらは、システム全体の整合性と安全性を確保するために不可欠です：

### 1. タスク境界の厳守

- 担当タスク外のモジュール（`utils/key/key_rotation.py`など）は絶対に変更しないでください
- 実装に必要なインターフェースが不足している場合は、作業を中断し報告してください
- 仕様に明示されていない機能や最適化は追加しないでください

### 2. テスト改ざんの禁止

- テストを単に通過させるための実装は避けてください
- テストファイルの変更は認められません
- テストの精神を尊重し、真に仕様を満たす実装を心がけてください

### 3. プロジェクト整合性の維持

- 既存のコードスタイルとアーキテクチャに従ってください
- 依存関係は明示的に文書化してください
- グローバル状態への依存は避け、モジュール間の結合は疎にしてください

### 4. 問題発生時の作業中断

- 実装中に矛盾、セキュリティ問題、設計上の懸念を発見した場合は作業を中断してください
- プロジェクトのセキュリティと整合性は個々のタスクの期限より優先されます
- 問題の性質と影響範囲を文書化して報告してください

## 📚 参考資料

実装に際して以下の参考資料を活用してください：

1. **暗号学的基準**:

   - NIST SP 800-57: 鍵管理推奨事項
   - NIST SP 800-90B: エントロピー源の推奨事項
   - NIST SP 800-22: 乱数発生器の統計的テスト

2. **数学的評価**:

   - 格子基底の直交性評価手法
   - 同型写像の非周期性分析
   - 相関耐性の数学的証明手法

3. **脆弱性と攻撃**:

   - 第二回暗号解読キャンペーン結果報告書
   - 相補文書推測攻撃の理論と対策
   - 量子計算機による暗号解読アルゴリズム

4. **プロジェクト固有資料**:
   - Tri-Fusion アーキテクチャ仕様
   - プロジェクト鍵品質基準
   - 暗号解読不能性証明フレームワーク

## 📋 デモンストレーション・検証情報

本タスク完了後、以下の検証が実施できる必要があります：

1. 様々な暗号鍵の品質を検証し、その結果を説明するデモ
2. 異なる攻撃モデルに対する鍵の強度評価とその意味の解説
3. 意図的に弱点を導入した鍵に対する脆弱性検出のデモンストレーション
4. 統計分析結果の視覚化と解釈ガイド

検証ツールとテストスクリプトがこの目的のために提供されます。

## 📑 関連資料

- **実装計画書**: `/docs/method_11_rabbit_homomorphic_docs/implementation_plan_chapters/04_implementation_details.md`
- **フェーズ 0 詳細**: `/docs/method_11_rabbit_homomorphic_docs/implementation_plan_chapters/04_implementation_details.md#フェーズ-0-実装準備4-週間`
- **ディレクトリ構成**: `/docs/method_11_rabbit_homomorphic_docs/implementation_plan_chapters/02_directory_structure_and_deliverables.md`
- **品質レベル規定**: `/docs/method_11_rabbit_homomorphic_docs/implementation_plan_chapters/05_quality_and_security.md`
- **システム設計とアーキテクチャ**: `/docs/method_11_rabbit_homomorphic_docs/implementation_plan_chapters/03_system_design_and_architecture.md`
- **前タスク：T16**: `/docs/method_11_rabbit_homomorphic_docs/issue/T16_key_storage_implementation.md`
- **前々タスク：T15**: `/docs/method_11_rabbit_homomorphic_docs/issue/T15_key_manager_implementation.md`
- **次タスク：T18 の予定タスク説明**: `/docs/method_11_rabbit_homomorphic_docs/implementation_plan_chapters/04_implementation_details.md`

---

この実装指示書に従って、鍵検証・強度評価機能を実装してください。タイムライン上の次のタスクは T18（鍵ローテーション実装）であり、このタスクの機能と緊密に連携する必要があります。
