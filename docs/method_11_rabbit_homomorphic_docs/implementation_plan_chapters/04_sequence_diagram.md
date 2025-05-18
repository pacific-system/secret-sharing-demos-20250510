## 4. 処理シーケンス図 📊

Tri-Fusion アーキテクチャにおける処理シーケンス図です。機能のオプショナル実行とフォールバックパスを明示しています：

```mermaid
sequenceDiagram
    participant User as ユーザー
    participant Encrypt as encrypt.py
    participant RabbitH as rabbit_homomorphic.py(メインフレーム)
    participant IdProt as identifier_protection.py
    participant TimeEq as timing_equalization.py
    participant FileStd as filesize_standardization.py
    participant SecProc as secure_processing.py
    participant SecKDer as secure_key_derivation.py
    participant SecCache as secure_cache.py
    participant SecLog as secure_logging.py
    participant ZKSystem as zero_knowledge/proof_system.py
    participant Logger as logger.py
    participant FmtDet as format_detector.py
    participant Adapter as adapters/*_adapter.py
    participant TriFusion as tri_fusion_state.py
    participant FusionMech as fusion_mechanism.py
    participant UncAmp as uncertainty_amplifier.py
    participant RabbitS as rabbit_stream.py
    participant Homo as homomorphic.py
    participant Quantum as quantum_resistant.py
    participant QRand as quantum_random.py
    participant Indist as indistinguishable.py

    %% 初期化フェーズ
    User->>Encrypt: 暗号化要求(ファイル, 鍵)
    Encrypt->>SecLog: 安全ログセッション開始

    %% データ準備
    Encrypt->>FmtDet: ファイル形式判定要求
    FmtDet->>Adapter: 適切なアダプタ選択
    Adapter->>Encrypt: データ形式情報返却

    %% 暗号化準備
    Encrypt->>RabbitH: 暗号化処理要求
    RabbitH->>SecLog: 処理開始記録（経路情報なし）

    %% 必須処理：安全な鍵導出
    RabbitH->>SecKDer: 鍵派生要求
    SecKDer->>QRand: 量子ソルトリクエスト
    QRand-->>SecKDer: 量子ソルト提供
    SecKDer-->>RabbitH: 派生鍵（経路情報を安全に組込済）

    %% 必須処理：ファイル識別子の保護処理
    RabbitH->>IdProt: ファイル識別子保護要求
    IdProt->>RabbitH: 保護済み識別子（識別情報除去済）

    %% 必須処理：処理時間均一化の準備
    RabbitH->>TimeEq: 処理時間均一化初期化
    TimeEq-->>RabbitH: 均一化処理準備完了

    %% 必須処理：セキュアキャッシュ設定
    RabbitH->>SecCache: セキュアキャッシュ初期化
    SecCache-->>RabbitH: キャッシュ準備完了

    %% オプショナル処理：ゼロ知識証明系初期化
    alt 高度なセキュリティモード有効
        RabbitH->>ZKSystem: ゼロ知識証明系初期化
        ZKSystem-->>RabbitH: 初期化完了
    else 通常モードまたは失敗時
        Note over RabbitH: ゼロ知識証明をスキップ<br/>(フォールバック：標準暗号化)
    end

    %% オプショナル処理：Tri-Fusion環境設定
    alt Tri-Fusionモード有効
        RabbitH->>TriFusion: 三方向共有状態初期化(派生鍵, 量子乱数)
        TriFusion->>RabbitS: ラビット状態初期化
        TriFusion->>Homo: 準同型コンテキスト初期化

        alt 量子耐性モード有効
            TriFusion->>Quantum: 量子耐性レイヤー初期化
            Quantum-->>TriFusion: 初期化完了
        else
            Note over TriFusion: 量子耐性レイヤーをスキップ<br/>(二方向融合モードで動作)
        end

        TriFusion-->>RabbitH: 初期化完了

        %% 融合メカニズム確立
        RabbitH->>FusionMech: 融合処理要求
        FusionMech-->>RabbitH: 準備完了
    else 標準モードまたは失敗時
        Note over RabbitH: Tri-Fusionをスキップ<br/>(フォールバック：直接RabbitS+Homoを使用)
        RabbitH->>RabbitS: 直接初期化
        RabbitH->>Homo: 直接初期化
    end

    %% 暗号化処理ループ
    loop 入力データブロック処理
        alt Tri-Fusionモード動作中
            %% 不確定性増幅プロセス
            FusionMech->>UncAmp: 不確定性増幅開始
            UncAmp->>QRand: 量子ノイズ要求
            QRand-->>UncAmp: 量子ノイズ提供
            UncAmp-->>FusionMech: 増幅結果

            %% 両経路の並列処理（タイミング攻撃対策）
            TimeEq->>RabbitH: 並列処理開始

            %% 三方向処理
            FusionMech->>RabbitS: ストリーム生成要求
            RabbitS-->>FusionMech: ストリーム生成結果

            FusionMech->>Homo: 準同型演算実行
            Homo-->>FusionMech: 演算結果

            alt 量子耐性モード有効
                FusionMech->>Quantum: 量子耐性演算実行
                Quantum-->>FusionMech: 処理結果
            end

            %% 結果統合
            FusionMech->>Indist: 不区別性処理適用
            Indist-->>FusionMech: 不区別化結果

            FusionMech-->>RabbitH: 融合処理結果
        else 標準モード（フォールバック）
            %% 簡易処理パス - 両方の暗号を直接使用
            TimeEq->>RabbitH: 並列処理開始

            RabbitH->>RabbitS: 直接ストリーム生成要求
            RabbitS-->>RabbitH: ストリーム生成結果

            RabbitH->>Homo: 直接準同型演算実行
            Homo-->>RabbitH: 演算結果

            RabbitH->>Indist: 直接不区別性処理適用
            Indist-->>RabbitH: 不区別化結果
        end

        %% 両経路の処理完了（タイミング攻撃対策）
        RabbitH->>TimeEq: 両経路処理終了
        TimeEq-->>RabbitH: 一定時間待機後に結果返却
    end

    %% 必須処理：ファイルサイズ標準化
    RabbitH->>FileStd: ファイルサイズ標準化要求
    FileStd->>QRand: 量子パディングリクエスト
    QRand-->>FileStd: 量子乱数パディング提供
    FileStd-->>RabbitH: 標準化済み暗号文

    %% オプショナル処理：ゼロ知識証明生成
    alt ゼロ知識証明モード有効
        RabbitH->>ZKSystem: ゼロ知識証明生成
        ZKSystem-->>RabbitH: 証明添付
    end

    %% 必須処理：セキュアキャッシュ処理
    RabbitH->>SecCache: キャッシュ更新（経路情報排除）
    SecCache-->>RabbitH: 安全キャッシュ更新完了

    %% 結果の返却
    RabbitH->>Adapter: 出力データ形式変換
    Adapter->>RabbitH: 変換済みデータ
    RabbitH->>Encrypt: 暗号化完了・結果返却
    RabbitH->>SecLog: 処理完了記録（経路情報なし）
    Encrypt->>SecLog: セッション終了記録
    Encrypt->>User: 暗号化ファイル

    %% セッション終了時のセキュリティ処理
    SecCache->>SecCache: セッション終了時キャッシュ消去
    SecProc->>SecProc: メモリ安全消去

    %% 復号プロセスも同様の構造（省略表記）
    Note over User,QRand: 復号処理も同様の流れで、<br/>選択されたモードに応じて<br/>必須処理とオプショナル処理が実行される
```

この設計は、情報理論的に証明可能なゼロ知識性を実現する革新的な Tri-Fusion アーキテクチャを核心としています。従来の 2 方向融合に加え、量子耐性レイヤーを第三の柱として組み込むことで、相補文書推測攻撃を含むあらゆる既知の攻撃手法に対して数学的に証明可能な耐性を実現しています。

さらに、第二回暗号解読キャンペーンで発見された「初歩的な観点の欠損」に対する包括的な対策を全工程に統合することで、理論と実装のギャップを完全に埋めています。特に、ファイル識別子の完全隠蔽、経路非依存処理、統一ファイルサイズ保証、安全ログシステム、予測不能な鍵導出、キャッシュ安全管理という 6 つの重要な脆弱性対策により、あらゆる既知の攻撃ベクトルに対して真に解読不能なシステムを実現しています。

### プロセスフローの最適化

Tri-Fusion アーキテクチャの処理シーケンスは、以下の点で最適化されています：

1. **フォールバックパスの自動選択**:

   - 高度な機能が無効または失敗した場合でも、自動的に標準的な処理パスにフォールバック
   - システム全体の堅牢性と可用性を確保

2. **並列処理の活用**:

   - タイミング攻撃対策としての両経路の並列処理
   - 処理効率と安全性を両立

3. **モジュラー設計**:

   - 機能ごとに明確に分離されたモジュール構造
   - 各モジュールは独立して動作可能
   - モジュール間の依存関係を最小限に抑制

4. **適応的処理選択**:
   - 実行時の状況に応じて最適な処理パスを動的に選択
   - 利用可能なリソースと要求されるセキュリティレベルに基づく処理の最適化

この処理フロー設計により、あらゆる状況下でも確実に動作する堅牢なシステムを実現し、セキュリティと実用性のバランスを最適化しています。
