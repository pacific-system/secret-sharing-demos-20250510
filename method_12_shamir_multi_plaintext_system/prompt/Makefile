# シャミア秘密分散法による複数平文復号システム - プロンプト生成

# 各プロンプトファイル
PROMPT_FILES = 00_overview.md 01_encryption.md 02_decryption.md 03_update.md 04_cli.md

# 出力ファイル
OUTPUT_FILE = complete_prompt.md

# デフォルトターゲット
all: $(OUTPUT_FILE)

# 全プロンプトを結合
$(OUTPUT_FILE): $(PROMPT_FILES)
	@echo "# シャミア秘密分散法による複数平文復号システム - 実装プロンプト" > $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "## 実装者のペルソナ" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "あなたは暗号学とセキュアコーディングに精通した優秀なPython開発者です。" >> $(OUTPUT_FILE)
	@echo "シャミア秘密分散法に関する深い知識を持ち、セキュリティシステムの実装経験が豊富です。" >> $(OUTPUT_FILE)
	@echo "「統計的区別不可能性」「定数時間処理」「サイドチャネル攻撃への対策」などの概念を熟知しています。" >> $(OUTPUT_FILE)
	@echo "また、Pythonにおけるベストプラクティスを遵守し、効率的で保守性の高いコードを作成します。" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "以下の設計に基づいて、シャミア秘密分散法による複数平文復号システムをPythonで実装してください。" >> $(OUTPUT_FILE)
	@echo "システムの核心は「複数の平文を単一の暗号ファイルに格納し、別々のパスワードでそれぞれ復号可能にする」ことです。" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "---" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@cat $(PROMPT_FILES) >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "---" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "## 実装の追加指示" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "1. このシステムは情報理論的安全性を持つよう設計されています。すべての実装においてこの原則に忠実であることが最重要です。" >> $(OUTPUT_FILE)
	@echo "2. タイミング攻撃を防ぐため、条件分岐の禁止と定数時間処理は絶対に守ってください。" >> $(OUTPUT_FILE)
	@echo "3. 暗号処理において、設計書にあるアルゴリズムから逸脱しないでください。" >> $(OUTPUT_FILE)
	@echo "4. 「正しいパスワードによる復号」に見せかけたバックドアを仕掛けないでください。" >> $(OUTPUT_FILE)
	@echo "5. 「統計的区別不可能性」を確保するためのA/B/未割当シェア分布を維持してください。" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "実装を開始してください。モジュール分割と正しいインポート関係を考慮したファイル構成から検討することをお勧めします。" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "備考：このシステムの主要な技術的特徴（多段MAP方式とシャミアベースの多重復号）は、研究目的での実装です。" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "制約条件：すべての原則を守りつつ実現できない場合は、何が達成できて何が難しいかを説明してください。" >> $(OUTPUT_FILE)
	@echo "その際、セキュリティの実現が最優先です。機能を制限してでもセキュリティ原則を守ってください。" >> $(OUTPUT_FILE)
	@echo "" >> $(OUTPUT_FILE)
	@echo "実装完了後は、コードの概要と使用方法を簡潔に説明してください。" >> $(OUTPUT_FILE)

	@echo "Complete prompt generated: $(OUTPUT_FILE)"

# クリーンアップ
clean:
	rm -f $(OUTPUT_FILE)

.PHONY: all clean