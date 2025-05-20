# シャミア秘密分散法による複数平文復号システム設計書 - ビルドスクリプト

# 各チャプターファイル（指定された順序で記載）
CHAPTER_FILES = 00_terms.md \
                01_overview.md \
                03_detailed_design.md \
                04_implementation.md \
                05_security.md \
                06_performance.md \
                07_guidelines.md \
                08_references.md \
                09_conclusion.md

# 出力ファイル
OUTPUT_FILE = ../shamir_multiple_plaintext_design_20240520.md

# デフォルトターゲット
.PHONY: all
all: $(OUTPUT_FILE)

# 設計書の生成
$(OUTPUT_FILE): $(CHAPTER_FILES)
	@echo "設計書を生成しています: $(OUTPUT_FILE)"
	@cat $(CHAPTER_FILES) > $(OUTPUT_FILE)
	@echo "生成完了しました！"

# クリーンアップ
.PHONY: clean
clean:
	@echo "出力ファイルを削除しています..."
	@rm -f $(OUTPUT_FILE)
	@echo "削除完了しました！"