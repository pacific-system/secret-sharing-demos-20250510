# シャミア秘密分散法による複数平文復号システム設計書のMakefile

OUTPUT_DIR = .
OUTPUT_FILE = $(OUTPUT_DIR)/shamir_multiple_plaintext_design.md
CHAPTERS_DIR = chapters
CHAPTERS = $(CHAPTERS_DIR)/01_overview.md \
           $(CHAPTERS_DIR)/02_architecture.md \
           $(CHAPTERS_DIR)/03_detailed_design.md \
           $(CHAPTERS_DIR)/04_security_analysis.md \
           $(CHAPTERS_DIR)/05_performance.md \
           $(CHAPTERS_DIR)/06_implementation.md \
           $(CHAPTERS_DIR)/07_references.md \
           $(CHAPTERS_DIR)/08_conclusion.md

.PHONY: all clean

all: $(OUTPUT_FILE)

$(OUTPUT_FILE): $(CHAPTERS)
	@echo "結合中: $(OUTPUT_FILE)"
	@cat $^ > $@
	@echo "タイムスタンプを付与: $(OUTPUT_FILE) -> $(OUTPUT_FILE:%.md=%_$(shell date +%Y%m%d).md)"
	@cp $@ $(OUTPUT_FILE:%.md=%_$(shell date +%Y%m%d).md)
	@echo "完了しました"

# 個別のチャプターファイルを編集した後でもファイル名を維持
$(CHAPTERS_DIR)/%.md:
	@if [ ! -f $@ ]; then \
		echo "チャプターファイルが存在しません: $@"; \
		exit 1; \
	fi

clean:
	@echo "出力ファイルを削除中..."
	@rm -f $(OUTPUT_FILE)
	@echo "削除完了"

# 既存のファイルを分割するためのユーティリティターゲット
split:
	@echo "既存のファイルをチャプターに分割中..."
	@mkdir -p $(CHAPTERS_DIR)
	@csplit -f "$(CHAPTERS_DIR)/chapter_" $(OUTPUT_FILE) '/^## [0-9]/' '{*}' > /dev/null 2>&1 || true
	@echo "分割完了。以下のファイルを $(CHAPTERS_DIR)/ ディレクトリに作成しました:"
	@ls -1 $(CHAPTERS_DIR)/chapter_*
	@echo "ファイル名を適切にリネームしてください"

help:
	@echo "シャミア秘密分散法による複数平文復号システム設計書ビルドツール"
	@echo ""
	@echo "利用可能なコマンド:"
	@echo "  make           - チャプターファイルを結合して設計書を生成"
	@echo "  make clean     - 生成された設計書を削除"
	@echo "  make split     - 既存の設計書をチャプターファイルに分割"
	@echo "  make help      - このヘルプメッセージを表示"
