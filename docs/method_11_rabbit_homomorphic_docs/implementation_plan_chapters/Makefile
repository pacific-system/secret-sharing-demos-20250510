# ラビット＋準同型マスキング暗号プロセッサ 実装計画ドキュメント結合用Makefile

.PHONY: all clean implementation verify backup

# 実装計画ドキュメントの章ファイル - 新しい章構成
IMPLEMENTATION_CHAPTERS := 01_overview_and_profile.md \
	02_directory_structure_and_deliverables.md \
	03_system_design_and_architecture.md \
	04_sequence_diagram.md \
	05_implementation_details.md \
	06_quality_and_security.md \
	07_implementation_strategy_optimization.md

# ターゲットファイル
IMPLEMENTATION_TARGET := ../implementation_plan.md

# タイムスタンプ
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

all: backup implementation verify

# バックアップの作成
backup:
	@echo "バックアップを作成しています..."
	@mkdir -p ../backups
	@if [ -f $(IMPLEMENTATION_TARGET) ]; then \
		cp $(IMPLEMENTATION_TARGET) ../backups/implementation_plan.md.$(TIMESTAMP); \
		echo "バックアップが完了しました: ../backups/implementation_plan.md.$(TIMESTAMP)"; \
	fi

# 実装計画ドキュメントの結合
implementation: $(IMPLEMENTATION_TARGET)

$(IMPLEMENTATION_TARGET): $(IMPLEMENTATION_CHAPTERS)
	@echo "実装計画ドキュメントを結合しています..."
	@cat $(IMPLEMENTATION_CHAPTERS) > $(IMPLEMENTATION_TARGET)
	@echo "実装計画ドキュメントの結合が完了しました。"

# 検証: 章の数とオリジナルファイルの行数を比較
verify:
	@echo "ドキュメント検証を実行しています..."
	@echo "実装計画: $(words $(IMPLEMENTATION_CHAPTERS))つの章に分割されています。"
	@wc -l $(IMPLEMENTATION_TARGET)
	@echo "検証完了。"

# クリーンアップ (一時ファイルのみ削除)
clean:
	@echo "一時ファイルを削除しています..."
	@echo "注: 生成された結合ファイルとバックアップは保持されます"
	@rm -f *.tmp *.bak
	@echo "クリーンアップ完了。"
