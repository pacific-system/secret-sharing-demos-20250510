# ラビット＋準同型マスキング暗号プロセッサ ドキュメント結合用Makefile

.PHONY: all clean implementation requirements verify backup

# 実装計画ドキュメントの章ファイル - 新しい章構成
IMPLEMENTATION_CHAPTERS := implementation_plan_chapters/01_overview_and_profile.md \
	implementation_plan_chapters/02_architecture_and_structure.md \
	implementation_plan_chapters/03_implementation_details.md \
	implementation_plan_chapters/04_quality_and_security.md

# 要求仕様ドキュメントの章ファイル
REQUIREMENTS_CHAPTERS := requirements_chapters/01_preface.md \
	requirements_chapters/02_profile.md \
	requirements_chapters/03_scope.md \
	requirements_chapters/04_fusion_architecture.md \
	requirements_chapters/05_basic_requirements.md \
	requirements_chapters/06_attack_model.md \
	requirements_chapters/07_strategic_requirements.md \
	requirements_chapters/08_functional_requirements.md \
	requirements_chapters/09_integration_architecture.md \
	requirements_chapters/10_technical_requirements.md \
	requirements_chapters/11_deliverables.md \
	requirements_chapters/12_verification_requirements.md \
	requirements_chapters/13_implementation_points.md \
	requirements_chapters/14_references.md

# ターゲットファイル
IMPLEMENTATION_TARGET := implementation_plan.md
REQUIREMENTS_TARGET := requirements.md

# タイムスタンプ
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

all: backup implementation requirements verify

# バックアップの作成
backup:
	@echo "バックアップを作成しています..."
	@mkdir -p backups
	@if [ -f $(IMPLEMENTATION_TARGET) ]; then \
		cp $(IMPLEMENTATION_TARGET) backups/$(IMPLEMENTATION_TARGET).$(TIMESTAMP); \
		echo "バックアップが完了しました: backups/$(IMPLEMENTATION_TARGET).$(TIMESTAMP)"; \
	fi
	@if [ -f $(REQUIREMENTS_TARGET) ]; then \
		cp $(REQUIREMENTS_TARGET) backups/$(REQUIREMENTS_TARGET).$(TIMESTAMP); \
		echo "バックアップが完了しました: backups/$(REQUIREMENTS_TARGET).$(TIMESTAMP)"; \
	fi

# 実装計画ドキュメントの結合
implementation: $(IMPLEMENTATION_TARGET)

$(IMPLEMENTATION_TARGET): $(IMPLEMENTATION_CHAPTERS)
	@echo "実装計画ドキュメントを結合しています..."
	@cat $(IMPLEMENTATION_CHAPTERS) > $(IMPLEMENTATION_TARGET)
	@echo "実装計画ドキュメントの結合が完了しました。"

# 要求仕様ドキュメントの結合
requirements: $(REQUIREMENTS_TARGET)

$(REQUIREMENTS_TARGET): $(REQUIREMENTS_CHAPTERS)
	@echo "要求仕様ドキュメントを結合しています..."
	@cat $(REQUIREMENTS_CHAPTERS) > $(REQUIREMENTS_TARGET)
	@echo "要求仕様ドキュメントの結合が完了しました。"

# 検証: 章の数とオリジナルファイルの行数を比較
verify:
	@echo "ドキュメント検証を実行しています..."
	@echo "実装計画: $(words $(IMPLEMENTATION_CHAPTERS))つの章に分割されています。"
	@echo "要求仕様: $(words $(REQUIREMENTS_CHAPTERS))つの章に分割されています。"
	@wc -l $(IMPLEMENTATION_TARGET) $(REQUIREMENTS_TARGET)
	@echo "検証完了。"

# クリーンアップ
clean:
	@echo "生成されたドキュメントを削除しています..."
	@rm -f $(IMPLEMENTATION_TARGET) $(REQUIREMENTS_TARGET)
	@echo "クリーンアップ完了。"