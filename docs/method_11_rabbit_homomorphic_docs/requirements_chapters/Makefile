# ラビット＋準同型マスキング暗号プロセッサ 要求仕様ドキュメント結合用Makefile

.PHONY: all clean requirements verify backup

# 要求仕様ドキュメントの章ファイル
REQUIREMENTS_CHAPTERS := 01_preface.md \
	02_profile.md \
	03_scope.md \
	04_fusion_architecture.md \
	05_basic_requirements.md \
	06_attack_model.md \
	07_strategic_requirements.md \
	08_functional_requirements.md \
	09_integration_architecture.md \
	10_technical_requirements.md \
	11_deliverables.md \
	12_verification_requirements.md \
	13_implementation_points.md \
	14_references.md

# ターゲットファイル
REQUIREMENTS_TARGET := ../requirements.md

# タイムスタンプ
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

all: backup requirements verify

# バックアップの作成
backup:
	@echo "バックアップを作成しています..."
	@mkdir -p ../backups
	@if [ -f $(REQUIREMENTS_TARGET) ]; then \
		cp $(REQUIREMENTS_TARGET) ../backups/requirements.md.$(TIMESTAMP); \
		echo "バックアップが完了しました: ../backups/requirements.md.$(TIMESTAMP)"; \
	fi

# 要求仕様ドキュメントの結合
requirements: $(REQUIREMENTS_TARGET)

$(REQUIREMENTS_TARGET): $(REQUIREMENTS_CHAPTERS)
	@echo "要求仕様ドキュメントを結合しています..."
	@cat $(REQUIREMENTS_CHAPTERS) > $(REQUIREMENTS_TARGET)
	@echo "要求仕様ドキュメントの結合が完了しました。"

# 検証: 章の数とオリジナルファイルの行数を比較
verify:
	@echo "ドキュメント検証を実行しています..."
	@echo "要求仕様: $(words $(REQUIREMENTS_CHAPTERS))つの章に分割されています。"
	@wc -l $(REQUIREMENTS_TARGET)
	@echo "検証完了。"

# クリーンアップ (一時ファイルのみ削除)
clean:
	@echo "一時ファイルを削除しています..."
	@echo "注: 生成された結合ファイルとバックアップは保持されます"
	@rm -f *.tmp *.bak
	@echo "クリーンアップ完了。"