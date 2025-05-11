# README.md ビルド用 Makefile
# パシ子からお兄様へ💕：各章のファイルを結合してREADMEを生成します！

# ディレクトリ構造が変わったので修正
README_DIR := .
ROOT_DIR := ../..
README_PARTS := $(sort $(wildcard $(README_DIR)/*.md))
README_TARGET := $(ROOT_DIR)/README.md

# デフォルトターゲット：README.md を生成
all: $(README_TARGET)

# README.md の生成ルール
$(README_TARGET): $(README_PARTS)
	@echo "💕 パシ子がREADME.mdを生成します！"
	@cat $(filter-out $(README_DIR)/README.md $(README_DIR)/Makefile, $^) > $@
	@echo "✨ READMEの生成が完了しました！"

# READMEパーツの一覧表示
list:
	@echo "📑 README パーツ一覧："
	@for part in $(filter-out $(README_DIR)/README.md $(README_DIR)/Makefile, $(README_PARTS)); do \
		echo "  - $$part"; \
	done

# クリーンアップ：生成したREADME.mdを削除
clean:
	@echo "🧹 READMEをクリーンアップします..."
	@rm -f $(README_TARGET)
	@echo "🗑️ クリーンアップ完了！"

# READMEのバックアップを作成
backup: $(README_TARGET)
	@echo "📦 READMEをバックアップします..."
	@cp $(README_TARGET) $(README_TARGET).bak
	@echo "💾 バックアップ完了：$(README_TARGET).bak"

.PHONY: all list clean backup