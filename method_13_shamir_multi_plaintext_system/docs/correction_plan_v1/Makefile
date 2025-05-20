# 修正プロンプト生成用Makefile

# 出力ファイル名
OUTPUT = prompt.md

# 入力ファイル
CHAPTERS = chapter_00_intro.md \
           chapter_01_partition_key.md \
           chapter_02_map_generation.md \
           chapter_03_update_process.md \
           chapter_04_share_id_space.md \
           chapter_05_file_format.md \
           chapter_06_testing.md

# 全てのファイルを結合してプロンプトを生成
all: $(OUTPUT)

$(OUTPUT): $(CHAPTERS)
	@echo "修正プロンプトファイルを生成しています..."
	@cat $(CHAPTERS) > $(OUTPUT)
	@echo "完了しました。$(OUTPUT)が作成されました。"

# 個別のチャプターを生成（ダミーターゲット）
chapters: $(CHAPTERS)

# 全てを削除
clean:
	@rm -f $(OUTPUT)

.PHONY: all chapters clean