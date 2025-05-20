# 初期化改修ドキュメント生成用Makefile

# 変数定義
DOCS_DIR := .
OUTPUT_DIR := ../../output/docs
MERGED_MD := $(OUTPUT_DIR)/encryption_optimization_full.md
HTML_OUTPUT := $(OUTPUT_DIR)/encryption_optimization_full.html

# デフォルトターゲット (PDFなし)
all: create_output_dir merge_md

# 出力ディレクトリの作成
create_output_dir:
	@mkdir -p $(OUTPUT_DIR)

# すべてのMarkdownファイルを結合して一つのMarkdownに
merge_md: create_output_dir
	@echo "Merging all markdown files into single markdown"
	@echo "# シャミア暗号化システム改善計画\n\n" > $(MERGED_MD)
	@echo "## はじめに\n\n" >> $(MERGED_MD)
	@echo "このドキュメントは、シャミア秘密分散法による複数平文復号システムの初期化処理と暗号化ファイルフォーマットを改善するための計画書です。システムは暗号書庫として機能し、ファイル A とファイル B が同一の暗号ファイル内に混在して保管されます。このシステムの設計では、**ファイル種別ごとに1つのファイルしか暗号化できない**（ファイル A は1つ、ファイル B は1つ）という制約があります。\n\n" >> $(MERGED_MD)
	@echo "## 目次\n\n" >> $(MERGED_MD)
	@echo "1. [初期化時の暗号化ファイル生成に関する課題](#1-初期化時の暗号化ファイル生成に関する課題)" >> $(MERGED_MD)
	@echo "2. [初期化時の暗号化ファイル生成改善](#2-初期化時の暗号化ファイル生成改善)" >> $(MERGED_MD)
	@echo "3. [シェアフォーマットの最適化](#3-シェアフォーマットの最適化)" >> $(MERGED_MD)
	@echo "4. [UUIDを使用したファイル命名規則](#4-uuidを使用したファイル命名規則)" >> $(MERGED_MD)
	@echo "5. [実装計画と優先順位](#5-実装計画と優先順位)\n\n" >> $(MERGED_MD)
	@cat $(DOCS_DIR)/01_problem_statement.md | sed 's/^# /## 1. /' >> $(MERGED_MD)
	@echo "\n\n" >> $(MERGED_MD)
	@cat $(DOCS_DIR)/02_init_file_generation.md | sed 's/^# /## 2. /' >> $(MERGED_MD)
	@echo "\n\n" >> $(MERGED_MD)
	@cat $(DOCS_DIR)/03_share_format_improvement.md | sed 's/^# /## 3. /' >> $(MERGED_MD)
	@echo "\n\n" >> $(MERGED_MD)
	@cat $(DOCS_DIR)/04_uuid_file_naming.md | sed 's/^# /## 4. /' >> $(MERGED_MD)
	@echo "\n\n" >> $(MERGED_MD)
	@cat $(DOCS_DIR)/05_implementation_plan.md | sed 's/^# /## 5. /' >> $(MERGED_MD)
	@echo "\n\n## 結論\n\nこの改善計画では、シャミア秘密分散法による複数平文暗号化システムの初期化プロセスと暗号化ファイルのフォーマットを改善します。システムは暗号書庫として機能し、ファイル A とファイル B が同一の暗号ファイル内に混在して保管されます。この設計上の制約として、**ファイル種別ごとに1つのファイルしか暗号化できない**（ファイル A は1つ、ファイル B は1つ）ことを明示的に実装し、設計理念との一貫性を確保します。また、初期化ファイルと暗号化済みファイルが外部から区別できないようファイル構造とヘッダー情報を統一することで、システムのセキュリティと効率性が向上し、情報漏洩リスクが低減します。" >> $(MERGED_MD)
	@echo "\n\nMarkdown generated at $(MERGED_MD)"

# HTMLファイルの生成 (pandocに依存)
html: create_output_dir merge_md
	@echo "Generating HTML documentation (requires pandoc)"
	@if command -v pandoc >/dev/null 2>&1; then \
		pandoc $(MERGED_MD) \
		-o $(HTML_OUTPUT) \
		--standalone \
		--toc \
		--css=github-markdown.css \
		--highlight-style=github \
		--metadata title="シャミア暗号化システム改善計画"; \
		echo "HTML generated at $(HTML_OUTPUT)"; \
	else \
		echo "pandoc command not found. Skipping HTML generation."; \
	fi

# テスト実行ターゲットの追加
test_encrypted_format:
	@echo "Testing encrypted format implementation"
	python -m unittest tests/test_formats.py::TestFileFormats::test_encrypted_format

test_empty_file:
	@echo "Testing empty encrypted file generation"
	python -m unittest tests/test_init.py::TestInitialization::test_empty_file_generation

test_uuid_naming:
	@echo "Testing UUID file naming"
	python -m unittest tests/test_utils.py::TestUtilities::test_unique_filename

test_user_constraint:
	@echo "Testing user constraint implementation"
	python -m unittest tests/test_constraints.py::TestUserConstraints::test_one_file_per_user

test_all: test_encrypted_format test_empty_file test_uuid_naming test_user_constraint

# 実装テンプレート生成
generate_templates:
	@echo "Generating implementation templates"
	@mkdir -p shamir/formats
	@mkdir -p tests/formats
	@echo "# 暗号化形式の実装テンプレート" > shamir/formats/__init__.py
	@echo "# 暗号化形式のテストテンプレート" > tests/formats/__init__.py

# クリーンアップ
clean:
	@echo "Cleaning up generated files"
	@rm -rf $(OUTPUT_DIR)

.PHONY: all clean merge_md html create_output_dir test_encrypted_format test_empty_file test_uuid_naming test_user_constraint test_all generate_templates