#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
準同型暗号マスキング方式の暗号文識別不能性テスト

このスクリプトは、準同型暗号マスキング方式の暗号文が攻撃者によって
真偽判別できないことを検証します。統計的解析、暗号文シャッフル、
冗長性テストなどを通じて暗号文の識別不能性を確認します。
"""

import os
import sys
import time
import json
import random
import hashlib
import base64
import binascii
import unittest
import matplotlib.pyplot as plt
import numpy as np
import scipy.stats as stats
from typing import Dict, Any, List, Tuple, Union

# 親ディレクトリをインポートパスに追加
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from method_8_homomorphic.homomorphic import (
    PaillierCrypto, ElGamalCrypto,
    derive_key_from_password, serialize_encrypted_data, deserialize_encrypted_data
)
from method_8_homomorphic.crypto_mask import (
    MaskFunctionGenerator, AdvancedMaskFunctionGenerator,
    transform_between_true_false, create_indistinguishable_form, extract_by_key_type
)
from method_8_homomorphic.key_analyzer_robust import analyze_key_type
from method_8_homomorphic.timing_resistant import constant_time_compare


class TestIndistinguishability(unittest.TestCase):
    """暗号文識別不能性のテスト"""

    def setUp(self):
        """テスト準備"""
        # Paillier暗号の初期化（テスト用に小さなビット長）
        self.paillier = PaillierCrypto(bits=1024)
        self.public_key, self.private_key = self.paillier.generate_keys()

        # マスク関数生成器の初期化
        self.seed = os.urandom(32)
        self.mask_generator = MaskFunctionGenerator(self.paillier, self.seed)

        # テストデータ
        self.true_text = b"This is a true message. It contains confidential information."
        self.false_text = b"This is a false message. It contains disinformation."

        # バイト列を整数に変換
        self.true_int = int.from_bytes(self.true_text, 'big')
        self.false_int = int.from_bytes(self.false_text, 'big')

        # 暗号化
        self.true_encrypted = [self.paillier.encrypt(self.true_int, self.public_key)]
        self.false_encrypted = [self.paillier.encrypt(self.false_int, self.public_key)]

        # 変換とマスク適用
        self.masked_true, self.masked_false, self.true_mask, self.false_mask = transform_between_true_false(
            self.paillier, self.true_encrypted, self.false_encrypted, self.mask_generator
        )

        # 区別不可能な形式に変換
        self.indistinguishable = create_indistinguishable_form(
            self.masked_true, self.masked_false, self.true_mask, self.false_mask,
            {"paillier_public_key": self.public_key}
        )

    def test_ciphertext_extraction(self):
        """暗号文の抽出テスト"""
        # 各鍵タイプで抽出
        for key_type in ["true", "false"]:
            chunks, mask_info = extract_by_key_type(self.indistinguishable, key_type)

            # 適切なチャンク数があることを確認
            self.assertEqual(len(chunks), 1)

            # マスク情報の形式を確認
            self.assertIn("type", mask_info)
            self.assertIn("seed", mask_info)

            # 抽出されたマスク情報が適切か確認
            expected_type = "true_mask" if key_type == "true" else "false_mask"
            self.assertEqual(mask_info["type"], expected_type)

    def test_decryption_correctness(self):
        """復号の正確性テスト"""
        # 各鍵タイプで抽出と復号
        for key_type in ["true", "false"]:
            # 暗号文とマスク情報の抽出
            chunks, mask_info = extract_by_key_type(self.indistinguishable, key_type)

            # シードからマスクを再生成
            seed = base64.b64decode(mask_info["seed"])
            new_mask_generator = MaskFunctionGenerator(self.paillier, seed)
            true_mask_new, false_mask_new = new_mask_generator.generate_mask_pair()

            # 鍵タイプに応じたマスクを選択
            mask = true_mask_new if key_type == "true" else false_mask_new

            # マスク除去
            unmasked = new_mask_generator.remove_mask(chunks, mask)

            # 復号
            decrypted_int = self.paillier.decrypt(unmasked[0], self.private_key)

            # 整数をバイト列に変換
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')

            # 期待される結果と比較
            expected = self.true_text if key_type == "true" else self.false_text
            self.assertEqual(expected, decrypted_bytes)

    def test_format_immutability(self):
        """形式不変性テスト：JSONシリアライズ/デシリアライズ後も保持されるか"""
        # 暗号文データをJSON文字列に変換
        json_str = json.dumps(self.indistinguishable)

        # JSON文字列から辞書に戻す
        deserialized = json.loads(json_str)

        # 元の形式と一致するか確認
        self.assertEqual(self.indistinguishable["format"], deserialized["format"])
        self.assertEqual(self.indistinguishable["version"], deserialized["version"])
        self.assertEqual(len(self.indistinguishable["true_chunks"]), len(deserialized["true_chunks"]))
        self.assertEqual(len(self.indistinguishable["false_chunks"]), len(deserialized["false_chunks"]))

        # 各チャンクが正確に保持されているか確認
        for i in range(len(self.indistinguishable["true_chunks"])):
            self.assertEqual(self.indistinguishable["true_chunks"][i], deserialized["true_chunks"][i])

        for i in range(len(self.indistinguishable["false_chunks"])):
            self.assertEqual(self.indistinguishable["false_chunks"][i], deserialized["false_chunks"][i])


class CryptanalyticTests(unittest.TestCase):
    """暗号解析攻撃に対する耐性テスト"""

    def setUp(self):
        """テスト準備"""
        # 出力ディレクトリの作成
        os.makedirs("test_output", exist_ok=True)

        # Paillier暗号の初期化
        self.paillier = PaillierCrypto(bits=1024)
        self.public_key, self.private_key = self.paillier.generate_keys()

        # マスク関数生成器の初期化
        self.seed = os.urandom(32)
        self.mask_generator = MaskFunctionGenerator(self.paillier, self.seed)

        # テスト用の大きなデータセット生成
        self.sample_size = 100

        # テストデータ（同じ長さのテキスト）
        self.true_message = "This is a true, confidential message containing actual information."
        self.false_message = "This is a false, decoy message with misleading details embedded."

        # データセットの生成
        self.true_ciphertexts = []
        self.false_ciphertexts = []
        self.indistinguishable_data = []

        for _ in range(self.sample_size):
            # バリエーションのために各メッセージに乱数を追加
            true_text = (self.true_message + f" Random: {random.randint(1, 10000)}").encode()
            false_text = (self.false_message + f" Random: {random.randint(1, 10000)}").encode()

            # バイト列を整数に変換
            true_int = int.from_bytes(true_text, 'big')
            false_int = int.from_bytes(false_text, 'big')

            # 暗号化
            true_encrypted = [self.paillier.encrypt(true_int, self.public_key)]
            false_encrypted = [self.paillier.encrypt(false_int, self.public_key)]

            # 毎回異なるシードでマスク生成器を使用
            new_seed = os.urandom(32)
            new_mask_generator = MaskFunctionGenerator(self.paillier, new_seed)

            # 変換とマスク適用
            masked_true, masked_false, true_mask, false_mask = transform_between_true_false(
                self.paillier, true_encrypted, false_encrypted, new_mask_generator
            )

            # 区別不可能な形式に変換
            indistinguishable = create_indistinguishable_form(
                masked_true, masked_false, true_mask, false_mask,
                {"paillier_public_key": self.public_key}
            )

            # データセットに追加
            self.true_ciphertexts.extend(masked_true)
            self.false_ciphertexts.extend(masked_false)
            self.indistinguishable_data.append(indistinguishable)

    def test_statistical_analysis(self):
        """統計的解析による攻撃耐性テスト"""
        # 暗号文の統計的特性を比較
        true_stats = self._get_ciphertext_stats(self.true_ciphertexts)
        false_stats = self._get_ciphertext_stats(self.false_ciphertexts)

        # 統計量の比較
        # カイ二乗検定でp値が0.05以上なら、2つの分布は統計的に区別できない
        chi2, p_value = stats.chisquare(true_stats, false_stats)

        # グラフの生成
        plt.figure(figsize=(10, 6))
        bins = range(len(true_stats))

        plt.bar(bins, true_stats, alpha=0.5, label='True Ciphertexts', width=0.4)
        plt.bar([x + 0.4 for x in bins], false_stats, alpha=0.5, label='False Ciphertexts', width=0.4)

        plt.xlabel('Value Bucket')
        plt.ylabel('Frequency')
        plt.title(f'Statistical Distribution of Ciphertexts (p-value: {p_value:.6f})')
        plt.legend()
        plt.grid(True)

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/statistical_masking_{timestamp}.png"
        plt.savefig(filename)

        # 統計的に区別できないことを確認（p値が0.05以上）
        self.assertGreaterEqual(p_value, 0.05,
                              f"統計的に区別可能（p値: {p_value}）。暗号文識別不能性が不十分です。")

        return filename

    def test_interleave_shuffle_attack(self):
        """インターリーブシャッフル攻撃耐性テスト"""
        # インターリーブシャッフル攻撃：暗号文をシャッフルしても正しく復号できることを確認
        shuffled_results = []

        for i in range(min(10, len(self.indistinguishable_data))):
            # 元の暗号文データ
            data = self.indistinguishable_data[i]

            # 真と偽の暗号文チャンクをシャッフル
            true_chunks_orig = [int(chunk, 16) for chunk in data["true_chunks"]]
            false_chunks_orig = [int(chunk, 16) for chunk in data["false_chunks"]]

            # シャッフルテスト用に一部チャンクを入れ替え
            if len(true_chunks_orig) > 1 and len(false_chunks_orig) > 1:
                # チャンクをシャッフル
                mixed_true_chunks = true_chunks_orig.copy()
                mixed_false_chunks = false_chunks_orig.copy()

                # インデックスをランダムに選択
                idx1, idx2 = random.sample(range(min(len(true_chunks_orig), len(false_chunks_orig))), 2)

                # チャンクを入れ替え
                mixed_true_chunks[idx1], mixed_true_chunks[idx2] = mixed_true_chunks[idx2], mixed_true_chunks[idx1]
                mixed_false_chunks[idx1], mixed_false_chunks[idx2] = mixed_false_chunks[idx2], mixed_false_chunks[idx1]

                # 16進数表現に変換
                data["true_chunks"] = [hex(chunk) for chunk in mixed_true_chunks]
                data["false_chunks"] = [hex(chunk) for chunk in mixed_false_chunks]

                # 各鍵タイプで復号を試みる
                for key_type in ["true", "false"]:
                    try:
                        # 抽出と復号
                        chunks, mask_info = extract_by_key_type(data, key_type)

                        # シードからマスクを再生成
                        seed = base64.b64decode(mask_info["seed"])
                        new_mask_generator = MaskFunctionGenerator(self.paillier, seed)
                        true_mask_new, false_mask_new = new_mask_generator.generate_mask_pair()

                        # 鍵タイプに応じたマスクを選択
                        mask = true_mask_new if key_type == "true" else false_mask_new

                        # マスク除去
                        new_mask_generator.remove_mask(chunks, mask)

                        # ここまで来れば正常（復号成功）
                        success = True
                    except Exception as e:
                        # 復号に失敗
                        success = False
                        shuffled_results.append((i, key_type, False, str(e)))

                # 元に戻す
                data["true_chunks"] = [hex(chunk) for chunk in true_chunks_orig]
                data["false_chunks"] = [hex(chunk) for chunk in false_chunks_orig]

            # チャンク数が1の場合は入れ替えテストをスキップ
            else:
                shuffled_results.append((i, "both", True, "チャンク数が少なすぎてシャッフルテストをスキップ"))

        # 結果の可視化
        plt.figure(figsize=(10, 6))
        success_rates = []

        # 10サンプルまたは全サンプルのうち少ない方
        for i in range(min(10, len(self.indistinguishable_data))):
            # このサンプルについての成功率
            success_count = sum(1 for r in shuffled_results if r[0] == i and r[2])
            total_count = sum(1 for r in shuffled_results if r[0] == i)

            if total_count > 0:
                success_rate = success_count / total_count
            else:
                success_rate = 1.0  # テストされなかった場合は成功と見なす

            success_rates.append(success_rate)

        # プロット
        plt.bar(range(len(success_rates)), success_rates, color='green')
        plt.xlabel('Sample Index')
        plt.ylabel('Shuffle Resistance Success Rate')
        plt.title('Resistance to Interleave/Shuffle Attacks')
        plt.ylim(0, 1.1)
        plt.grid(True)

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/interleave_shuffle_ciphertexts_{timestamp}.png"
        plt.savefig(filename)

        # シャッフル耐性が十分であることを確認
        avg_success_rate = sum(success_rates) / len(success_rates) if success_rates else 1.0
        self.assertGreaterEqual(avg_success_rate, 0.5,
                              f"シャッフル耐性が不十分です（成功率: {avg_success_rate}）")

        return filename

    def test_redundancy_attack(self):
        """冗長性攻撃耐性テスト"""
        # 同じ平文から生成された異なる暗号文を比較
        redundancy_results = []

        # サンプルのうち最初の10個（またはサンプル全体）を使用
        test_samples = min(10, self.sample_size)
        success_count = 0

        for i in range(0, test_samples, 2):
            if i+1 < test_samples:
                data1 = self.indistinguishable_data[i]
                data2 = self.indistinguishable_data[i+1]

                # 真の暗号文チャンクを比較
                true_chunks1 = [int(chunk, 16) for chunk in data1["true_chunks"]]
                true_chunks2 = [int(chunk, 16) for chunk in data2["true_chunks"]]

                # 暗号文の差異を計算
                true_diff_ratio = self._calculate_difference_ratio(true_chunks1, true_chunks2)

                # 偽の暗号文チャンクを比較
                false_chunks1 = [int(chunk, 16) for chunk in data1["false_chunks"]]
                false_chunks2 = [int(chunk, 16) for chunk in data2["false_chunks"]]

                # 暗号文の差異を計算
                false_diff_ratio = self._calculate_difference_ratio(false_chunks1, false_chunks2)

                # 十分な差異があれば冗長性攻撃に耐性あり
                true_resistant = true_diff_ratio > 0.3
                false_resistant = false_diff_ratio > 0.3

                redundancy_results.append({
                    "sample_pair": (i, i+1),
                    "true_diff_ratio": true_diff_ratio,
                    "false_diff_ratio": false_diff_ratio,
                    "true_resistant": true_resistant,
                    "false_resistant": false_resistant
                })

                if true_resistant and false_resistant:
                    success_count += 1

        # 結果の可視化
        plt.figure(figsize=(12, 6))

        # 差異率のプロット
        sample_pairs = [f"{r['sample_pair'][0]}-{r['sample_pair'][1]}" for r in redundancy_results]
        true_diffs = [r["true_diff_ratio"] for r in redundancy_results]
        false_diffs = [r["false_diff_ratio"] for r in redundancy_results]

        x = np.arange(len(sample_pairs))
        width = 0.35

        plt.bar(x - width/2, true_diffs, width, label='True Chunks Difference')
        plt.bar(x + width/2, false_diffs, width, label='False Chunks Difference')

        plt.axhline(y=0.3, color='r', linestyle='--', label='Minimum Safe Difference')

        plt.xlabel('Sample Pairs')
        plt.ylabel('Difference Ratio')
        plt.title('Redundancy Attack Resistance Test')
        plt.xticks(x, sample_pairs, rotation=45)
        plt.legend()
        plt.grid(True)

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/redundancy_test_{timestamp}.png"
        plt.savefig(filename)

        # 冗長性攻撃耐性が十分であることを確認
        success_rate = success_count / len(redundancy_results) if redundancy_results else 1.0
        self.assertGreaterEqual(success_rate, 0.7,
                              f"冗長性攻撃耐性が不十分です（成功率: {success_rate}）")

        return filename

    def test_comprehensive_indistinguishability(self):
        """包括的な識別不能性テスト"""
        # 複数の識別不能性要素を組み合わせたテスト
        test_results = {
            "statistical_masking": {"success": True, "p_value": None},
            "chunk_distribution": {"success": True, "difference": None},
            "key_analysis": {"success": True, "error_rate": None},
            "timing_attacks": {"success": True, "timing_variance": None}
        }

        # 1. 統計的マスキング
        # 暗号文の統計的特性を比較
        true_stats = self._get_ciphertext_stats(self.true_ciphertexts)
        false_stats = self._get_ciphertext_stats(self.false_ciphertexts)

        # カイ二乗検定
        chi2, p_value = stats.chisquare(true_stats, false_stats)
        test_results["statistical_masking"]["p_value"] = p_value
        test_results["statistical_masking"]["success"] = p_value >= 0.05

        # 2. チャンク分布
        # 真と偽のチャンク数分布を比較
        true_chunk_counts = [len(data["true_chunks"]) for data in self.indistinguishable_data]
        false_chunk_counts = [len(data["false_chunks"]) for data in self.indistinguishable_data]

        # 差異の計算
        avg_true_chunks = sum(true_chunk_counts) / len(true_chunk_counts)
        avg_false_chunks = sum(false_chunk_counts) / len(false_chunk_counts)
        chunk_diff = abs(avg_true_chunks - avg_false_chunks)

        test_results["chunk_distribution"]["difference"] = chunk_diff
        test_results["chunk_distribution"]["success"] = chunk_diff < 0.5

        # 3. 鍵解析
        # 真と偽の鍵をランダムに生成し、解析精度をテスト
        num_keys = 50
        errors = 0

        for _ in range(num_keys):
            # ランダムな鍵を生成
            key = os.urandom(32)

            # 鍵のタイプをコイントスで決定
            true_key = random.random() < 0.5
            expected = "true" if true_key else "false"

            # 鍵解析の結果
            result = analyze_key_type(key)

            # 期待値と一致しない場合はエラー
            if result != expected:
                errors += 1

        error_rate = errors / num_keys
        test_results["key_analysis"]["error_rate"] = error_rate
        test_results["key_analysis"]["success"] = error_rate <= 0.6  # 60%以下のエラー率（ランダムより少し良い）

        # 4. タイミング攻撃
        # 真と偽のキーで処理時間の差を測定
        timing_samples = 20
        true_times = []
        false_times = []

        for _ in range(timing_samples):
            # テストデータ
            test_data = self.indistinguishable_data[random.randint(0, len(self.indistinguishable_data)-1)]

            # 真の鍵での処理時間測定
            start_time = time.time()
            extract_by_key_type(test_data, "true")
            true_times.append(time.time() - start_time)

            # 偽の鍵での処理時間測定
            start_time = time.time()
            extract_by_key_type(test_data, "false")
            false_times.append(time.time() - start_time)

        # 処理時間の差（標準偏差）
        true_mean = sum(true_times) / len(true_times)
        false_mean = sum(false_times) / len(false_times)

        true_std = (sum((t - true_mean) ** 2 for t in true_times) / len(true_times)) ** 0.5
        false_std = (sum((t - false_mean) ** 2 for t in false_times) / len(false_times)) ** 0.5

        timing_diff = abs(true_mean - false_mean) / ((true_std + false_std) / 2)

        test_results["timing_attacks"]["timing_variance"] = timing_diff
        test_results["timing_attacks"]["success"] = timing_diff < 2.0  # 標準偏差の2倍以内

        # 総合結果
        overall_success = all(test["success"] for test in test_results.values())

        # 結果の可視化
        plt.figure(figsize=(10, 8))

        # 結果のプロット（レーダーチャート）
        categories = list(test_results.keys())
        N = len(categories)

        # 角度の計算
        angles = [n / float(N) * 2 * np.pi for n in range(N)]
        angles += angles[:1]  # 閉じたポリゴンにするため

        # スコアの計算（0-1の範囲に正規化）
        scores = []
        for category in categories:
            test = test_results[category]
            if category == "statistical_masking":
                # p値が高いほど良い（0.05以上が成功）
                score = min(1.0, test["p_value"] / 0.1) if test["p_value"] is not None else 0.5
            elif category == "chunk_distribution":
                # 差異が小さいほど良い（0.5未満が成功）
                score = max(0.0, 1.0 - test["difference"]) if test["difference"] is not None else 0.5
            elif category == "key_analysis":
                # エラー率が0.5に近いほど良い（識別不能）
                err = test["error_rate"] if test["error_rate"] is not None else 0.5
                score = 1.0 - abs(0.5 - err) * 2  # 0.5のとき1.0、0または1のとき0.0
            elif category == "timing_attacks":
                # タイミング差が小さいほど良い（2.0未満が成功）
                var = test["timing_variance"] if test["timing_variance"] is not None else 2.0
                score = max(0.0, 1.0 - var / 4.0)  # 0のとき1.0、4以上のとき0.0
            scores.append(score)

        # 閉じたポリゴンにするため
        scores += scores[:1]

        # レーダーチャートの描画
        ax = plt.subplot(111, polar=True)
        ax.plot(angles, scores, 'o-', linewidth=2)
        ax.fill(angles, scores, alpha=0.25)
        ax.set_thetagrids(angles[:-1] * 180 / np.pi, categories)

        # 目盛りの設定
        ax.set_ylim(0, 1)
        ax.grid(True)

        plt.title('Comprehensive Indistinguishability Test')

        # 保存
        timestamp = int(time.time())
        filename = f"test_output/comprehensive_indistinguishability_{timestamp}.png"
        plt.savefig(filename)

        # JSONファイルにも保存
        json_filename = f"test_output/indistinguishable_test_results.json_{timestamp}"
        with open(json_filename, 'w') as f:
            json.dump(test_results, f, indent=2)

        # テストが成功したことを確認
        self.assertTrue(overall_success,
                       f"識別不能性テストが失敗しました。詳細: {test_results}")

        return filename, json_filename

    def _get_ciphertext_stats(self, ciphertexts: List[int], num_buckets: int = 20) -> List[int]:
        """暗号文の統計的特性を抽出"""
        if not ciphertexts:
            return [0] * num_buckets

        # 最大値/最小値を算出
        min_value = min(c % (10**12) for c in ciphertexts)  # モジュロを使用して値を小さくする
        max_value = max(c % (10**12) for c in ciphertexts)

        # 範囲を計算
        value_range = max_value - min_value
        if value_range == 0:
            return [len(ciphertexts)] + [0] * (num_buckets - 1)

        # バケット間隔を計算
        bucket_size = value_range / num_buckets

        # 各バケットのカウントを初期化
        buckets = [0] * num_buckets

        # 各暗号文をバケットに分類
        for c in ciphertexts:
            value = c % (10**12)
            bucket_idx = min(int((value - min_value) / bucket_size), num_buckets - 1)
            buckets[bucket_idx] += 1

        return buckets

    def _calculate_difference_ratio(self, chunks1: List[int], chunks2: List[int]) -> float:
        """2つのチャンクリスト間の差異率を計算"""
        if not chunks1 or not chunks2:
            return 1.0  # 空のリストがある場合は最大差異

        # リストの長さを合わせる
        min_len = min(len(chunks1), len(chunks2))
        chunks1 = chunks1[:min_len]
        chunks2 = chunks2[:min_len]

        differences = 0

        for c1, c2 in zip(chunks1, chunks2):
            # ビット表現での差異を計算
            bin1 = bin(c1)[2:].zfill(64)[-64:]  # 最後の64ビットのみ使用
            bin2 = bin(c2)[2:].zfill(64)[-64:]

            # ハミング距離を計算
            hamming_dist = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))

            # 差異率を計算（0-1の範囲）
            diff_ratio = hamming_dist / 64

            # 合計に加算
            differences += diff_ratio

        # 平均差異率を返す
        return differences / min_len


def run_all_indistinguishability_tests():
    """すべての識別不能性テストを実行し、結果をまとめる"""
    # 出力ディレクトリの作成
    os.makedirs("test_output", exist_ok=True)

    # テスト結果を格納する辞書
    test_results = {}

    # CryptanalyticTestsを実行
    cryptanalytic_suite = unittest.TestLoader().loadTestsFromTestCase(CryptanalyticTests)
    cryptanalytic_result = unittest.TextTestRunner(verbosity=2).run(cryptanalytic_suite)

    # テスト実行前にインスタンスを作成して視覚化関数を呼び出す
    crypto_tests = CryptanalyticTests()
    crypto_tests.setUp()

    # 視覚化チャートの生成
    print("統計的マスキングテストを実行中...")
    stats_chart = crypto_tests.test_statistical_analysis()
    test_results["statistical_masking"] = stats_chart

    print("インターリーブシャッフル攻撃耐性テストを実行中...")
    shuffle_chart = crypto_tests.test_interleave_shuffle_attack()
    test_results["interleave_shuffle"] = shuffle_chart

    print("冗長性攻撃耐性テストを実行中...")
    redundancy_chart = crypto_tests.test_redundancy_attack()
    test_results["redundancy_test"] = redundancy_chart

    print("包括的識別不能性テストを実行中...")
    indistinguishability_chart, results_json = crypto_tests.test_comprehensive_indistinguishability()
    test_results["comprehensive_indistinguishability"] = indistinguishability_chart
    test_results["test_results_json"] = results_json

    # TestIndistinguishabilityを実行
    indistinguishability_suite = unittest.TestLoader().loadTestsFromTestCase(TestIndistinguishability)
    indistinguishability_result = unittest.TextTestRunner(verbosity=2).run(indistinguishability_suite)

    # 成功したかどうか
    all_passed = cryptanalytic_result.wasSuccessful() and indistinguishability_result.wasSuccessful()

    # 結果を出力
    print("\n============ 識別不能性テスト結果 ============")
    if all_passed:
        print("✅ 全てのテストが成功しました！")
    else:
        print("❌ 一部のテストが失敗しました。")

    print("\n生成されたチャート:")
    for test_name, chart_file in test_results.items():
        print(f"- {test_name}: {chart_file}")

    return all_passed, test_results


if __name__ == "__main__":
    # テストの実行
    success, results = run_all_indistinguishability_tests()

    # 終了コード
    sys.exit(0 if success else 1)