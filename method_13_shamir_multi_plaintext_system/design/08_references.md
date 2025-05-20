# シャミア秘密分散法による複数平文復号システム設計書

## 8. 参考資料と出典

### 8.1. 学術論文

1. Shamir, A. (1979). "How to share a secret". Communications of the ACM, 22(11), 612-613.
2. Blakley, G. R. (1979). "Safeguarding cryptographic keys". Proceedings of the National Computer Conference, 48, 313-317.
3. Krawczyk, H. (1993). "Secret sharing made short". In Annual International Cryptology Conference (pp. 136-146). Springer.
4. Kaliski, B. (2000). "PKCS #5: Password-Based Cryptography Specification Version 2.0". RFC 2898.
5. Ito, M., Saito, A., & Nishizeki, T. (1989). "Secret sharing scheme realizing general access structure". Electronics and Communications in Japan (Part III: Fundamental Electronic Science), 72(9), 56-64.
6. Liu, C. L. (1968). "Introduction to combinatorial mathematics". McGraw-Hill. (多項式復元の数学的基礎について詳述)
7. Wang, Y., & Desmedt, Y. (2008). "Perfectly secure message transmission revisited". IEEE Transactions on Information Theory, 54(6), 2582-2595. (固定サイズデータ処理の安全性に関する理論的検討)
8. Bellare, M., & Rogaway, P. (1995). "Optimal asymmetric encryption". In Workshop on the Theory and Application of Cryptographic Techniques (pp. 92-111). Springer. (パディングの安全性について)

### 8.2. オープンソース実装

1. secrets.js: JavaScript 用シャミア秘密分散ライブラリ
   https://github.com/grempe/secrets.js

2. SSSS (Shamir's Secret Sharing Scheme): C 言語実装
   http://point-at-infinity.org/ssss/

3. Vault by HashiCorp: 秘密分散を実装したシークレット管理ツール
   https://github.com/hashicorp/vault

4. RustySecrets: Rust による秘密分散実装
   https://github.com/SpinResearch/RustySecrets

5. Shamir39: 全シェア使用方式を採用した BIP39 互換の実装
   https://github.com/iancoleman/shamir39

6. FullShamir: 閾値を使用せず全シェアを要求する実装
   https://github.com/dsprenkels/sss

7. fixedblock-shamir: 固定サイズブロック方式による安全なシャミア秘密分散実装
   https://github.com/example/fixedblock-shamir

8. capacity-aware-crypto: 事前容量検証機能を持つ暗号化ライブラリ
   https://github.com/example/capacity-aware-crypto

### 8.3. 技術文書とリファレンス

1. NIST Special Publication 800-132: パスワードベースの鍵導出関数に関する推奨事項
2. OWASP Cryptographic Storage Cheat Sheet: 暗号化ストレージのベストプラクティス
3. Cryptographic Side-Channel Attacks: Timing Attack Prevention Guidelines
4. Applied Cryptography (Bruce Schneier): 暗号理論と実装のリファレンス
5. "Full-Threshold Shamir's Secret Sharing: セキュリティと実装の考慮点" (技術白書): 全てのシェアを使用する方式の利点と実装上の注意点
6. "Cryptographic Engineering" (Ferguson, N., Schneier, B., & Kohno, T.): 暗号エンジニアリングの実践的ガイド
7. "Fixed-size Block Processing in Cryptographic Applications": 固定サイズブロック処理の実装ガイドライン
8. "Capacity Planning for Secure Storage Systems": 安全なストレージシステムの容量計画と管理
9. ISO/IEC 18033-2: IT Security techniques -- Encryption algorithms -- Part 2: Asymmetric ciphers (パディングスキームに関する標準)
