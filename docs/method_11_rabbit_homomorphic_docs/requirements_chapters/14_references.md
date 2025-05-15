## 参考文献と学術的根拠 📚

本仕様書の設計は以下の学術的根拠に基づいています。

### 1. 暗号理論の基礎

1. Bellare, M., & Rogaway, P. (2005). **Introduction to Modern Cryptography**. _UCSD CSE Course Notes_, 207.

2. Katz, J., & Lindell, Y. (2020). **Introduction to Modern Cryptography** (3rd ed.). CRC Press.

3. Goldreich, O. (2003). **Foundations of Cryptography: Basic Tools**. Cambridge University Press.

4. Boneh, D., & Shoup, V. (2020). **A Graduate Course in Applied Cryptography**. _Stanford University_. Available at https://toc.cryptobook.us/

### 2. ストリーム暗号とラビット暗号

5. Boesgaard, M., Vesterager, M., Pedersen, T., Christiansen, J., & Scavenius, O. (2003). **Rabbit: A New High-Performance Stream Cipher**. In _Fast Software Encryption_ (pp. 307-329). Springer.

6. eSTREAM: The ECRYPT Stream Cipher Project. (2012). **The Rabbit Stream Cipher**. Final report of the ECRYPT Stream Cipher Project. https://www.ecrypt.eu.org/stream/

7. Chen, L., & Gong, G. (2012). **Communication System Security**. CRC Press. [Chapter on Stream Ciphers and Their Applications]

8. Lu, Y., Meier, W., & Vaudenay, S. (2005). **The Conditional Correlation Attack: A Practical Attack on Bluetooth Encryption**. In _Advances in Cryptology – CRYPTO 2005_ (pp. 97-117).

### 3. 準同型暗号

9. Gentry, C. (2009). **A Fully Homomorphic Encryption Scheme**. _Stanford University Doctoral Dissertation_.

10. Brakerski, Z., & Vaikuntanathan, V. (2014). **Efficient Fully Homomorphic Encryption from (Standard) LWE**. _SIAM Journal on Computing_, 43(2), 831-871.

11. Fan, J., & Vercauteren, F. (2012). **Somewhat Practical Fully Homomorphic Encryption**. _IACR Cryptology ePrint Archive_, 2012, 144.

12. Albrecht, M., Chase, M., Chen, H., Ding, J., Goldwasser, S., Gorbunov, S., Hoffstein, J., Lauter, K., Lokam, S., Micciancio, D., Moody, D., Morrison, T., Sahai, A., & Vaikuntanathan, V. (2018). **Homomorphic Encryption Security Standard**. _HomomorphicEncryption.org_.

### 4. 格子暗号と量子耐性

13. Peikert, C. (2016). **A Decade of Lattice Cryptography**. _Foundations and Trends in Theoretical Computer Science_, 10(4), 283-424.

14. Micciancio, D., & Regev, O. (2009). **Lattice-based Cryptography**. In _Post-Quantum Cryptography_ (pp. 147-191). Springer.

15. Bernstein, D. J., & Lange, T. (2017). **Post-quantum Cryptography**. _Nature_, 549(7671), 188-194.

16. Alagic, G., Alperin-Sheriff, J., Apon, D., Cooper, D., Dang, Q., Kelsey, J., Liu, Y., Miller, C., Moody, D., Peralta, R., Perlner, R., Robinson, A., & Smith-Tone, D. (2020). **Status Report on the Second Round of the NIST Post-Quantum Cryptography Standardization Process**. _National Institute of Standards and Technology_.

### 5. 暗号融合と複合設計

17. Bellare, M., & Namprempre, C. (2008). **Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm**. _Journal of Cryptology_, 21(4), 469-491.

18. Jutla, C. S. (2001). **Encryption Modes with Almost Free Message Integrity**. In _Advances in Cryptology – EUROCRYPT 2001_ (pp. 529-544).

19. 山下 紘史, 國廣 昇, & 竹内 孔一. (2018). **複合型暗号方式の安全性解析と効率的実装**. _情報処理学会論文誌_, 59(2), 725-739.

20. Vaudenay, S. (2002). **Security Flaws Induced by CBC Padding—Applications to SSL, IPSEC, WTLS...**. In _Advances in Cryptology – EUROCRYPT 2002_ (pp. 534-546).

### 6. サイドチャネル攻撃と防御

21. Kocher, P., Jaffe, J., & Jun, B. (1999). **Differential Power Analysis**. In _Advances in Cryptology – CRYPTO '99_ (pp. 388-397).

22. Chari, S., Jutla, C. S., Rao, J. R., & Rohatgi, P. (1999). **Towards Sound Approaches to Counteract Power-Analysis Attacks**. In _Advances in Cryptology – CRYPTO '99_ (pp. 398-412).

23. Bernstein, D. J. (2005). **Cache-timing Attacks on AES**. _Technical Report_.

24. Yarom, Y., & Falkner, K. (2014). **FLUSH+RELOAD: A High Resolution, Low Noise, L3 Cache Side-Channel Attack**. In _23rd USENIX Security Symposium_ (pp. 719-732).

### 7. 形式検証と安全性証明

25. Barthe, G., Grégoire, B., & Béguelin, S. Z. (2009). **Formal Certification of Code-based Cryptographic Proofs**. In _Proceedings of the 36th ACM SIGPLAN-SIGACT Symposium on Principles of Programming Languages_ (pp. 90-101).

26. Halevi, S. (2005). **A Plausible Approach to Computer-aided Cryptographic Proofs**. _IACR Cryptology ePrint Archive_, 2005, 181.

27. Blanchet, B. (2008). **A Computationally Sound Mechanized Prover for Security Protocols**. _IEEE Transactions on Dependable and Secure Computing_, 5(4), 193-207.

28. Barthe, G., Dupressoir, F., Grégoire, B., Kunz, C., Schmidt, B., & Strub, P. Y. (2013). **EasyCrypt: A Tutorial**. In _Foundations of Security Analysis and Design VII_ (pp. 146-166).

### 8. 実装効率と最適化

29. Bernstein, D. J., & Schwabe, P. (2012). **NEON Crypto**. In _Cryptographic Hardware and Embedded Systems – CHES 2012_ (pp. 320-339).

30. Gueron, S. (2012). **Intel® Advanced Encryption Standard (AES) New Instructions Set**. _Intel Corporation_, 1-94.

31. Aoki, K., Guo, J., Matusiewicz, K., Sasaki, Y., & Wang, L. (2013). **Preimages for Step-Reduced SHA-2**. In _Advances in Cryptology – ASIACRYPT 2009_ (pp. 578-597).

32. 櫻井 幸一, & 穴田 啓晃. (2019). **暗号アルゴリズムの高速実装技術**. _情報処理_, 60(10), 952-960.

### 9. 量子アルゴリズムと量子計算

33. Shor, P. W. (1997). **Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer**. _SIAM Journal on Computing_, 26(5), 1484-1509.

34. Grover, L. K. (1996). **A Fast Quantum Mechanical Algorithm for Database Search**. In _Proceedings of the Twenty-Eighth Annual ACM Symposium on Theory of Computing_ (pp. 212-219).

35. Nielsen, M. A., & Chuang, I. L. (2010). **Quantum Computation and Quantum Information**. Cambridge University Press.

36. Brassard, G., Høyer, P., & Tapp, A. (1998). **Quantum Cryptanalysis of Hash and Claw-Free Functions**. In _LATIN'98: Theoretical Informatics_ (pp. 163-169).

### 10. 新興暗号技術

37. Sahai, A., & Waters, B. (2005). **Fuzzy Identity-Based Encryption**. In _Advances in Cryptology – EUROCRYPT 2005_ (pp. 457-473).

38. Boneh, D., Sahai, A., & Waters, B. (2011). **Functional Encryption: Definitions and Challenges**. In _Theory of Cryptography Conference_ (pp. 253-273).

39. Garg, S., Gentry, C., Halevi, S., Raykova, M., Sahai, A., & Waters, B. (2013). **Candidate Indistinguishability Obfuscation and Functional Encryption for All Circuits**. In _54th Annual Symposium on Foundations of Computer Science_ (pp. 40-49).

40. Boneh, D., Lewi, K., Montgomery, H., & Raghunathan, A. (2013). **Key Homomorphic PRFs and Their Applications**. In _Advances in Cryptology – CRYPTO 2013_ (pp. 410-428).

### 11. 日本国内関連規格

41. 総務省. (2021). **政府機関等のサイバーセキュリティ対策のための統一基準** (令和 3 年度版).

42. 経済産業省. (2020). **暗号技術検討会 2019 年度報告書**. 独立行政法人情報処理推進機構.

43. CRYPTREC. (2022). **電子政府推奨暗号リスト**. https://www.cryptrec.go.jp/list.html

44. 国立研究開発法人情報通信研究機構. (2019). **量子情報通信研究開発ロードマップ**.

---

これらの参考文献は、本仕様の設計・実装において参照すべき学術的根拠を提供します。特に、格子暗号とラビットストリーム暗号の融合という革新的アプローチの理論的基盤となるものであり、実装者はこれらを参照して最新の暗号理論と実装技術を理解することが推奨されます。
