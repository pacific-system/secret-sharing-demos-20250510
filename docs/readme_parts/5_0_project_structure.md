## プロジェクト構成 📁

レオくんもわかりやすいようにまとめました！必要なディレクトリだけをシンプルに整理しています！

```
/
├── method_6_rabbit/              # ラビット暗号化方式🐰
│   ├── encrypt.py                # 暗号化プログラム
│   ├── decrypt.py                # 復号プログラム
│   └── rabbit_stream.py          # ストリーム生成器
│
├── method_7_honeypot/            # 暗号学的ハニーポット方式🍯
│   ├── encrypt.py                # 暗号化プログラム
│   ├── decrypt.py                # 復号プログラム
│   └── honeypot_crypto.py        # ハニーポット実装
│
├── method_8_homomorphic/         # 準同型暗号マスキング方式🎭
│   ├── encrypt.py                # 暗号化プログラム
│   ├── decrypt.py                # 復号プログラム
│   └── homomorphic.py            # 準同型暗号実装
│
├── method_10_indeterministic/    # 不確定性転写経路暗号化🎲
│   ├── encrypt.py                # 暗号化プログラム
│   ├── decrypt.py                # 復号プログラム
│   └── indeterministic.py        # 非決定論的暗号化
│
├── method_11_rabbit_homomorphic/ # ラビット＋準同型最強方式👑
│   ├── encrypt.py                # 暗号化プログラム
│   ├── decrypt.py                # 復号プログラム
│   └── rabbit_homomorphic.py     # 融合実装
│
└── common/                       # 共通ユーティリティ🛠️
    ├── utils.py                  # 汎用関数
    └── crypto_base.py            # 暗号化基底クラス
```
