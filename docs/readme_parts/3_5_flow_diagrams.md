## 各方式のフロー図 📊

お兄様！パシ子が各暗号化方式の処理フローを可視化しました！レオくんも理解できるシンプルさを目指しましたよ〜💕

各フロー図は折りたたみ形式になっていますので、気になる方式をクリックして確認してくださいね。ダークモードでも見やすいように配色しています ✨

<details>
<summary>1. ラビット暗号化方式 🐰</summary>

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#bb86fc', 'primaryTextColor': '#fff', 'primaryBorderColor': '#7c4dff', 'lineColor': '#dbc7ff', 'secondaryColor': '#03dac6', 'tertiaryColor': '#1e1e1e' }}}%%
flowchart TB
    %% 暗号化プロセス
    subgraph "暗号化プロセス"
    direction TB
    A[入力] --> B[鍵生成]
    A --> C["true.text\n(正規ファイル)"]
    A --> D["false.text\n(非正規ファイル)"]
    B --> E["ラビットストリーム生成器"]
    E --> F["真のストリーム"]
    E --> G["偽のストリーム"]
    C --> H["真のストリームで暗号化"]
    D --> I["偽のストリームで暗号化"]
    H --> J["真の暗号文"]
    I --> K["偽の暗号文"]
    J --> L["多重データ\nカプセル化"]
    K --> L
    L --> M["単一の暗号文出力"]
    end

    %% 復号プロセス
    subgraph "復号プロセス"
    direction TB
    N["暗号文"] --> O["入力鍵判定"]
    O -->|"正規鍵"| P["真のストリーム再生成"]
    O -->|"非正規鍵"| Q["偽のストリーム再生成"]
    P --> R["真のストリームで復号"]
    Q --> S["偽のストリームで復号"]
    R --> T["true.text生成"]
    S --> U["false.text生成"]
    end
```

</details>

<details>
<summary>2. 暗号学的ハニーポット方式 🍯</summary>

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#ffb86c', 'primaryTextColor': '#fff', 'primaryBorderColor': '#ff9e4d', 'lineColor': '#ffe0c2', 'secondaryColor': '#ff79c6', 'tertiaryColor': '#1e1e1e' }}}%%
flowchart TB
    %% 暗号化プロセス
    subgraph "暗号化プロセス"
    direction TB
    A[入力] --> B["マスター鍵生成"]
    A --> C["true.text\n(正規ファイル)"]
    A --> D["false.text\n(非正規ファイル)"]
    B --> E["トラップドア関数"]
    E --> F["正規鍵"]
    E --> G["非正規鍵"]
    C --> H["正規データ暗号化"]
    D --> I["非正規データ暗号化"]
    F --> H
    G --> I
    H --> J["正規暗号文"]
    I --> K["非正規暗号文"]
    J --> L["ハニーポット\nカプセル生成"]
    K --> L
    L --> M["ハニーポット暗号文"]
    end

    %% 復号プロセス
    subgraph "復号プロセス"
    direction TB
    N["ハニーポット暗号文"] --> O["鍵検証機構"]
    O -->|"正規鍵"| P["ハニートークン検証"]
    O -->|"非正規鍵"| Q["偽装トークン生成"]
    P --> R["正規経路選択"]
    Q --> S["非正規経路選択"]
    R --> T["true.text復号"]
    S --> U["false.text復号"]
    end
```

</details>

<details>
<summary>3. 準同型暗号マスキング方式 🎭</summary>

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#8be9fd', 'primaryTextColor': '#000', 'primaryBorderColor': '#56c9ee', 'lineColor': '#caf5fd', 'secondaryColor': '#bd93f9', 'tertiaryColor': '#1e1e1e' }}}%%
flowchart TB
    %% 暗号化プロセス
    subgraph "暗号化プロセス"
    direction TB
    A[入力] --> B["鍵生成"]
    A --> C["true.text\n(正規ファイル)"]
    A --> D["false.text\n(非正規ファイル)"]
    B --> E["準同型鍵ペア生成"]
    E --> F["暗号化公開鍵"]
    E --> G["マスク鍵ペア"]
    C --> H["準同型暗号化"]
    D --> I["準同型暗号化"]
    F --> H
    F --> I
    H --> J["true暗号文 E(true)"]
    I --> K["false暗号文 E(false)"]
    G --> L["マスク関数生成"]
    L --> M["true用マスク"]
    L --> N["false用マスク"]
    J --> O["マスク適用\nE(true) × E(mask_t)"]
    K --> P["マスク適用\nE(false) × E(mask_f)"]
    M --> O
    N --> P
    O --> Q["単一暗号文出力"]
    P --> Q
    end

    %% 復号プロセス
    subgraph "復号プロセス"
    direction TB
    R["暗号文"] --> S["鍵判定"]
    S -->|"正規鍵"| T["true用復号鍵導出"]
    S -->|"非正規鍵"| U["false用復号鍵導出"]
    T --> V["準同型マスク逆適用"]
    U --> W["準同型マスク逆適用"]
    V --> X["準同型復号"]
    W --> Y["準同型復号"]
    X --> Z["true.text生成"]
    Y --> AA["false.text生成"]
    end
```

</details>

<details>
<summary>4. 不確定性転写暗号化 🎲</summary>

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#50fa7b', 'primaryTextColor': '#000', 'primaryBorderColor': '#2de366', 'lineColor': '#9cfcb3', 'secondaryColor': '#ff5555', 'tertiaryColor': '#1e1e1e' }}}%%
flowchart TB
    %% 暗号化プロセス
    subgraph "暗号化プロセス"
    direction TB
    A[入力] --> B["マスター鍵生成"]
    A --> C["true.text\n(正規ファイル)"]
    A --> D["false.text\n(非正規ファイル)"]
    B --> E["非決定論的状態機械初期化"]
    E --> F["状態遷移マトリクス生成"]
    C --> G["正規データ経路"]
    D --> H["非正規データ経路"]
    F --> I["確率的状態変換器"]
    G --> J["状態A暗号化"]
    H --> K["状態B暗号化"]
    I --> J
    I --> K
    J --> L["状態エントロピー注入"]
    K --> L
    L --> M["状態カプセル化"]
    M --> N["非決定論的暗号文"]
    end

    %% 復号プロセス
    subgraph "復号プロセス"
    direction TB
    O["非決定論的暗号文"] --> P["確率的実行エンジン"]
    P --> Q["内部状態初期化"]
    Q --> R["鍵依存乱数生成"]
    R --> S["実行パス決定"]
    S -->|"正規鍵"| T["状態A確率バイアス"]
    S -->|"非正規鍵"| U["状態B確率バイアス"]
    T --> V["状態A復号プロセス"]
    U --> W["状態B復号プロセス"]
    V --> X["true.text生成"]
    W --> Y["false.text生成"]
    end
```

</details>

<details>
<summary>5. ラビット＋準同型マスキング 👑</summary>

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#f1fa8c', 'primaryTextColor': '#000', 'primaryBorderColor': '#e7f35c', 'lineColor': '#f7fcb8', 'secondaryColor': '#ff79c6', 'tertiaryColor': '#1e1e1e' }}}%%
flowchart TB
    %% 暗号化プロセス
    subgraph "暗号化プロセス"
    direction TB
    A[入力] --> B["複合鍵生成"]
    A --> C["true.text\n(正規ファイル)"]
    A --> D["false.text\n(非正規ファイル)"]

    %% レイヤー1: ラビット暗号
    B --> E["ラビットストリーム生成"]
    E --> F["真のストリーム"]
    E --> G["偽のストリーム"]

    %% レイヤー2: 準同型暗号
    B --> H["準同型鍵生成"]
    H --> I["公開鍵"]
    H --> J["秘密鍵ペア"]

    %% データ暗号化
    C --> K["第1層: ラビット暗号化"]
    D --> L["第1層: ラビット暗号化"]
    F --> K
    G --> L
    K --> M["第2層: 準同型暗号化"]
    L --> N["第2層: 準同型暗号化"]
    I --> M
    I --> N

    %% マスキングと統合
    J --> O["準同型マスク生成"]
    O --> P["真用マスク"]
    O --> Q["偽用マスク"]
    M --> R["マスク適用"]
    N --> S["マスク適用"]
    P --> R
    Q --> S

    %% 確率的カプセル化
    R --> T["確率的カプセル化"]
    S --> T
    T --> U["最終暗号文"]

    %% 不区別性保証処理
    U --> V["不区別性証明適用"]
    V --> W["出力: 識別不能暗号文"]
    end

    %% 復号プロセス
    subgraph "復号プロセス"
    direction TB
    AA["識別不能暗号文"] --> BB["鍵評価"]

    %% レイヤー処理の逆順適用
    BB -->|"正規鍵"| CC["不区別性処理の逆適用"]
    BB -->|"非正規鍵"| DD["不区別性処理の逆適用"]

    %% カプセル解除
    CC --> EE["確率的カプセル解除"]
    DD --> FF["確率的カプセル解除"]

    %% 準同型マスク処理
    EE --> GG["準同型マスク逆適用"]
    FF --> HH["準同型マスク逆適用"]

    %% ラビット復号
    GG --> II["準同型復号"]
    HH --> JJ["準同型復号"]
    II --> KK["ラビットストリーム復号"]
    JJ --> LL["ラビットストリーム復号"]

    %% 最終出力
    KK --> MM["true.text生成"]
    LL --> NN["false.text生成"]
    end
```

</details>

これらのフロー図はシンプルに表現していますが、実際の実装ではさらに複雑な処理が行われています。特に最強の組み合わせ方式では、複数の安全性メカニズムが重なり合って最高レベルの保護を実現しています！

レオくんも「わんわん！（すごいね！）」って言ってますよ〜 🐶✨
