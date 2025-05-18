# ブロックチェーン技術を活用した複数平文復号システムの実装調査結果

**調査日**: 2024 年 5 月 16 日

## 要約

本調査では、ブロックチェーン技術を活用して単一の暗号文から異なる鍵に応じて異なる平文を取り出す仕組みの実装方法について検証しました。調査の結果、以下の主要な実装アプローチが明らかになりました：

1. **ハイブリッドオンチェーン・オフチェーンアプローチ**：メタデータと検証ロジックをブロックチェーン上に、暗号化データを分散ストレージ（IPFS 等）に配置するハイブリッドモデル。現時点で最も実用的かつ拡張性の高い方法として推奨されます。

2. **完全オンチェーンアプローチ**：すべての処理をブロックチェーン上で行う方法。透明性と監査可能性に優れる一方、コストが高くスケーラビリティに制約があります。

3. **プライバシー特化型ブロックチェーンアプローチ**：Secret Network や Oasis Network などのプライバシー機能に特化したブロックチェーンを活用する方法。ネイティブなプライバシー保証が得られますが、エコシステムが限定的です。

4. **ゼロ知識証明（ZKP）統合アプローチ**：オンチェーンでの検証に ZKP を活用し、プライバシーを確保する方法。技術的難易度は高いものの、高度なプライバシー保護が可能です。

最も実装例が多く、実用的な選択肢は**ハイブリッドアプローチ**です。特に、Lit Protocol や Semaphore、Threshold Network といったプロジェクトが提供するフレームワークを活用することで、実装の複雑さを抑えつつ、複数平文復号システムを構築できます。

本調査結果に基づき、イーサリアムスマートコントラクトと IPFS を組み合わせた実装アプローチを推奨します。これにより、コスト効率、スケーラビリティ、セキュリティのバランスが取れたシステムが構築可能です。

## 1. 実行可能な実装例の詳細

### 1.1 Lit Protocol

- **リポジトリ URL**: [https://github.com/LIT-Protocol/lit-js-sdk](https://github.com/LIT-Protocol/lit-js-sdk)
- **使用ブロックチェーンプラットフォーム**: イーサリアム、Polygon、Solana、その他 EVM 互換チェーン
- **実装言語とフレームワーク**: JavaScript/TypeScript、Solidity
- **ライセンス**: MIT
- **最終更新日**: 2024 年（活発に開発中）
- **主要な機能**:
  - 条件付きアクセス制御（特定の条件を満たすユーザーのみがデータを復号可能）
  - 閾値暗号による分散鍵管理
  - ブロックチェーン条件に基づく暗号化データへのアクセス制御
  - クロスチェーン対応
- **利用状況や普及度**: 複数の DApp で採用されており、Web3 エコシステムで広く認知されています

Lit Protocol は分散型アクセス制御層を提供し、特定の条件（トークン所有、NFT 保有など）を満たすユーザーのみが暗号化コンテンツを復号できる仕組みを実現します。ネットワーク上の複数のノードが連携して閾値暗号を実行することで、単一障害点を排除しています。

**実装例**:

```javascript
// Lit Protocolを使用した条件付き暗号化・復号の例
import * as LitJsSdk from '@lit-protocol/lit-node-client';

// Litクライアントの初期化
const client = new LitJsSdk.LitNodeClient();
await client.connect();

// アクセス制御条件の定義
const accessControlConditions = [
  {
    contractAddress: '',
    standardContractType: '',
    chain: 'ethereum',
    method: 'eth_getBalance',
    parameters: [':userAddress', 'latest'],
    returnValueTest: {
      comparator: '>=',
      value: '1000000000000000000' // 1 ETH
    }
  }
];

// メタデータの作成と暗号化
const plaintext = 'api_38f4c2a99e1d4f5e7b9c0d2e1f3a5c8b';
const { encryptedString, symmetricKey } = await LitJsSdk.encryptString(plaintext);

// 対称鍵の保存（アクセス制御条件付き）
const encryptedSymmetricKey = await client.saveEncryptionKey({
  accessControlConditions,
  symmetricKey,
  authSig, // ユーザーの署名
  chain: 'ethereum'
});

// 復号
// ユーザーが条件を満たしている場合のみ復号可能
const retrievedSymmetricKey = await client.getEncryptionKey({
  accessControlConditions,
  toDecrypt: encryptedSymmetricKey,
  chain: 'ethereum',
  authSig
});

const decryptedString = await LitJsSdk.decryptString(encryptedString, retrievedSymmetricKey);
```

Lit Protocol の主な制限は、完全な分散性と条件評価のリアルタイム性のバランスです。また、複雑な条件の評価にはガスコストがかかる場合があります。

### 1.2 Semaphore

- **リポジトリ URL**: [https://github.com/semaphore-protocol/semaphore](https://github.com/semaphore-protocol/semaphore)
- **使用ブロックチェーンプラットフォーム**: イーサリアム、Polygon、その他 EVM 互換チェーン
- **実装言語とフレームワーク**: TypeScript、Solidity、circom（ZKP 回路）
- **ライセンス**: MIT
- **最終更新日**: 2024 年（活発に開発中）
- **主要な機能**:
  - 匿名認証とプライバシー保護
  - ゼロ知識証明を活用した身元証明
  - グループメンバーシップ証明
  - プライバシーを保護したアクセス制御
- **利用状況や普及度**: プライバシー保護を重視するプロジェクトで採用されており、匿名投票や匿名認証システムに利用されています

Semaphore は、ゼロ知識証明を活用してユーザーの匿名性を保ちながら、特定のグループに所属していることを証明できるプロトコルです。複数平文復号システムでは、特定のグループのメンバーだけが特定の平文にアクセスできるようにするために利用できます。

**実装例**:

```javascript
// Semaphoreを使用した匿名アクセス制御の例
import { Group } from '@semaphore-protocol/group';
import { Identity } from '@semaphore-protocol/identity';
import { generateProof, verifyProof } from '@semaphore-protocol/proof';

// グループの作成（各平文へのアクセス権を持つユーザー群）
const group = new Group();

// ユーザー識別子の生成
const userIdentity = new Identity('user_secret');
group.addMember(userIdentity.commitment);

// ゼロ知識証明の生成（ユーザーがグループに所属していることの証明）
const externalNullifier = 1; // 信号の固有識別子
const signal = 'access_plaintext_a'; // 実行したいアクション

const fullProof = await generateProof(userIdentity, group, externalNullifier, signal, {
  wasmFilePath: './semaphore.wasm',
  zkeyFilePath: './semaphore.zkey'
});

// スマートコントラクトで証明を検証
// コントラクトは証明が有効な場合のみ、特定の平文へのアクセスを許可
const verificationResult = await verifyProof(fullProof, 20);
```

Semaphore の主な制限は、ZKP 生成の計算コストと、プライバシー保護とユーザーエクスペリエンスのトレードオフです。また、ZKP の検証はガスコストが高くなる傾向があります。

### 1.3 Threshold Network

- **リポジトリ URL**: [https://github.com/threshold-network/solidity-contracts](https://github.com/threshold-network/solidity-contracts)
- **使用ブロックチェーンプラットフォーム**: イーサリアム
- **実装言語とフレームワーク**: Solidity、TypeScript
- **ライセンス**: GPL-3.0
- **最終更新日**: 2024 年（活発に開発中）
- **主要な機能**:
  - 閾値 ECDSA 署名
  - 秘密分散と再構築
  - 分散型鍵管理
  - プライバシー保護されたトークンマネジメント
- **利用状況や普及度**: tBTC プロジェクトの基盤技術として利用されており、金融 DeFi 分野で採用されています

Threshold Network は、Keep Network と NuCypher が統合したプロジェクトで、閾値暗号を活用した分散型インフラを提供します。複数平文復号システムでは、閾値暗号を活用して異なる鍵に応じて異なる平文を復号する仕組みを実現できます。

**実装例**:

```typescript
// Threshold NetworkのtECDSAを活用した実装例
import { ThresholdProvider } from '@threshold-network/threshold.js';
import { ethers } from 'ethers';

// Threshold Networkプロバイダーの初期化
const provider = new ethers.providers.JsonRpcProvider('...');
const thresholdProvider = new ThresholdProvider(provider);

// 秘密の分散（複数の平文に対する鍵の生成）
const plaintextKeys = {
  plaintext_a: 'key_for_plaintext_a',
  plaintext_b: 'key_for_plaintext_b'
};

// 閾値署名グループの設定
const stakingProvider = '0x...'; // 署名グループの管理者
const threshold = 3; // 最低限必要な署名者数
const participants = 5; // 合計署名者数

// 各平文に対する閾値署名グループの作成
for (const [plaintextId, key] of Object.entries(plaintextKeys)) {
  const groupId = await thresholdProvider.tecdsa.createStakingGroup(
    stakingProvider,
    threshold,
    participants
  );

  // 平文とグループIDのマッピングをスマートコントラクトに保存
  await contractInstance.registerPlaintextGroup(plaintextId, groupId);
}

// 復号リクエスト
async function decryptPlaintext(userKey) {
  // ユーザーキーからプレーンテキストIDを導出
  const plaintextId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userKey));

  // 対応するグループIDを取得
  const groupId = await contractInstance.getPlaintextGroup(plaintextId);

  // グループが存在しない場合は無効な鍵
  if (!groupId) {
    throw new Error('Invalid key');
  }

  // 閾値グループによる署名リクエスト（復号処理の承認）
  const signatureRequest = await thresholdProvider.tecdsa.requestSignature(
    groupId,
    ethers.utils.arrayify(plaintextId)
  );

  // 署名結果を使用して暗号文を復号
  const encryptedData = await contractInstance.getEncryptedData(plaintextId);
  const plaintext = decrypt(encryptedData, signatureRequest.signature);

  return plaintext;
}
```

Threshold Network の主な制限は、閾値暗号の複雑さと、複数の当事者間での調整が必要なことです。また、ネットワークの信頼性や署名者の可用性に依存します。

### 1.4 Secret Network

- **リポジトリ URL**: [https://github.com/scrtlabs/SecretNetwork](https://github.com/scrtlabs/SecretNetwork)
- **使用ブロックチェーンプラットフォーム**: Secret Network（Cosmos ベース）
- **実装言語とフレームワーク**: Rust（CosmWasm）
- **ライセンス**: AGPL-3.0
- **最終更新日**: 2024 年（活発に開発中）
- **主要な機能**:
  - プライバシー保護されたスマートコントラクト
  - エンクレーブ技術による秘密計算
  - 暗号化されたデータのオンチェーン保存
  - プライバシーを保持したクエリと計算
- **利用状況や普及度**: プライバシー重視の DApps で採用されており、Secret DeFi やプライバシー保護 NFT で利用されています

Secret Network は、プライバシー保護機能をネイティブに提供するブロックチェーンで、TEE（Trusted Execution Environment）を活用して暗号化されたデータに対する計算を可能にします。複数平文復号システムでは、異なる鍵に対して異なる平文を提供する機能をプライバシーを保持したまま実装できます。

**実装例**:

```rust
// Secret Networkのスマートコントラクト実装例
use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Querier,
    StdError, StdResult, Storage,
};
use secret_toolkit::crypto::{sha_256, Prng, SHA256_HASH_SIZE};
use secret_toolkit::utils::{pad_handle_result, pad_query_result};

// 平文データの構造
#[derive(Serialize, Deserialize)]
struct PlaintextMapping {
    plaintext_id: String,
    encrypted_data: Binary,
}

// コントラクトの状態
#[derive(Serialize, Deserialize)]
pub struct State {
    plaintext_mappings: Vec<PlaintextMapping>,
    viewing_keys: Vec<ViewingKey>,
}

// 初期化
pub fn init(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    _msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        plaintext_mappings: vec![],
        viewing_keys: vec![],
    };
    deps.storage.set(STATE_KEY, &serialize(&state)?);

    Ok(InitResponse::default())
}

// 平文の登録
pub fn handle_register_plaintext(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    plaintext_id: String,
    encrypted_data: Binary,
) -> StdResult<HandleResponse> {
    let mut state: State = load_state(deps.storage)?;

    // 平文マッピングの追加
    state.plaintext_mappings.push(PlaintextMapping {
        plaintext_id: plaintext_id.clone(),
        encrypted_data,
    });

    save_state(deps.storage, &state)?;

    // レスポンスをパディングしてサイドチャネル攻撃を防止
    pad_handle_result(Ok(HandleResponse::default()), PADDING_SIZE)
}

// 鍵の検証と平文の取得
pub fn query_get_plaintext(
    deps: &Extern<S, A, Q>,
    user_key: String,
) -> StdResult<Binary> {
    let state: State = load_state(deps.storage)?;

    // ユーザーキーから平文IDを導出
    let plaintext_id = derive_plaintext_id(user_key)?;

    // 対応する平文を検索
    let plaintext = state.plaintext_mappings.iter()
        .find(|m| m.plaintext_id == plaintext_id)
        .ok_or_else(|| StdError::generic_err("Invalid key"))?;

    // レスポンスをパディングしてサイドチャネル攻撃を防止
    pad_query_result(to_binary(&plaintext.encrypted_data), PADDING_SIZE)
}
```

Secret Network の主な制限は、Cosmos エコシステムに限定されていることと、TEE に対する信頼が必要なことです。また、他のブロックチェーンとの相互運用性には追加の橋渡し（ブリッジ）が必要です。
