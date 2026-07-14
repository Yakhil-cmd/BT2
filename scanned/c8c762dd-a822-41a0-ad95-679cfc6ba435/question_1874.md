# Q1874: rpc-state via createNewRecoveryWallet 1874

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `createNewRecoveryWallet` (packages/api/src/wallets/DID.ts) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/DID.ts` / `createNewRecoveryWallet`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
