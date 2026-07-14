# Q1281: rpc-state via getIsOutgoingTransaction 1281

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `getIsOutgoingTransaction` (packages/wallets/src/components/WalletHistory.tsx) control response object with duplicate camelCase/snake_case keys with a delayed metadata fetch and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletHistory.tsx` / `getIsOutgoingTransaction`
- Entrypoint: camel/snake case transform path
- Attacker controls: response object with duplicate camelCase/snake_case keys; with a delayed metadata fetch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
