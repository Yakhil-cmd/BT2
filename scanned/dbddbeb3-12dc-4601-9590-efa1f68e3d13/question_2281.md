# Q2281: rpc-state via WalletStandardCards 2281

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `WalletStandardCards` (packages/wallets/src/components/standard/WalletStandardCards.tsx) control large numeric fields near JS precision limits with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/standard/WalletStandardCards.tsx` / `WalletStandardCards`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with a cached permission entry
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
