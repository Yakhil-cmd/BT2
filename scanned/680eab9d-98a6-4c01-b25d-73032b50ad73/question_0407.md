# Q407: rpc-state via WalletCreateCard 407

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WalletCreateCard` (packages/wallets/src/components/create/WalletCreateCard.tsx) control out-of-order event and query responses with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/create/WalletCreateCard.tsx` / `WalletCreateCard`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with a cached permission entry
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
