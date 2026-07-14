# Q381: rpc-state via WalletCardPendingChange 381

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `WalletCardPendingChange` (packages/wallets/src/components/card/WalletCardPendingChange.tsx) control large numeric fields near JS precision limits after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/card/WalletCardPendingChange.tsx` / `WalletCardPendingChange`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
