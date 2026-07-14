# Q380: rpc-state via WalletCardPendingChange 380

## Question
Can an unprivileged attacker entering through the service command response correlation in `WalletCardPendingChange` (packages/wallets/src/components/card/WalletCardPendingChange.tsx) control large numeric fields near JS precision limits after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/card/WalletCardPendingChange.tsx` / `WalletCardPendingChange`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
