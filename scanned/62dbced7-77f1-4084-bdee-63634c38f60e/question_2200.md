# Q2200: rpc-state via WalletBadge 2200

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `WalletBadge` (packages/wallets/src/components/WalletBadge.tsx) control large numeric fields near JS precision limits with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletBadge.tsx` / `WalletBadge`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with a duplicate identifier
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
