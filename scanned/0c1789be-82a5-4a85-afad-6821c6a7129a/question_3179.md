# Q3179: rpc-state via WalletCardCRCatRestrictions 3179

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `WalletCardCRCatRestrictions` (packages/wallets/src/components/card/WalletCardCRCatRestrictions.tsx) control out-of-order event and query responses with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/card/WalletCardCRCatRestrictions.tsx` / `WalletCardCRCatRestrictions`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; with reordered RPC events
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
