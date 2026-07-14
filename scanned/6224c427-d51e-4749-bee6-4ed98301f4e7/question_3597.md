# Q3597: rpc-state via TransactionTypeFilterMode 3597

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `TransactionTypeFilterMode` (packages/api/src/constants/TransactionTypeFilterMode.ts) control subscription event for a different wallet/fingerprint after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/TransactionTypeFilterMode.ts` / `TransactionTypeFilterMode`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; after a failed RPC response
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
