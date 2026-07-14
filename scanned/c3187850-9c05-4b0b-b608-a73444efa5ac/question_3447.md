# Q3447: rpc-state via sleep 3447

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `sleep` (packages/gui/src/electron/utils/sleep.ts) control subscription event for a different wallet/fingerprint after a profile switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/sleep.ts` / `sleep`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; after a profile switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
