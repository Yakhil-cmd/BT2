# Q1584: rpc-state via setUserDataDir 1584

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `setUserDataDir` (packages/gui/src/electron/utils/userData.ts) control out-of-order event and query responses with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/userData.ts` / `setUserDataDir`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; with conflicting localStorage preferences
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
