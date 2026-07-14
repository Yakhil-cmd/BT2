# Q637: rpc-state via isNumericKey 637

## Question
Can an unprivileged attacker entering through the service command response correlation in `isNumericKey` (packages/gui/src/electron/utils/isNumericKey.ts) control large numeric fields near JS precision limits with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/isNumericKey.ts` / `isNumericKey`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; with hidden Unicode characters
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
