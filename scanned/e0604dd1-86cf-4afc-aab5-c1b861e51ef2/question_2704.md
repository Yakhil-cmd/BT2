# Q2704: rpc-state via handleCompletion 2704

## Question
Can an unprivileged attacker entering through the RTK query cache update in `handleCompletion` (packages/gui/src/components/signVerify/SignVerifyDialog.tsx) control RPC error payload shaped like success with a stale Redux cache and drive the sequence fetch -> cache -> refresh -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignVerifyDialog.tsx` / `handleCompletion`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
