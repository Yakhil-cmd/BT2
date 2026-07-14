# Q2674: rpc-state via fungibleAssetFromAssetIdAndAmount 2674

## Question
Can an unprivileged attacker entering through the RTK query cache update in `fungibleAssetFromAssetIdAndAmount` (packages/api/src/utils/calculateRoyalties.ts) control large numeric fields near JS precision limits with a cached permission entry and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/calculateRoyalties.ts` / `fungibleAssetFromAssetIdAndAmount`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with a cached permission entry
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
