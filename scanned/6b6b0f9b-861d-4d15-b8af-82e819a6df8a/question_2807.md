# Q2807: rpc-state via updateRecoveryIds 2807

## Question
Can an unprivileged attacker entering through the RTK query cache update in `updateRecoveryIds` (packages/api/src/wallets/DID.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/DID.ts` / `updateRecoveryIds`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
