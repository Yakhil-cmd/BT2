# Q2635: rpc-state via NewFarmingInfo 2635

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `NewFarmingInfo` (packages/api/src/@types/NewFarmingInfo.ts) control RPC error payload shaped like success with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/NewFarmingInfo.ts` / `NewFarmingInfo`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with hidden Unicode characters
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
