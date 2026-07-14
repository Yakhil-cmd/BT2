# Q912: rpc-state via sumPoints 912

## Question
Can an unprivileged attacker entering through the service command response correlation in `sumPoints` (packages/gui/src/util/getPercentPointsSuccessfull.ts) control RPC error payload shaped like success with a duplicate identifier and drive the sequence download or render content -> trigger linked wallet action so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/getPercentPointsSuccessfull.ts` / `sumPoints`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; with a duplicate identifier
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
