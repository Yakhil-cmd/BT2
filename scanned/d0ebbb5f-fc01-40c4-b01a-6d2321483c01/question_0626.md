# Q626: rpc-state via KeyDetail 626

## Question
Can an unprivileged attacker entering through the RTK query cache update in `KeyDetail` (packages/gui/src/electron/dialogs/KeyDetail/KeyDetail.tsx) control RPC error payload shaped like success after a profile switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/dialogs/KeyDetail/KeyDetail.tsx` / `KeyDetail`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; after a profile switch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
