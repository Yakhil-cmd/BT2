# Q2504: rpc-state via ipcMainHandle 2504

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `ipcMainHandle` (packages/gui/src/electron/utils/ipcMainHandle.ts) control RPC error payload shaped like success during a pending modal confirmation and drive the sequence open notification -> resolve details -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/ipcMainHandle.ts` / `ipcMainHandle`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; during a pending modal confirmation
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
