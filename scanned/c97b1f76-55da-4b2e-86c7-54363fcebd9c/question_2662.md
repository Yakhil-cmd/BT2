# Q2662: rpc-state via TransactionType 2662

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `TransactionType` (packages/api/src/constants/TransactionType.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/TransactionType.ts` / `TransactionType`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
