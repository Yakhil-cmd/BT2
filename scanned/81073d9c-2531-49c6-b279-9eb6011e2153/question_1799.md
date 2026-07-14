# Q1799: rpc-state via mojoToCATLocaleString 1799

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `mojoToCATLocaleString` (packages/core/src/utils/mojoToCATLocaleString.ts) control response object with duplicate camelCase/snake_case keys during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/utils/mojoToCATLocaleString.ts` / `mojoToCATLocaleString`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; during a pending modal confirmation
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
