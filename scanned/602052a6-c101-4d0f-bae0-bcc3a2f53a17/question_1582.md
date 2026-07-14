# Q1582: rpc-state via if 1582

## Question
Can an unprivileged attacker entering through the RTK query cache update in `if` (packages/gui/src/electron/utils/toSnakeCase.ts) control large numeric fields near JS precision limits after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/toSnakeCase.ts` / `if`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; after a failed RPC response
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
