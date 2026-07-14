# Q3613: rpc-state via bytesToHex 3613

## Question
Can an unprivileged attacker entering through the RTK query cache update in `bytesToHex` (packages/api/src/utils/randomHex.ts) control large numeric fields near JS precision limits after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/randomHex.ts` / `bytesToHex`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; after canceling and reopening the dialog
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
