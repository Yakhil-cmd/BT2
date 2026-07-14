# Q3432: rpc-state via assets 3432

## Question
Can an unprivileged attacker entering through the RTK query cache update in `assets` (packages/gui/src/electron/utils/assets.ts) control large numeric fields near JS precision limits with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/assets.ts` / `assets`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with a stale Redux cache
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
