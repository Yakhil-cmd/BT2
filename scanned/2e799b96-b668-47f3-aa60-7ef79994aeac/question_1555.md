# Q1555: rpc-state via Unit 1555

## Question
Can an unprivileged attacker entering through the RTK query cache update in `Unit` (packages/gui/src/electron/constants/Unit.ts) control RPC error payload shaped like success with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/Unit.ts` / `Unit`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
