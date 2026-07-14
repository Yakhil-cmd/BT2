# Q624: rpc-state via About 624

## Question
Can an unprivileged attacker entering through the RTK query cache update in `About` (packages/gui/src/electron/dialogs/About/About.tsx) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence connect -> approve -> switch context -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/dialogs/About/About.tsx` / `About`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
