# Q2515: rpc-state via toCamelCase 2515

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `toCamelCase` (packages/gui/src/electron/utils/toCamelCase.ts) control large numeric fields near JS precision limits after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/toCamelCase.ts` / `toCamelCase`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
