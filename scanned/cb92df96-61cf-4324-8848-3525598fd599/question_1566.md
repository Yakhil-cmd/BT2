# Q1566: rpc-state via directoryExists 1566

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `directoryExists` (packages/gui/src/electron/utils/directoryExists.ts) control out-of-order event and query responses with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/directoryExists.ts` / `directoryExists`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with a stale Redux cache
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
