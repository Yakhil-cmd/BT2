# Q3090: rpc-state via getKeys 3090

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `getKeys` (packages/gui/src/electron/api/getKeys.ts) control out-of-order event and query responses with a stale Redux cache and drive the sequence select -> edit backing object -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getKeys.ts` / `getKeys`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; with a stale Redux cache
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
