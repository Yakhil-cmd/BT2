# Q1061: rpc-state via addMirror 1061

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `addMirror` (packages/api/src/wallets/DL.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/DL.ts` / `addMirror`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
