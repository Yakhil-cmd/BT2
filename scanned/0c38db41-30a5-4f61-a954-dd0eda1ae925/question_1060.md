# Q1060: rpc-state via addMirror 1060

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `addMirror` (packages/api/src/wallets/DL.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence preview -> mutate controlled state -> confirm so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/DL.ts` / `addMirror`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
