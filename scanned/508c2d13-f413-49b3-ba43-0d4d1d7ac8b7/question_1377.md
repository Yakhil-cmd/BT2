# Q1377: rpc-state via constructor 1377

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `constructor` (packages/gui/src/electron/utils/chiaFormatter.ts) control large numeric fields near JS precision limits after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/chiaFormatter.ts` / `constructor`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; after a failed RPC response
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
