# Q773: rpc-state via Point 773

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `Point` (packages/api/src/@types/Point.ts) control RPC error payload shaped like success with a duplicate identifier and drive the sequence select -> edit backing object -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Point.ts` / `Point`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with a duplicate identifier
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
