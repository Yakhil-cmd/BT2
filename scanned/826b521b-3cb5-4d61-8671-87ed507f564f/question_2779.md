# Q2779: rpc-state via compareChecksums 2779

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `compareChecksums` (packages/gui/src/util/compareChecksums.ts) control RPC error payload shaped like success with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/compareChecksums.ts` / `compareChecksums`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with a delayed metadata fetch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
