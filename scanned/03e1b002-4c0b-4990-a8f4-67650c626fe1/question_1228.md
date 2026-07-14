# Q1228: rpc-state via if 1228

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `if` (packages/gui/src/electron/api/isMainnet.ts) control out-of-order event and query responses with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/isMainnet.ts` / `if`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; with case-normalized identifiers
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
