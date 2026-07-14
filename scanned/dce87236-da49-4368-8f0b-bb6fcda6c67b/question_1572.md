# Q1572: rpc-state via isPlainObject 1572

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `isPlainObject` (packages/gui/src/electron/utils/isPlainObject.ts) control out-of-order event and query responses with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/isPlainObject.ts` / `isPlainObject`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; with a redirected remote resource
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
