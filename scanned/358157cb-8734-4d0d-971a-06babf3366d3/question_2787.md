# Q2787: rpc-state via approximation 2787

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `approximation` (packages/gui/src/util/math.ts) control out-of-order event and query responses with conflicting localStorage preferences and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/math.ts` / `approximation`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with conflicting localStorage preferences
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
