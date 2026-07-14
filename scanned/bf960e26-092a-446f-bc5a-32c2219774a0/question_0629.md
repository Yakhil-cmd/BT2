# Q629: rpc-state via if 629

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `if` (packages/gui/src/electron/preloadDialog.ts) control out-of-order event and query responses during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/preloadDialog.ts` / `if`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; during a pending modal confirmation
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
