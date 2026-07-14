# Q1581: rpc-state via if 1581

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/gui/src/electron/utils/toCamelCase.ts) control subscription event for a different wallet/fingerprint after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/toCamelCase.ts` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; after a failed RPC response
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
