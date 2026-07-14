# Q544: rpc-state via MessageInterface 544

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `MessageInterface` (packages/api/src/@types/MessageInterface.ts) control RPC error payload shaped like success through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/MessageInterface.ts` / `MessageInterface`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; through a batch of rapid user-accessible actions
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
