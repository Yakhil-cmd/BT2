# Q3575: rpc-state via Point 3575

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `Point` (packages/api/src/@types/Point.ts) control out-of-order event and query responses with reordered RPC events and drive the sequence download or render content -> trigger linked wallet action so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Point.ts` / `Point`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; with reordered RPC events
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
