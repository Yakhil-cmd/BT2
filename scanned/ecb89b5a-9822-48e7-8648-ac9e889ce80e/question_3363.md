# Q3363: rpc-state via constructor 3363

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `constructor` (packages/api/src/Message.ts) control out-of-order event and query responses through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/Message.ts` / `constructor`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; through a batch of rapid user-accessible actions
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
