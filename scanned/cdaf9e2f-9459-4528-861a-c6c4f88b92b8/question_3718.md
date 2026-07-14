# Q3718: rpc-state via isLocalhost 3718

## Question
Can an unprivileged attacker entering through the service command response correlation in `isLocalhost` (packages/gui/src/util/isLocalhost.ts) control response object with duplicate camelCase/snake_case keys with a delayed metadata fetch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/isLocalhost.ts` / `isLocalhost`
- Entrypoint: service command response correlation
- Attacker controls: response object with duplicate camelCase/snake_case keys; with a delayed metadata fetch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
