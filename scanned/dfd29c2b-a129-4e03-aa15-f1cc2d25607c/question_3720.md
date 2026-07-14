# Q3720: rpc-state via limit 3720

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `limit` (packages/gui/src/util/limit.ts) control large numeric fields near JS precision limits with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/limit.ts` / `limit`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with a stale Redux cache
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
