# Q3600: rpc-state via index 3600

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `index` (packages/api/src/index.ts) control large numeric fields near JS precision limits with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/index.ts` / `index`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with a stale Redux cache
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
