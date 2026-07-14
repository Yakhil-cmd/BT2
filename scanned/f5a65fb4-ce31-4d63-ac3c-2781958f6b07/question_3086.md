# Q3086: rpc-state via catAssetIdToName 3086

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `catAssetIdToName` (packages/gui/src/electron/api/catAssetIdToName.ts) control large numeric fields near JS precision limits with case-normalized identifiers and drive the sequence fetch -> cache -> refresh -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/catAssetIdToName.ts` / `catAssetIdToName`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with case-normalized identifiers
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
