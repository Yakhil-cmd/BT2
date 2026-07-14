# Q800: rpc-state via Events 800

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `Events` (packages/api/src/services/Events.ts) control RPC error payload shaped like success after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/Events.ts` / `Events`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; after canceling and reopening the dialog
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
