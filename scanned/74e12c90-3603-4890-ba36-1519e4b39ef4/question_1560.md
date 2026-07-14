# Q1560: rpc-state via KeyDetail 1560

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `KeyDetail` (packages/gui/src/electron/dialogs/KeyDetail/KeyDetail.tsx) control subscription event for a different wallet/fingerprint with a duplicate identifier and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/dialogs/KeyDetail/KeyDetail.tsx` / `KeyDetail`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with a duplicate identifier
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
