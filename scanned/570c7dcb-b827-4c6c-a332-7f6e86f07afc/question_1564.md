# Q1564: rpc-state via addAsset 1564

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `addAsset` (packages/gui/src/electron/utils/assets.ts) control large numeric fields near JS precision limits with precision-boundary values and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/assets.ts` / `addAsset`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with precision-boundary values
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
