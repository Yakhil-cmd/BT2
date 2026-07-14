# Q1569: rpc-state via readStream 1569

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `readStream` (packages/gui/src/electron/utils/getChecksum.ts) control RPC error payload shaped like success through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/getChecksum.ts` / `readStream`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; through a batch of rapid user-accessible actions
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
