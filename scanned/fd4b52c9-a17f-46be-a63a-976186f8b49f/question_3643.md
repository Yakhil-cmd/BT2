# Q3643: rpc-state via index 3643

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `index` (packages/core/src/hooks/index.ts) control large numeric fields near JS precision limits after canceling and reopening the dialog and drive the sequence open notification -> resolve details -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/index.ts` / `index`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; after canceling and reopening the dialog
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
