# Q2670: rpc-state via getBlockRecords 2670

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getBlockRecords` (packages/api/src/services/FullNode.ts) control large numeric fields near JS precision limits with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/FullNode.ts` / `getBlockRecords`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with precision-boundary values
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
