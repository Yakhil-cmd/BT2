# Q651: rpc-state via getConnection 651

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `getConnection` (packages/gui/src/electron/utils/webSocketBridge.ts) control large numeric fields near JS precision limits after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/webSocketBridge.ts` / `getConnection`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; after a failed RPC response
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
