# Q3645: rpc-state via if 3645

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/core/src/hooks/useCurrencyCode.ts) control out-of-order event and query responses with a delayed metadata fetch and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useCurrencyCode.ts` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; with a delayed metadata fetch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
