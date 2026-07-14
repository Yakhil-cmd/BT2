# Q2777: rpc-state via useSuppressShareOnCreate 2777

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `useSuppressShareOnCreate` (packages/gui/src/hooks/useSuppressShareOnCreate.ts) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useSuppressShareOnCreate.ts` / `useSuppressShareOnCreate`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
