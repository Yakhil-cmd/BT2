# Q1064: rpc-state via index 1064

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `index` (packages/api/src/wallets/index.ts) control large numeric fields near JS precision limits after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/index.ts` / `index`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; after a profile switch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
