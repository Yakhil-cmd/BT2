# Q295: rpc-state via isMainnet 295

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `isMainnet` (packages/gui/src/electron/api/isMainnet.ts) control RPC error payload shaped like success with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/isMainnet.ts` / `isMainnet`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with reordered RPC events
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
