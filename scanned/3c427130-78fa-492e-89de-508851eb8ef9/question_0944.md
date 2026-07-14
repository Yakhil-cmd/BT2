# Q944: rpc-state via createNewPoolWallet 944

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `createNewPoolWallet` (packages/api/src/wallets/Pool.ts) control subscription event for a different wallet/fingerprint with a delayed metadata fetch and drive the sequence import -> parse -> preview -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/Pool.ts` / `createNewPoolWallet`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with a delayed metadata fetch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
