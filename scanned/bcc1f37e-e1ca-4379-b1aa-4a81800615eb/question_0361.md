# Q361: rpc-state via WalletStatus 361

## Question
Can an unprivileged attacker entering through the service command response correlation in `WalletStatus` (packages/wallets/src/components/WalletStatus.tsx) control RPC error payload shaped like success with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletStatus.tsx` / `WalletStatus`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
