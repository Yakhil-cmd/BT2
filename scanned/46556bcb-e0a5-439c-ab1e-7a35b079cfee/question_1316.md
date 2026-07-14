# Q1316: rpc-state via WalletCardPendingTotalBalance 1316

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WalletCardPendingTotalBalance` (packages/wallets/src/components/card/WalletCardPendingTotalBalance.tsx) control RPC error payload shaped like success after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/card/WalletCardPendingTotalBalance.tsx` / `WalletCardPendingTotalBalance`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; after a failed RPC response
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
