# Q1315: rpc-state via WalletCardPendingChange 1315

## Question
Can an unprivileged attacker entering through the service command response correlation in `WalletCardPendingChange` (packages/wallets/src/components/card/WalletCardPendingChange.tsx) control out-of-order event and query responses with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/card/WalletCardPendingChange.tsx` / `WalletCardPendingChange`
- Entrypoint: service command response correlation
- Attacker controls: out-of-order event and query responses; with precision-boundary values
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
