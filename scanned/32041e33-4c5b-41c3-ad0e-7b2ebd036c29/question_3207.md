# Q3207: rpc-state via select_option_admin 3207

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `select_option_admin` (packages/wallets/src/components/create/WalletCreate.tsx) control RPC error payload shaped like success with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/create/WalletCreate.tsx` / `select_option_admin`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with conflicting localStorage preferences
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
