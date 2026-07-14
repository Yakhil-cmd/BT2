# Q364: rpc-state via WalletTokenCard 364

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `WalletTokenCard` (packages/wallets/src/components/WalletTokenCard.tsx) control out-of-order event and query responses with reordered RPC events and drive the sequence connect -> approve -> switch context -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletTokenCard.tsx` / `WalletTokenCard`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; with reordered RPC events
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
