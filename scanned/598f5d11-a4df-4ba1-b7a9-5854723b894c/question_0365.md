# Q365: rpc-state via WalletTokenCard 365

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WalletTokenCard` (packages/wallets/src/components/WalletTokenCard.tsx) control out-of-order event and query responses with reordered RPC events and drive the sequence fetch -> cache -> refresh -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletTokenCard.tsx` / `WalletTokenCard`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with reordered RPC events
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
