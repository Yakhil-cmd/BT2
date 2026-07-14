# Q3181: rpc-state via WalletCardPendingBalance 3181

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WalletCardPendingBalance` (packages/wallets/src/components/card/WalletCardPendingBalance.tsx) control large numeric fields near JS precision limits after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/card/WalletCardPendingBalance.tsx` / `WalletCardPendingBalance`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
