# Q3885: rpc-state via getTransaction 3885

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getTransaction` (packages/api/src/services/WalletService.ts) control subscription event for a different wallet/fingerprint after canceling and reopening the dialog and drive the sequence connect -> approve -> switch context -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/WalletService.ts` / `getTransaction`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; after canceling and reopening the dialog
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
