# Q62: walletconnect via WalletConnectConnections 62

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `WalletConnectConnections` (packages/gui/src/components/walletConnect/WalletConnectConnections.tsx) control previously granted bypass permission combined with profile switch after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectConnections.tsx` / `WalletConnectConnections`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: previously granted bypass permission combined with profile switch; after canceling and reopening the dialog
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
