# Q3796: walletconnect via WalletConnectAddConnectionDialog 3796

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `WalletConnectAddConnectionDialog` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control chainId/account/fingerprint mismatch with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `WalletConnectAddConnectionDialog`
- Entrypoint: pairing URI/import flow
- Attacker controls: chainId/account/fingerprint mismatch; with precision-boundary values
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
