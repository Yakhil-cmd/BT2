# Q3797: walletconnect via WalletConnectAddConnectionDialog 3797

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `WalletConnectAddConnectionDialog` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control chainId/account/fingerprint mismatch with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `WalletConnectAddConnectionDialog`
- Entrypoint: stored dapp permission reload
- Attacker controls: chainId/account/fingerprint mismatch; with precision-boundary values
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
