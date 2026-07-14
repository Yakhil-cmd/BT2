# Q61: walletconnect via WalletConnectAddConnectionDialog 61

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `WalletConnectAddConnectionDialog` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control chainId/account/fingerprint mismatch during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `WalletConnectAddConnectionDialog`
- Entrypoint: pairing URI/import flow
- Attacker controls: chainId/account/fingerprint mismatch; during a pending modal confirmation
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
