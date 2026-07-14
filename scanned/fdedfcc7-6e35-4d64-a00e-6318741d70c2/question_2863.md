# Q2863: walletconnect via handleSubmit 2863

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `handleSubmit` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control session metadata with misleading origin/icon/name fields after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `handleSubmit`
- Entrypoint: WalletConnect session proposal
- Attacker controls: session metadata with misleading origin/icon/name fields; after a network switch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
