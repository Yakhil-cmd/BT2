# Q1930: walletconnect via handleAddConnection 1930

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `handleAddConnection` (packages/gui/src/components/walletConnect/WalletConnectConnections.tsx) control chainId/account/fingerprint mismatch with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectConnections.tsx` / `handleAddConnection`
- Entrypoint: stored dapp permission reload
- Attacker controls: chainId/account/fingerprint mismatch; with a delayed metadata fetch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
