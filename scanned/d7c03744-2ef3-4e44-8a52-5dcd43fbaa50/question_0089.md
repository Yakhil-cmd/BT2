# Q89: walletconnect via WalletConnections 89

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `WalletConnections` (packages/wallets/src/components/WalletConnections.tsx) control session metadata with misleading origin/icon/name fields after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/wallets/src/components/WalletConnections.tsx` / `WalletConnections`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; after a failed RPC response
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
