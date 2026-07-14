# Q1986: walletconnect via if 1986

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `if` (packages/gui/src/hooks/useWalletConnectClient.ts) control batched sign/spend command sequence with reordered RPC events and drive the sequence select -> edit backing object -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectClient.ts` / `if`
- Entrypoint: pairing URI/import flow
- Attacker controls: batched sign/spend command sequence; with reordered RPC events
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
