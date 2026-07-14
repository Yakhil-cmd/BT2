# Q1950: walletconnect via isSignCommand 1950

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `isSignCommand` (packages/gui/src/electron/commands/isSignCommand.ts) control chainId/account/fingerprint mismatch with reordered RPC events and drive the sequence connect -> approve -> switch context -> execute so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isSignCommand.ts` / `isSignCommand`
- Entrypoint: WalletConnect session proposal
- Attacker controls: chainId/account/fingerprint mismatch; with reordered RPC events
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
