# Q1053: walletconnect via getSingleton 1053

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `getSingleton` (packages/gui/src/hooks/useWalletConnectClient.ts) control chainId/account/fingerprint mismatch with a cached permission entry and drive the sequence connect -> approve -> switch context -> execute so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectClient.ts` / `getSingleton`
- Entrypoint: WalletConnect session proposal
- Attacker controls: chainId/account/fingerprint mismatch; with a cached permission entry
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
