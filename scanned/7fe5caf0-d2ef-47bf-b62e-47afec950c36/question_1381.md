# Q1381: walletconnect via if 1381

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `if` (packages/gui/src/electron/utils/dispatchPairRequest.ts) control chainId/account/fingerprint mismatch during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/dispatchPairRequest.ts` / `if`
- Entrypoint: stored dapp permission reload
- Attacker controls: chainId/account/fingerprint mismatch; during a pending modal confirmation
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
