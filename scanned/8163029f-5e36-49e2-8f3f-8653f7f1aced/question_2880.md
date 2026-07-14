# Q2880: walletconnect via handleMessage 2880

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `handleMessage` (packages/gui/src/electron/api/sendCommand.ts) control chainId/account/fingerprint mismatch after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/api/sendCommand.ts` / `handleMessage`
- Entrypoint: pairing URI/import flow
- Attacker controls: chainId/account/fingerprint mismatch; after a profile switch
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
