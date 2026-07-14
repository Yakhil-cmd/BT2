# Q435: walletconnect via getRequestedCommands 435

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `getRequestedCommands` (packages/gui/src/electron/utils/addDappBypassPermissions.ts) control previously granted bypass permission combined with profile switch after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/addDappBypassPermissions.ts` / `getRequestedCommands`
- Entrypoint: pairing URI/import flow
- Attacker controls: previously granted bypass permission combined with profile switch; after a network switch
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
