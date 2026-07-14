# Q1415: walletconnect via loadBypassCommands 1415

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `loadBypassCommands` (packages/gui/src/hooks/useBypassCommands.ts) control previously granted bypass permission combined with profile switch after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useBypassCommands.ts` / `loadBypassCommands`
- Entrypoint: dapp command permission prompt
- Attacker controls: previously granted bypass permission combined with profile switch; after canceling and reopening the dialog
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
