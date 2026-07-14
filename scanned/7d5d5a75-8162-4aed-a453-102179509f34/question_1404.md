# Q1404: walletconnect via if 1404

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `if` (packages/gui/src/electron/utils/pairStore.ts) control previously granted bypass permission combined with profile switch after canceling and reopening the dialog and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/pairStore.ts` / `if`
- Entrypoint: dapp command permission prompt
- Attacker controls: previously granted bypass permission combined with profile switch; after canceling and reopening the dialog
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
