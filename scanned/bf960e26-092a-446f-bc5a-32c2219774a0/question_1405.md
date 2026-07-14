# Q1405: walletconnect via if 1405

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `if` (packages/gui/src/electron/utils/pairStore.ts) control method name and params with casing or namespace ambiguity after canceling and reopening the dialog and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/pairStore.ts` / `if`
- Entrypoint: pairing URI/import flow
- Attacker controls: method name and params with casing or namespace ambiguity; after canceling and reopening the dialog
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
