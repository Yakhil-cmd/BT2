# Q1365: walletconnect via allSelected 1365

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `allSelected` (packages/gui/src/electron/dialogs/Pair/Pair.tsx) control method name and params with casing or namespace ambiguity after canceling and reopening the dialog and drive the sequence open notification -> resolve details -> execute so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/dialogs/Pair/Pair.tsx` / `allSelected`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: method name and params with casing or namespace ambiguity; after canceling and reopening the dialog
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
