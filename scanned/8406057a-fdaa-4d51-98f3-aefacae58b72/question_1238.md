# Q1238: walletconnect via if 1238

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `if` (packages/gui/src/electron/commands/findCommandSchemaById.ts) control previously granted bypass permission combined with profile switch after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/findCommandSchemaById.ts` / `if`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: previously granted bypass permission combined with profile switch; after canceling and reopening the dialog
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
