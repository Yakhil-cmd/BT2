# Q2191: walletconnect via nextParams 2191

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `nextParams` (packages/gui/src/electron/commands/parseDappParams.ts) control method name and params with casing or namespace ambiguity through a batch of rapid user-accessible actions and drive the sequence load persisted state -> render approval -> execute command so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseDappParams.ts` / `nextParams`
- Entrypoint: pairing URI/import flow
- Attacker controls: method name and params with casing or namespace ambiguity; through a batch of rapid user-accessible actions
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
