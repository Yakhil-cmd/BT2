# Q1015: walletconnect via getDappCommandMetadata 1015

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `getDappCommandMetadata` (packages/gui/src/electron/commands/getDappCommandMetadata.ts) control method name and params with casing or namespace ambiguity with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/getDappCommandMetadata.ts` / `getDappCommandMetadata`
- Entrypoint: stored dapp permission reload
- Attacker controls: method name and params with casing or namespace ambiguity; with hidden Unicode characters
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
