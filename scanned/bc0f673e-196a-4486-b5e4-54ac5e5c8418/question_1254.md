# Q1254: walletconnect via isSpendCommand 1254

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `isSpendCommand` (packages/gui/src/electron/commands/isSpendCommand.ts) control session metadata with misleading origin/icon/name fields with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isSpendCommand.ts` / `isSpendCommand`
- Entrypoint: WalletConnect session proposal
- Attacker controls: session metadata with misleading origin/icon/name fields; with a delayed metadata fetch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
