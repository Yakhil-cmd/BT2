# Q316: walletconnect via isBalanceCommand 316

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `isBalanceCommand` (packages/gui/src/electron/commands/isBalanceCommand.ts) control session metadata with misleading origin/icon/name fields after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isBalanceCommand.ts` / `isBalanceCommand`
- Entrypoint: stored dapp permission reload
- Attacker controls: session metadata with misleading origin/icon/name fields; after a network switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
