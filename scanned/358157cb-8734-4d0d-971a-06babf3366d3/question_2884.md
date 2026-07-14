# Q2884: walletconnect via isSignCommand 2884

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `isSignCommand` (packages/gui/src/electron/commands/isSignCommand.ts) control previously granted bypass permission combined with profile switch with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isSignCommand.ts` / `isSignCommand`
- Entrypoint: stored dapp permission reload
- Attacker controls: previously granted bypass permission combined with profile switch; with case-normalized identifiers
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
