# Q2885: walletconnect via isSignCommand 2885

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `isSignCommand` (packages/gui/src/electron/commands/isSignCommand.ts) control previously granted bypass permission combined with profile switch with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isSignCommand.ts` / `isSignCommand`
- Entrypoint: WalletConnect session proposal
- Attacker controls: previously granted bypass permission combined with profile switch; with case-normalized identifiers
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
