# Q1236: walletconnect via for 1236

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `for` (packages/gui/src/electron/commands/filterRequestedDappCommands.ts) control previously granted bypass permission combined with profile switch after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/filterRequestedDappCommands.ts` / `for`
- Entrypoint: WalletConnect session proposal
- Attacker controls: previously granted bypass permission combined with profile switch; after a profile switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
