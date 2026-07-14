# Q81: walletconnect via getDappCommandMetadata 81

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `getDappCommandMetadata` (packages/gui/src/electron/commands/getDappCommandMetadata.ts) control batched sign/spend command sequence during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/getDappCommandMetadata.ts` / `getDappCommandMetadata`
- Entrypoint: WalletConnect session proposal
- Attacker controls: batched sign/spend command sequence; during a pending modal confirmation
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
