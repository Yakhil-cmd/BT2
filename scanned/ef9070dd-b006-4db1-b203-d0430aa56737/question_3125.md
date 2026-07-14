# Q3125: walletconnect via if 3125

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `if` (packages/gui/src/electron/commands/parseDappParams.ts) control batched sign/spend command sequence after a profile switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseDappParams.ts` / `if`
- Entrypoint: dapp command permission prompt
- Attacker controls: batched sign/spend command sequence; after a profile switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
