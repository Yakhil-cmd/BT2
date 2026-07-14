# Q323: walletconnect via parseDappParams 323

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `parseDappParams` (packages/gui/src/electron/commands/parseDappParams.ts) control chainId/account/fingerprint mismatch after a network switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseDappParams.ts` / `parseDappParams`
- Entrypoint: WalletConnect session proposal
- Attacker controls: chainId/account/fingerprint mismatch; after a network switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
