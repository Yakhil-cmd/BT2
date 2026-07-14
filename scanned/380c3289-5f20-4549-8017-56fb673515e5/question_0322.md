# Q322: walletconnect via parseDappParams 322

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `parseDappParams` (packages/gui/src/electron/commands/parseDappParams.ts) control chainId/account/fingerprint mismatch after a network switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseDappParams.ts` / `parseDappParams`
- Entrypoint: stored dapp permission reload
- Attacker controls: chainId/account/fingerprint mismatch; after a network switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
