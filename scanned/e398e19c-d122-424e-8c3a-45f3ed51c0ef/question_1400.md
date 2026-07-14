# Q1400: walletconnect via if 1400

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `if` (packages/gui/src/electron/utils/openPairDialog.ts) control batched sign/spend command sequence with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/openPairDialog.ts` / `if`
- Entrypoint: pairing URI/import flow
- Attacker controls: batched sign/spend command sequence; with a stale Redux cache
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
