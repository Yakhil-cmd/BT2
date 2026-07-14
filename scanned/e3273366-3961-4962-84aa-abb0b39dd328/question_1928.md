# Q1928: walletconnect via handleClose 1928

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `handleClose` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control batched sign/spend command sequence after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `handleClose`
- Entrypoint: WalletConnect session proposal
- Attacker controls: batched sign/spend command sequence; after a failed RPC response
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
