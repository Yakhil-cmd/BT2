# Q93: rpc-state via emptyMnemonic 93

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `emptyMnemonic` (packages/wallets/src/components/WalletImport.tsx) control subscription event for a different wallet/fingerprint with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletImport.tsx` / `emptyMnemonic`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with hidden Unicode characters
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
