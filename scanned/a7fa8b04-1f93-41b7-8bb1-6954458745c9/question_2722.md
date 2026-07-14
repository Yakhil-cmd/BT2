# Q2722: rpc-state via useScrollbarsSettings 2722

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useScrollbarsSettings` (packages/core/src/hooks/useScrollbarsSettings.tsx) control subscription event for a different wallet/fingerprint with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useScrollbarsSettings.tsx` / `useScrollbarsSettings`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
