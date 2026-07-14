# Q1347: rpc-state via WalletStandardCards 1347

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WalletStandardCards` (packages/wallets/src/components/standard/WalletStandardCards.tsx) control RPC error payload shaped like success with conflicting localStorage preferences and drive the sequence connect -> approve -> switch context -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/standard/WalletStandardCards.tsx` / `WalletStandardCards`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with conflicting localStorage preferences
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
