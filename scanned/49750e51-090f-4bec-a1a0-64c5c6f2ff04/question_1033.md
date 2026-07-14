# Q1033: rpc-state via stringPropertiesToNumbers 1033

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `stringPropertiesToNumbers` (packages/wallets/src/hooks/useClawbackDefaultTime.tsx) control large numeric fields near JS precision limits after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/hooks/useClawbackDefaultTime.tsx` / `stringPropertiesToNumbers`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
