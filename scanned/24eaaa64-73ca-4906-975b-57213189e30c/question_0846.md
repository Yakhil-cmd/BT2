# Q846: rpc-state via useHiddenList 846

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useHiddenList` (packages/core/src/hooks/useHiddenList.ts) control large numeric fields near JS precision limits with reordered RPC events and drive the sequence load persisted state -> render approval -> execute command so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useHiddenList.ts` / `useHiddenList`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; with reordered RPC events
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
