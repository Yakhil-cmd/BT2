# Q850: rpc-state via useMode 850

## Question
Can an unprivileged attacker entering through the service command response correlation in `useMode` (packages/core/src/hooks/useMode.ts) control response object with duplicate camelCase/snake_case keys with a cached permission entry and drive the sequence connect -> approve -> switch context -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useMode.ts` / `useMode`
- Entrypoint: service command response correlation
- Attacker controls: response object with duplicate camelCase/snake_case keys; with a cached permission entry
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
