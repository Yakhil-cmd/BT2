# Q2723: rpc-state via getLocationState 2723

## Question
Can an unprivileged attacker entering through the RTK query cache update in `getLocationState` (packages/core/src/hooks/useSerializedNavigationState.ts) control subscription event for a different wallet/fingerprint with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useSerializedNavigationState.ts` / `getLocationState`
- Entrypoint: RTK query cache update
- Attacker controls: subscription event for a different wallet/fingerprint; with a redirected remote resource
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
