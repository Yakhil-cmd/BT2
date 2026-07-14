# Q1641: rpc-state via global.d 1641

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `global.d` (packages/api-react/src/@types/global.d.ts) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/@types/global.d.ts` / `global.d`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
