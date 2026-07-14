# Q3397: rpc-state via index 3397

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `index` (packages/wallets/src/components/index.ts) control RPC error payload shaped like success through a batch of rapid user-accessible actions and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/index.ts` / `index`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; through a batch of rapid user-accessible actions
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
