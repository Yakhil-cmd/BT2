# Q2236: rpc-state via WalletsDropdown 2236

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `WalletsDropdown` (packages/wallets/src/components/WalletsDropdown.tsx) control response object with duplicate camelCase/snake_case keys with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletsDropdown.tsx` / `WalletsDropdown`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; with a redirected remote resource
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
