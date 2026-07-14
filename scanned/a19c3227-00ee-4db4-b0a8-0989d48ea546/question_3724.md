# Q3724: rpc-state via service_names 3724

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `service_names` (packages/gui/src/util/service_names.js) control large numeric fields near JS precision limits with hidden Unicode characters and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/service_names.js` / `service_names`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with hidden Unicode characters
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
