# Q3242: rpc-state via getExecutablePath 3242

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getExecutablePath` (packages/gui/src/electron/utils/chiaEnvironment.js) control RPC error payload shaped like success with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/chiaEnvironment.js` / `getExecutablePath`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
