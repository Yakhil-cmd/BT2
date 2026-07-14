# Q1493: rpc-state via WalletCreate 1493

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `WalletCreate` (packages/api/src/@types/WalletCreate.ts) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/WalletCreate.ts` / `WalletCreate`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
