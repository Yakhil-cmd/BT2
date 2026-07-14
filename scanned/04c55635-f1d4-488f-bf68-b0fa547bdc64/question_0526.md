# Q526: rpc-state via ServiceConstructor 526

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `ServiceConstructor` (packages/api-react/src/@types/ServiceConstructor.ts) control subscription event for a different wallet/fingerprint after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/@types/ServiceConstructor.ts` / `ServiceConstructor`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; after a network switch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
