# Q3425: rpc-state via WebSocketAPI 3425

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WebSocketAPI` (packages/gui/src/electron/constants/WebSocketAPI.ts) control subscription event for a different wallet/fingerprint with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/WebSocketAPI.ts` / `WebSocketAPI`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with conflicting localStorage preferences
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
