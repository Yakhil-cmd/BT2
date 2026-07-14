# Q2575: rpc-state via global.d 2575

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `global.d` (packages/api-react/src/@types/global.d.ts) control out-of-order event and query responses during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/@types/global.d.ts` / `global.d`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; during a pending modal confirmation
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
