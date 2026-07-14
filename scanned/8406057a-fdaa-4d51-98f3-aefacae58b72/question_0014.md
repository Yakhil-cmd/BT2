# Q14: rpc-state via VCWallet 14

## Question
Can an unprivileged attacker entering through the service command response correlation in `VCWallet` (packages/api/src/wallets/VC.ts) control RPC error payload shaped like success with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/VC.ts` / `VCWallet`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; with a cached permission entry
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
