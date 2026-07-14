# Q15: rpc-state via VCWallet 15

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `VCWallet` (packages/api/src/wallets/VC.ts) control RPC error payload shaped like success with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/VC.ts` / `VCWallet`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with a cached permission entry
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
