# Q1345: rpc-state via setSelectedTab 1345

## Question
Can an unprivileged attacker entering through the service command response correlation in `setSelectedTab` (packages/wallets/src/components/standard/WalletStandard.tsx) control RPC error payload shaped like success with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/standard/WalletStandard.tsx` / `setSelectedTab`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; with a delayed metadata fetch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
