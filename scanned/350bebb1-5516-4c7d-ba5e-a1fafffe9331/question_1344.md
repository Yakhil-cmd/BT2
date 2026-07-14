# Q1344: rpc-state via setSelectedTab 1344

## Question
Can an unprivileged attacker entering through the RTK query cache update in `setSelectedTab` (packages/wallets/src/components/standard/WalletStandard.tsx) control out-of-order event and query responses with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/standard/WalletStandard.tsx` / `setSelectedTab`
- Entrypoint: RTK query cache update
- Attacker controls: out-of-order event and query responses; with a delayed metadata fetch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
