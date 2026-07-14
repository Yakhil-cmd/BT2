# Q368: rpc-state via getPrimaryTitle 368

## Question
Can an unprivileged attacker entering through the service command response correlation in `getPrimaryTitle` (packages/wallets/src/components/WalletsDropdown.tsx) control RPC error payload shaped like success with reordered RPC events and drive the sequence fetch -> cache -> refresh -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletsDropdown.tsx` / `getPrimaryTitle`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; with reordered RPC events
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
