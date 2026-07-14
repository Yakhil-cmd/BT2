# Q3218: rpc-state via switch 3218

## Question
Can an unprivileged attacker entering through the service command response correlation in `switch` (packages/wallets/src/utils/getWalletPrimaryTitle.ts) control subscription event for a different wallet/fingerprint with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/utils/getWalletPrimaryTitle.ts` / `switch`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
