# Q2273: rpc-state via goBack 2273

## Question
Can an unprivileged attacker entering through the RTK query cache update in `goBack` (packages/wallets/src/components/create/WalletCreate.tsx) control subscription event for a different wallet/fingerprint with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/create/WalletCreate.tsx` / `goBack`
- Entrypoint: RTK query cache update
- Attacker controls: subscription event for a different wallet/fingerprint; with a delayed metadata fetch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
