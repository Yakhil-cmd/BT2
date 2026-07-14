# Q1968: rpc-state via show 1968

## Question
Can an unprivileged attacker entering through the RTK query cache update in `show` (packages/wallets/src/hooks/useHiddenWallet.ts) control large numeric fields near JS precision limits with a cached permission entry and drive the sequence open notification -> resolve details -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/hooks/useHiddenWallet.ts` / `show`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with a cached permission entry
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
