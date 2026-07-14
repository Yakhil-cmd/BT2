# Q833: pool-plotnft via PoolInfo 833

## Question
Can an unprivileged attacker entering through the payout instruction update in `PoolInfo` (packages/gui/src/components/pool/PoolInfo.tsx) control pool URL/login response with mismatched launcher ID with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolInfo.tsx` / `PoolInfo`
- Entrypoint: payout instruction update
- Attacker controls: pool URL/login response with mismatched launcher ID; with hidden Unicode characters
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
