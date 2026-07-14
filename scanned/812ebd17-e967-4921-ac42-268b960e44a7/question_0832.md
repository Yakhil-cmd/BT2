# Q832: pool-plotnft via PoolHero 832

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PoolHero` (packages/gui/src/components/pool/PoolHero.tsx) control pool URL/login response with mismatched launcher ID with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHero.tsx` / `PoolHero`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: pool URL/login response with mismatched launcher ID; with hidden Unicode characters
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
