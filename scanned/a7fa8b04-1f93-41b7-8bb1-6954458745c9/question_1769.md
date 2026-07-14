# Q1769: pool-plotnft via handleAddPool 1769

## Question
Can an unprivileged attacker entering through the payout instruction update in `handleAddPool` (packages/gui/src/components/pool/PoolOverview.tsx) control stale PlotNFT wallet id during pool change after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolOverview.tsx` / `handleAddPool`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; after a profile switch
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
