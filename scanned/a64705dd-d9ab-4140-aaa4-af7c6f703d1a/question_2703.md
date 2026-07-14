# Q2703: pool-plotnft via if 2703

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `if` (packages/gui/src/components/pool/PoolOverview.tsx) control stale PlotNFT wallet id during pool change with a duplicate identifier and drive the sequence download or render content -> trigger linked wallet action so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolOverview.tsx` / `if`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: stale PlotNFT wallet id during pool change; with a duplicate identifier
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
