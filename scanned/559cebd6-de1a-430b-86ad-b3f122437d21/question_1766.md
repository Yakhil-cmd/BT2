# Q1766: pool-plotnft via handleJoinPool 1766

## Question
Can an unprivileged attacker entering through the pool join/change flow in `handleJoinPool` (packages/gui/src/components/pool/PoolHero.tsx) control stale PlotNFT wallet id during pool change after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHero.tsx` / `handleJoinPool`
- Entrypoint: pool join/change flow
- Attacker controls: stale PlotNFT wallet id during pool change; after a failed RPC response
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
