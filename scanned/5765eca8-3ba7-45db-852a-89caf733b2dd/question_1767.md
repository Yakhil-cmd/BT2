# Q1767: pool-plotnft via rows 1767

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `rows` (packages/gui/src/components/pool/PoolInfo.tsx) control stale PlotNFT wallet id during pool change after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolInfo.tsx` / `rows`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: stale PlotNFT wallet id during pool change; after a failed RPC response
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
