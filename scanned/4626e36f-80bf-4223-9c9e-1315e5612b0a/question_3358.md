# Q3358: pool-plotnft via UnconfirmedPlotNFT 3358

## Question
Can an unprivileged attacker entering through the payout instruction update in `UnconfirmedPlotNFT` (packages/api/src/@types/UnconfirmedPlotNFT.ts) control stale PlotNFT wallet id during pool change with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/UnconfirmedPlotNFT.ts` / `UnconfirmedPlotNFT`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; with a redirected remote resource
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
