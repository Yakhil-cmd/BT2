# Q2361: pool-plotnft via usePlotNFTExternalDetails 2361

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `usePlotNFTExternalDetails` (packages/gui/src/hooks/usePlotNFTExternalDetails.ts) control payout address with network or Unicode ambiguity with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTExternalDetails.ts` / `usePlotNFTExternalDetails`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: payout address with network or Unicode ambiguity; with case-normalized identifiers
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
