# Q3676: pool-plotnft via PlotNFTName 3676

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTName` (packages/gui/src/components/plotNFT/PlotNFTName.tsx) control payout address with network or Unicode ambiguity after a profile switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTName.tsx` / `PlotNFTName`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: payout address with network or Unicode ambiguity; after a profile switch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
