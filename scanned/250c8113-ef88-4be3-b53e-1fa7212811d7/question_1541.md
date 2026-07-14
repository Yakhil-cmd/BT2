# Q1541: pool-plotnft via nft 1541

## Question
Can an unprivileged attacker entering through the payout instruction update in `nft` (packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx) control payout address with network or Unicode ambiguity with a delayed metadata fetch and drive the sequence import -> parse -> preview -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx` / `nft`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; with a delayed metadata fetch
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
