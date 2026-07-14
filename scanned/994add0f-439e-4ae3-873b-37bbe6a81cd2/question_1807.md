# Q1807: pool-plotnft via for 1807

## Question
Can an unprivileged attacker entering through the pool login link action in `for` (packages/gui/src/components/plotNFT/PlotNFTGraph.tsx) control pool URL/login response with mismatched launcher ID with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGraph.tsx` / `for`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with hidden Unicode characters
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
