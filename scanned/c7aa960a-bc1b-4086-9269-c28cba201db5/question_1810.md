# Q1810: pool-plotnft via if 1810

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `if` (packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx) control pool URL/login response with mismatched launcher ID after a network switch and drive the sequence import -> parse -> preview -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTUnconfirmedCard.tsx` / `if`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: pool URL/login response with mismatched launcher ID; after a network switch
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
