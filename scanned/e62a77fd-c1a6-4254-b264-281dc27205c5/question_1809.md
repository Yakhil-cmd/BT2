# Q1809: pool-plotnft via if 1809

## Question
Can an unprivileged attacker entering through the pool join/change flow in `if` (packages/gui/src/components/plotNFT/PlotNFTState.tsx) control external pool metadata changing between preview and submit with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTState.tsx` / `if`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; with hidden Unicode characters
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
