# Q2740: pool-plotnft via totalPointsFound24 2740

## Question
Can an unprivileged attacker entering through the pool join/change flow in `totalPointsFound24` (packages/gui/src/components/plotNFT/PlotNFTCard.tsx) control payout address with network or Unicode ambiguity through a batch of rapid user-accessible actions and drive the sequence load persisted state -> render approval -> execute command so the GUI would route pool login links through unsafe external URL handling, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTCard.tsx` / `totalPointsFound24`
- Entrypoint: pool join/change flow
- Attacker controls: payout address with network or Unicode ambiguity; through a batch of rapid user-accessible actions
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
