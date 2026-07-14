# Q877: pool-plotnft via StyledCollapse 877

## Question
Can an unprivileged attacker entering through the pool join/change flow in `StyledCollapse` (packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx) control payout address with network or Unicode ambiguity with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx` / `StyledCollapse`
- Entrypoint: pool join/change flow
- Attacker controls: payout address with network or Unicode ambiguity; with a cached permission entry
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
