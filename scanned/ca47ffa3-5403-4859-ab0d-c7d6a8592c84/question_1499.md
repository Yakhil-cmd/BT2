# Q1499: pool-plotnft via PlotNFTState 1499

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PlotNFTState` (packages/api/src/constants/PlotNFTState.ts) control payout address with network or Unicode ambiguity after a network switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/constants/PlotNFTState.ts` / `PlotNFTState`
- Entrypoint: pool join/change flow
- Attacker controls: payout address with network or Unicode ambiguity; after a network switch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
