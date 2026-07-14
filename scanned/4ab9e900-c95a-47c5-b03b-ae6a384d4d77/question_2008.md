# Q2008: pool-plotnft via PlotNFTExternal 2008

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTExternal` (packages/api/src/@types/PlotNFTExternal.ts) control external pool metadata changing between preview and submit with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFTExternal.ts` / `PlotNFTExternal`
- Entrypoint: farmer reward address management
- Attacker controls: external pool metadata changing between preview and submit; with a stale Redux cache
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
