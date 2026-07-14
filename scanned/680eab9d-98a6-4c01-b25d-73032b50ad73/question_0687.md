# Q687: pool-plotnft via LOCAL_STORAGE_KEY 687

## Question
Can an unprivileged attacker entering through the farmer reward address management in `LOCAL_STORAGE_KEY` (packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts) control pool URL/login response with mismatched launcher ID with a redirected remote resource and drive the sequence download or render content -> trigger linked wallet action so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useUnconfirmedPlotNFTs.ts` / `LOCAL_STORAGE_KEY`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; with a redirected remote resource
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
