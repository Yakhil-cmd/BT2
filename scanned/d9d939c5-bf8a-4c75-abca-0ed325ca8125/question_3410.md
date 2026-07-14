# Q3410: pool-plotnft via PlotNFTExternalState 3410

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTExternalState` (packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx) control payout address with network or Unicode ambiguity after a profile switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx` / `PlotNFTExternalState`
- Entrypoint: farmer reward address management
- Attacker controls: payout address with network or Unicode ambiguity; after a profile switch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
