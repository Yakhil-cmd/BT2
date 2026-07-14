# Q2742: pool-plotnft via PlotNFTName 2742

## Question
Can an unprivileged attacker entering through the payout instruction update in `PlotNFTName` (packages/gui/src/components/plotNFT/PlotNFTName.tsx) control external pool metadata changing between preview and submit through a batch of rapid user-accessible actions and drive the sequence import -> parse -> preview -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTName.tsx` / `PlotNFTName`
- Entrypoint: payout instruction update
- Attacker controls: external pool metadata changing between preview and submit; through a batch of rapid user-accessible actions
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
