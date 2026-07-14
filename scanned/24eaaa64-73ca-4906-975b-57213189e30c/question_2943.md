# Q2943: pool-plotnft via PlotNFTExternal 2943

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTExternal` (packages/api/src/@types/PlotNFTExternal.ts) control pool URL/login response with mismatched launcher ID with a delayed metadata fetch and drive the sequence import -> parse -> preview -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFTExternal.ts` / `PlotNFTExternal`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; with a delayed metadata fetch
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
