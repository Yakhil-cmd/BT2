# Q1543: pool-plotnft via handleClose 1543

## Question
Can an unprivileged attacker entering through the pool login link action in `handleClose` (packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx) control pool URL/login response with mismatched launcher ID during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx` / `handleClose`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; during a pending modal confirmation
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
