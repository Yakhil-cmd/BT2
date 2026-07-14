# Q871: pool-plotnft via PlotNFTAdd 871

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PlotNFTAdd` (packages/gui/src/components/plotNFT/PlotNFTAdd.tsx) control pool URL/login response with mismatched launcher ID after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTAdd.tsx` / `PlotNFTAdd`
- Entrypoint: pool join/change flow
- Attacker controls: pool URL/login response with mismatched launcher ID; after a profile switch
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
