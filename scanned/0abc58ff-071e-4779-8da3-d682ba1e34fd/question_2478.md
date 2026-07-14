# Q2478: pool-plotnft via PlotNFTSelectPool 2478

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTSelectPool` (packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx) control stale PlotNFT wallet id during pool change after a profile switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx` / `PlotNFTSelectPool`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: stale PlotNFT wallet id during pool change; after a profile switch
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
