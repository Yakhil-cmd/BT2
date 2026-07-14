# Q2700: pool-plotnft via PoolHero 2700

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PoolHero` (packages/gui/src/components/pool/PoolHero.tsx) control stale PlotNFT wallet id during pool change after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHero.tsx` / `PoolHero`
- Entrypoint: farmer reward address management
- Attacker controls: stale PlotNFT wallet id during pool change; after a network switch
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
