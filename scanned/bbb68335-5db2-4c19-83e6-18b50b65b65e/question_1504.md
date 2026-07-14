# Q1504: rpc-state via addPlotProgress 1504

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `addPlotProgress` (packages/api/src/services/PlotterService.ts) control out-of-order event and query responses during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/PlotterService.ts` / `addPlotProgress`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; during a pending modal confirmation
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
