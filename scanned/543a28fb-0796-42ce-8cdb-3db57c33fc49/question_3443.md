# Q3443: rpc-state via manageDaemonLifetime 3443

## Question
Can an unprivileged attacker entering through the RTK query cache update in `manageDaemonLifetime` (packages/gui/src/electron/utils/manageDaemonLifetime.ts) control RPC error payload shaped like success with a cached permission entry and drive the sequence select -> edit backing object -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/manageDaemonLifetime.ts` / `manageDaemonLifetime`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with a cached permission entry
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
