# Q2285: rpc-state via getWalletPrimaryTitle 2285

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `getWalletPrimaryTitle` (packages/wallets/src/utils/getWalletPrimaryTitle.ts) control RPC error payload shaped like success after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/utils/getWalletPrimaryTitle.ts` / `getWalletPrimaryTitle`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; after a network switch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
