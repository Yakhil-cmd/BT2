# Q585: rpc-state via SignMessageEntities 585

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `SignMessageEntities` (packages/gui/src/components/signVerify/SignMessageEntities.ts) control subscription event for a different wallet/fingerprint after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignMessageEntities.ts` / `SignMessageEntities`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; after a network switch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
