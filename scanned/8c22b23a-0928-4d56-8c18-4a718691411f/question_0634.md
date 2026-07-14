# Q634: rpc-state via ensureDirectoryExists 634

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `ensureDirectoryExists` (packages/gui/src/electron/utils/ensureDirectoryExists.ts) control RPC error payload shaped like success after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/ensureDirectoryExists.ts` / `ensureDirectoryExists`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; after a profile switch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
