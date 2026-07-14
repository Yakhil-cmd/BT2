# Q901: rpc-state via useFullNodeState 901

## Question
Can an unprivileged attacker entering through the RTK query cache update in `useFullNodeState` (packages/gui/src/hooks/useFullNodeState.ts) control out-of-order event and query responses after canceling and reopening the dialog and drive the sequence open notification -> resolve details -> execute so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useFullNodeState.ts` / `useFullNodeState`
- Entrypoint: RTK query cache update
- Attacker controls: out-of-order event and query responses; after canceling and reopening the dialog
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
