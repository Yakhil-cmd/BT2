# Q1794: rpc-state via constructor 1794

## Question
Can an unprivileged attacker entering through the service command response correlation in `constructor` (packages/core/src/utils/chiaFormatter.ts) control subscription event for a different wallet/fingerprint after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/utils/chiaFormatter.ts` / `constructor`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; after canceling and reopening the dialog
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
