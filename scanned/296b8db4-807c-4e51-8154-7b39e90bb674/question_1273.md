# Q1273: rpc-state via handleClose 1273

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `handleClose` (packages/wallets/src/components/WalletEmptyDialog.tsx) control response object with duplicate camelCase/snake_case keys with hidden Unicode characters and drive the sequence load persisted state -> render approval -> execute command so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletEmptyDialog.tsx` / `handleClose`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; with hidden Unicode characters
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
