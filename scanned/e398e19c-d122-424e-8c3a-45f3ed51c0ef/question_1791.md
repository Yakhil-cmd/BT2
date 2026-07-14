# Q1791: rpc-state via showError 1791

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `showError` (packages/core/src/hooks/useShowError.tsx) control response object with duplicate camelCase/snake_case keys with conflicting localStorage preferences and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useShowError.tsx` / `showError`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; with conflicting localStorage preferences
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
