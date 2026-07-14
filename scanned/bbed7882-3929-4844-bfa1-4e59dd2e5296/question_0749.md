# Q749: rpc-state via CalculateRoyaltiesResponse 749

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `CalculateRoyaltiesResponse` (packages/api/src/@types/CalculateRoyaltiesResponse.ts) control response object with duplicate camelCase/snake_case keys with case-normalized identifiers and drive the sequence fetch -> cache -> refresh -> submit so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/CalculateRoyaltiesResponse.ts` / `CalculateRoyaltiesResponse`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; with case-normalized identifiers
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
