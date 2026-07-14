# Q2423: rpc-state via SignagePoint 2423

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `SignagePoint` (packages/api/src/@types/SignagePoint.ts) control large numeric fields near JS precision limits during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/SignagePoint.ts` / `SignagePoint`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; during a pending modal confirmation
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
