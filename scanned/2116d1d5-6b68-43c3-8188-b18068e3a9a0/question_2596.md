# Q2596: rpc-state via daemonApi 2596

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `daemonApi` (packages/api-react/src/services/daemon.ts) control large numeric fields near JS precision limits with reordered RPC events and drive the sequence load persisted state -> render approval -> execute command so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/services/daemon.ts` / `daemonApi`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with reordered RPC events
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
