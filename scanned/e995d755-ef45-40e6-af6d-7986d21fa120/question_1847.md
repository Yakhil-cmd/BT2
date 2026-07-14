# Q1847: rpc-state via getUnknownCATs 1847

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `getUnknownCATs` (packages/gui/src/util/getUnknownCATs.ts) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/getUnknownCATs.ts` / `getUnknownCATs`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
