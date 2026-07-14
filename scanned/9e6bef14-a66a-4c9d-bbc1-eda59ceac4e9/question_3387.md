# Q3387: rpc-state via SignMessageEntities 3387

## Question
Can an unprivileged attacker entering through the RTK query cache update in `SignMessageEntities` (packages/gui/src/components/signVerify/SignMessageEntities.ts) control RPC error payload shaped like success with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignMessageEntities.ts` / `SignMessageEntities`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
