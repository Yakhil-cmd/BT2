# Q3604: rpc-state via getUnfinishedBlockHeaders 3604

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `getUnfinishedBlockHeaders` (packages/api/src/services/FullNode.ts) control out-of-order event and query responses through a batch of rapid user-accessible actions and drive the sequence connect -> approve -> switch context -> execute so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/FullNode.ts` / `getUnfinishedBlockHeaders`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; through a batch of rapid user-accessible actions
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
