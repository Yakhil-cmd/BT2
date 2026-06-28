# Q1667: ETH connector withdraw malformed JSON or borsh at recipient address serialization for the downstream connector

## Question
Can an attacker send malformed but parseable JSON or borsh through `withdraw()` on the Aurora engine contract so that recipient address serialization for the downstream connector accepts a structurally valid payload with a semantically dangerous meaning, leading to Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `recipient address serialization for the downstream connector`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: look for edge-case decoding that preserves syntax but changes business meaning at the targeted step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Fuzz the relevant JSON or borsh fields and assert downstream promise payloads and state changes remain semantically canonical. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
