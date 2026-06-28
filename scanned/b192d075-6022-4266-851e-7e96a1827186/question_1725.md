# Q1725: ETH connector withdraw promise shape confusion in attached gas computation in `calculate_attached_gas`

## Question
Can an attacker make attached gas computation in `calculate_attached_gas` observe an unexpected promise count, result index, or result type through `withdraw()` on the Aurora engine contract, so the wrong branch mints, refunds, or registers state and leads to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `attached gas computation in `calculate_attached_gas``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: target assumptions about promise shape and result indexing inside the named connector step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Mock or simulate alternate promise-result layouts and assert the function rejects every malformed layout before mutating value-bearing state. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
