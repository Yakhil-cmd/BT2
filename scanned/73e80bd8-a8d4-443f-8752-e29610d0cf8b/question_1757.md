# Q1757: ETH connector withdraw connector target confusion in withdraw serialization type assumptions stored in connector state

## Question
Can an attacker route withdraw serialization type assumptions stored in connector state toward the wrong connector account or downstream method through `withdraw()` on the Aurora engine contract, so a valid-looking request lands in the wrong contract context and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `withdraw serialization type assumptions stored in connector state`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: abuse connector account selection and method-name routing near the targeted helper.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Insolvency
- Fast validation: Inspect the generated promise target account and method for crafted inputs and assert they always match the intended operation. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
