# Q1674: ETH connector withdraw cross-asset mixup in recipient address serialization for the downstream connector

## Question
Can an attacker use `withdraw()` on the Aurora engine contract to make recipient address serialization for the downstream connector associate the wrong token contract, metadata, or bridge account with the current action, so one asset is credited or debited as another and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `recipient address serialization for the downstream connector`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: abuse asset-identity assumptions at the targeted mapping or metadata step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Exercise different token identities around the same flow and assert each path touches only its own balances and metadata. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
