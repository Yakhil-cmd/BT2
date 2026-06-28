# Q1614: ETH connector withdraw cross-asset mixup in one-yocto gating before withdrawal

## Question
Can an attacker use `withdraw()` on the Aurora engine contract to make one-yocto gating before withdrawal associate the wrong token contract, metadata, or bridge account with the current action, so one asset is credited or debited as another and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `one-yocto gating before withdrawal`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: abuse asset-identity assumptions at the targeted mapping or metadata step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Exercise different token identities around the same flow and assert each path touches only its own balances and metadata. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
