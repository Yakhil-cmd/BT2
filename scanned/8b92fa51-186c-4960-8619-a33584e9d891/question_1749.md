# Q1749: ETH connector withdraw recipient mismatch in withdraw serialization type assumptions stored in connector state

## Question
Can an attacker make withdraw serialization type assumptions stored in connector state route value to a different recipient than the one visible at the public entrypoint, via encoding, truncation, or mapping confusion, causing Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `withdraw serialization type assumptions stored in connector state`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: exploit a mismatch between public recipient intent and downstream recipient bytes or addresses.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Insolvency
- Fast validation: Use crafted recipient values and compare the entrypoint-visible recipient with the recipient encoded in downstream calls or minted balances. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
