# Q1728: ETH connector withdraw gas starvation around attached gas computation in `calculate_attached_gas`

## Question
Can an attacker choose input size or call ordering through `withdraw()` on the Aurora engine contract so that attached gas computation in `calculate_attached_gas` creates a promise graph with too little gas to finish safely, stranding funds or state and causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `attached gas computation in `calculate_attached_gas``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: target gas sizing logic attached to the connector promise or callback path.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Run low-prepaid-gas and high-input-size cases and assert the function cannot strand value or half-written mapping state when gas is tight. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
