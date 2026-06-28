# Q1603: ETH connector withdraw partial burn or refund at one-yocto gating before withdrawal

## Question
Can an attacker force one-yocto gating before withdrawal into a path where value is burned, escrowed, or promised before the success condition is finalized, then reclaim or replay value so the protocol loses funds and suffers Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `one-yocto gating before withdrawal`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: attack ordering between burn/escrow and final success acknowledgement at the named step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Instrument the failing downstream branch and assert burned or escrowed value is either fully restored or never consumed. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
