# Q3714: EvmErc20V2.sol withdrawals sandwiched failure around recipient byte encoding in `withdrawToNear`

## Question
Can a user place one withdrawal before and one after a forced failure at recipient byte encoding in `withdrawToNear` so the middle failure disturbs shared state and makes one of the successful calls mis-account value, causing Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `recipient byte encoding in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: look for shared mutable state across withdrawal attempts.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Execute success-fail-success sequences and compare supply and user balances after every step. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
