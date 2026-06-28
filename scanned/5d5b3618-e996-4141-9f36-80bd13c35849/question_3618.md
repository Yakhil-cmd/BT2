# Q3618: EvmErc20.sol withdrawals callbackless loss after zero and extreme amount handling

## Question
Can a user trigger zero and extreme amount handling into a path where downstream recovery depends on a callback the token contract never validates, so lost value cannot be reclaimed and causes Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `zero and extreme amount handling`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: find a withdraw path that assumes external recovery without local validation of the final outcome.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Force downstream failure and inspect whether any path exists to restore the burned tokens safely. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
