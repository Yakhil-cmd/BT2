# Q3798: EvmErc20V2.sol withdrawals callbackless loss after interaction with refund-capable engine logic

## Question
Can a user trigger interaction with refund-capable engine logic into a path where downstream recovery depends on a callback the token contract never validates, so lost value cannot be reclaimed and causes Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `interaction with refund-capable engine logic`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: find a withdraw path that assumes external recovery without local validation of the final outcome.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Force downstream failure and inspect whether any path exists to restore the burned tokens safely. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
