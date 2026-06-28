# Q3824: EvmErc20V2.sol withdrawals repeat withdraw around total supply consistency after withdraw failures or reverts

## Question
Can a user repeat the same logical withdrawal through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract so that total supply consistency after withdraw failures or reverts applies some supply or exit side effect twice for one intended burn, leading to Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `total supply consistency after withdraw failures or reverts`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: look for replay or idempotence gaps in the withdrawal path.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Repeat the same withdrawal under success and forced-failure timing and assert total burned and exited amounts remain single-applied. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
