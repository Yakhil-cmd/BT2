# Q3715: EvmErc20V2.sol withdrawals mirror version split at recipient byte encoding in `withdrawToNear`

## Question
Can a user exploit behavioral differences between mirrored token versions through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract so recipient byte encoding in `withdrawToNear` on one version exits value under assumptions the engine or other version does not share, causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `recipient byte encoding in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: compare the same logical withdrawal across versions and hunt for mismatched semantics.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Insolvency
- Fast validation: Run the same withdrawal tests against both token versions and diff supply, revert, and exit behavior. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
