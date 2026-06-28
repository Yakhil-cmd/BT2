# Q3555: EvmErc20.sol withdrawals mirror version split at recipient byte encoding in `withdrawToNear`

## Question
Can a user exploit behavioral differences between mirrored token versions through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` so recipient byte encoding in `withdrawToNear` on one version exits value under assumptions the engine or other version does not share, causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `recipient byte encoding in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: compare the same logical withdrawal across versions and hunt for mismatched semantics.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Run the same withdrawal tests against both token versions and diff supply, revert, and exit behavior. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
