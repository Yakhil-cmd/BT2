# Q3524: EvmErc20.sol withdrawals repeat withdraw around burn-before-external-call sequencing in `withdrawToNear`

## Question
Can a user repeat the same logical withdrawal through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` so that burn-before-external-call sequencing in `withdrawToNear` applies some supply or exit side effect twice for one intended burn, leading to Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: look for replay or idempotence gaps in the withdrawal path.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Repeat the same withdrawal under success and forced-failure timing and assert total burned and exited amounts remain single-applied. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
