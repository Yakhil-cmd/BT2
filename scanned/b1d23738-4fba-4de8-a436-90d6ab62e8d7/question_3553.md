# Q3553: EvmErc20.sol withdrawals rounding drift through recipient byte encoding in `withdrawToNear`

## Question
Can a user exploit rounding or width conversions in recipient byte encoding in `withdrawToNear` so repeated small withdrawals drift supply or exit amounts over time and cause Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `recipient byte encoding in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: amplify any tiny mismatch at the withdrawal boundary across repeated calls.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Run many tiny withdrawals and compare cumulative burned amount with cumulative exit amount. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
