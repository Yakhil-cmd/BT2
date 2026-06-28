# Q3833: EvmErc20V2.sol withdrawals rounding drift through total supply consistency after withdraw failures or reverts

## Question
Can a user exploit rounding or width conversions in total supply consistency after withdraw failures or reverts so repeated small withdrawals drift supply or exit amounts over time and cause Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `total supply consistency after withdraw failures or reverts`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: amplify any tiny mismatch at the withdrawal boundary across repeated calls.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Insolvency
- Fast validation: Run many tiny withdrawals and compare cumulative burned amount with cumulative exit amount. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
