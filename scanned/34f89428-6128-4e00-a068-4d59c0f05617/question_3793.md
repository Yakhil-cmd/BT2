# Q3793: EvmErc20V2.sol withdrawals rounding drift through interaction with refund-capable engine logic

## Question
Can a user exploit rounding or width conversions in interaction with refund-capable engine logic so repeated small withdrawals drift supply or exit amounts over time and cause Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `interaction with refund-capable engine logic`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: amplify any tiny mismatch at the withdrawal boundary across repeated calls.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Run many tiny withdrawals and compare cumulative burned amount with cumulative exit amount. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
