# Q3811: EvmErc20V2.sol withdrawals balance snapshot gap at exit address constant selection

## Question
Can a user exploit stale balance assumptions around exit address constant selection by sequencing approvals, transfers, and withdraws so burn and exit logic observe different balances and cause Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `exit address constant selection`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: attack balance snapshots consumed by the targeted function across intra-transaction state changes.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Sequence transfer/approval/withdraw operations and assert the burned balance matches the exiting amount exactly. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
