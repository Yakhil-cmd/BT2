# Q3571: EvmErc20.sol withdrawals balance snapshot gap at burn-before-external-call sequencing in `withdrawToEthereum`

## Question
Can a user exploit stale balance assumptions around burn-before-external-call sequencing in `withdrawToEthereum` by sequencing approvals, transfers, and withdraws so burn and exit logic observe different balances and cause Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: attack balance snapshots consumed by the targeted function across intra-transaction state changes.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Sequence transfer/approval/withdraw operations and assert the burned balance matches the exiting amount exactly. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
