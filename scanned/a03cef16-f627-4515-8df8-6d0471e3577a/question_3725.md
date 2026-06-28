# Q3725: EvmErc20V2.sol withdrawals revert/success split at burn-before-external-call sequencing in `withdrawToEthereum`

## Question
Can a user make burn-before-external-call sequencing in `withdrawToEthereum` treat a failed external exit as if the withdrawal succeeded, or vice versa, leaving token supply and bridged value out of sync and causing Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `burn-before-external-call sequencing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split external-call result handling from supply semantics at the targeted function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Inject failing exit targets in tests and assert supply and user balances always match the real external outcome. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
