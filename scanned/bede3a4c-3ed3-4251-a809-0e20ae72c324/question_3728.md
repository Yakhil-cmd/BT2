# Q3728: EvmErc20V2.sol withdrawals event meaning split around burn-before-external-call sequencing in `withdrawToEthereum`

## Question
Can a user make burn-before-external-call sequencing in `withdrawToEthereum` emit or imply a successful withdrawal while the actual exit side effect differs, allowing downstream systems to act on false success and causing Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `burn-before-external-call sequencing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: compare what the contract appears to signal with what the exit contract actually receives.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Capture events and external call payloads and confirm they always represent the same withdrawal result. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
