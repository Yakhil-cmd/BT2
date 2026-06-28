# Q3701: EvmErc20V2.sol withdrawals burn/external ordering at recipient byte encoding in `withdrawToNear`

## Question
Can an unprivileged token holder use a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract with ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing so that recipient byte encoding in `withdrawToNear` burns user balance before the external exit path is truly final, then recovers or replays value and causes Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `recipient byte encoding in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: target burn-before-external-call ordering at the named withdrawal step.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Force the downstream exit call to revert or misbehave and assert supply and user balance either revert or are fully compensated. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
