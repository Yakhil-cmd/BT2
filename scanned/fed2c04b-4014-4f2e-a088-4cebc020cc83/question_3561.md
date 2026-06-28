# Q3561: EvmErc20.sol withdrawals burn/external ordering at burn-before-external-call sequencing in `withdrawToEthereum`

## Question
Can an unprivileged token holder use a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` with ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing so that burn-before-external-call sequencing in `withdrawToEthereum` burns user balance before the external exit path is truly final, then recovers or replays value and causes Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: target burn-before-external-call ordering at the named withdrawal step.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Force the downstream exit call to revert or misbehave and assert supply and user balance either revert or are fully compensated. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
