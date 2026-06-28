# Q3576: EvmErc20.sol withdrawals pause assumption gap in burn-before-external-call sequencing in `withdrawToEthereum`

## Question
Can a user reach burn-before-external-call sequencing in `withdrawToEthereum` during a paused or partially paused engine state in a way that the token contract does not expect, causing value to be burned into a blocked path and leading to Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: check how the token withdraw path behaves when its downstream engine route is not fully available.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Pause the relevant engine-side path and confirm the token withdraw function cannot burn value into an unrecoverable state. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
