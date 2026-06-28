# Q3696: EvmErc20V2.sol withdrawals pause assumption gap in burn-before-external-call sequencing in `withdrawToNear`

## Question
Can a user reach burn-before-external-call sequencing in `withdrawToNear` during a paused or partially paused engine state in a way that the token contract does not expect, causing value to be burned into a blocked path and leading to Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `burn-before-external-call sequencing in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: check how the token withdraw path behaves when its downstream engine route is not fully available.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Insolvency
- Fast validation: Pause the relevant engine-side path and confirm the token withdraw function cannot burn value into an unrecoverable state. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
